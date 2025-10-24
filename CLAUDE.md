# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **security static analysis toolkit** that uses local LLM capabilities (via LM Studio) to detect vulnerabilities in source code. The project consists of two main components:

1. **AeyeGuard_cmd.py** - Recursive directory scanner that orchestrates analysis across multiple files
2. **cs/AeyeGuard_cs.py** - C# language-specific analyzer that performs deep security analysis on individual files

All analysis is performed **locally** - no code is sent to external APIs. This is a defensive security tool only.

## Development Commands

### Setup and Installation

```bash
# Install dependencies for all analyzers
pip install -r requirements.txt

# Verify setup (checks Python version, packages, LM Studio connection)
python tests/cs/setup_test.py
```

### Running Analysis

```bash
# Analyze a single C# file
python cs/AeyeGuard_cs.py path/to/file.cs

# Scan entire directory recursively (from root)
python AeyeGuard_cmd.py /path/to/codebase

# Scan with common options
python AeyeGuard_cmd.py /path/to/codebase --severity high --parallel 4 --verbose

# Test on a few files first
python AeyeGuard_cmd.py /path/to/codebase --max-files 5
```

### Testing Changes

```bash
# Test the analyzer parser (useful when modifying security_analyzer.py)
python tests/cs/test_parser.py

# Run quick validation
python AeyeGuard_cmd.py /path/to/small/test/dir --verbose
```

## Architecture

### Two-Tier Design

```
AeyeGuard_cmd.py (Orchestrator)
    ├── Discovers files recursively (currently .cs files only)
    ├── Filters based on exclusion rules
    ├── Spawns subprocess for each file
    └── For each .cs file:
        └── Calls: python cs/AeyeGuard_cs.py <file> [forwarded options]
            ├── Reads file with multi-encoding support
            ├── Chunks if > 5000 lines (configurable)
            ├── Sends to LM Studio with security analysis prompts
            ├── Parses text response for findings
            └── Returns exit code: 0 (clean), 1 (high), 2 (critical)
```

### Module Responsibilities (cs/modules/)

- **config.py** - Multi-source configuration (CLI > ENV > YAML > defaults)
- **llm_connector.py** - LM Studio API client with retry logic (uses LangChain)
- **security_analyzer.py** - Prompt engineering, response parsing, chunking logic
- **output_formatter.py** - Formats output to console/JSON/Markdown/SARIF

### Critical Design Details

1. **Exit Codes Matter**: Both scripts use exit codes to signal severity:
   - 0 = no issues or only low/medium
   - 1 = high severity found
   - 2 = critical severity found
   - 130 = interrupted (Ctrl+C)

2. **Text-Based Output**: The C# analyzer outputs plain text (not JSON) for readability. The parser in `security_analyzer.py` uses regex patterns to extract findings count and severity distribution from the text.

3. **Default Folder Exclusion**: `AeyeGuard_cmd.py` automatically excludes common build/cache folders (defined in `DEFAULT_EXCLUDE_FOLDERS` set). To add more, simply add folder names to this set at the top of AeyeGuard_cmd.py.

4. **Temperature Setting**: Default is now 0.0 for deterministic analysis. This is critical for consistent security scanning.

5. **Confidence vs Severity Bug**: In `cs/modules/security_analyzer.py` lines 342-386, the severity patterns are currently checking for `**confidence:**` instead of `**severity:**`. The commented-out patterns below are what should be active. This causes the parser to miss findings.

## Configuration System

Configuration loads in this precedence (highest to lowest):
1. Command-line arguments (`--model`, `--temperature`, etc.)
2. Environment variables (`SECSCAN_MODEL`, `SECSCAN_LM_STUDIO_URL`, etc.)
3. YAML config file (via `--config path/to/config.yaml`)
4. Hardcoded defaults in `cs/modules/config.py`

## Common Development Patterns

### Adding New Exclusion Folders

Edit `AeyeGuard_cmd.py` and add to the `DEFAULT_EXCLUDE_FOLDERS` set:

```python
DEFAULT_EXCLUDE_FOLDERS = {
    'bin', 'obj', '.vs',
    'your_new_folder',  # Add here
}
```

### Modifying Security Analysis Prompts

Edit `cs/modules/security_analyzer.py`:
- `_build_system_prompt()` - LLM's role and instructions
- `_build_analysis_prompt()` - Per-file analysis request

### Testing Parser Changes

After modifying `_parse_text_for_summary()` in security_analyzer.py:

```bash
python tests/cs/test_parser.py  # Test with sample LLM responses
```

### Adding New Output Formats

Edit `cs/modules/output_formatter.py` and add a new format method to the `OutputFormatter` class.

## Key Files to Know

- **AeyeGuard_cmd.py** lines 24-36: `DEFAULT_EXCLUDE_FOLDERS` - folders auto-skipped during traversal
- **AeyeGuard_cmd.py** lines 452-456: Temperature default (recently changed to 0.0)
- **cs/AeyeGuard_cs.py** lines 130-134: Temperature default (recently changed to 0.0)
- **cs/modules/security_analyzer.py** lines 181-204: System prompt that guides LLM behavior
- **cs/modules/security_analyzer.py** lines 299-475: Response parser (complex regex-based extraction)
- **cs/modules/config.py** lines 26-50: Default configuration values

## LM Studio Requirements

This tool requires **LM Studio** running locally:
- Default URL: `http://localhost:1234`
- Recommended model: `qwen/qwen3-coder-30b` (or any code-capable model)
- The model must be loaded before scanning

Test connection: `python tests/cs/setup_test.py`

## Known Issues / Technical Debt

1. **Parser Pattern Bug**: `security_analyzer.py` checks for `**confidence:**` instead of `**severity:**` in severity patterns (lines 342-386)
2. **Interface-Only Files**: Files with only interface definitions (no implementation) may still be flagged as vulnerable due to aggressive keyword matching
3. **No Dependency Management**: `AeyeGuard_cmd.py` has no requirements.txt (uses only stdlib)
4. **Single Language Support**: Currently only C# - architecture supports more languages but not implemented

## Exit Code Semantics

Understanding exit codes is crucial for CI/CD integration:

```python
# AeyeGuard_cmd.py aggregates exit codes from all analyzed files
# If ANY file has critical findings → return 2
# Else if ANY file has high findings → return 1
# Else → return 0
```

## File Size Handling

- Files < 5000 lines: Single-pass analysis
- Files ≥ 5000 lines: Auto-chunked with 50-line overlap
- Each chunk analyzed separately, results combined
- Configurable via `chunk_size` in config.yaml

## Important Security Constraints

**This is a defensive security tool.** Do not use it to:
- Create exploits or offensive security tools
- Harvest credentials from codebases (bulk scanning for secrets is prohibited)
- Modify code to be more exploitable

Allow: Security analysis, detection rules, vulnerability explanations, defensive tools, security documentation.
