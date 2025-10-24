# AeyeGuard_cmd: a Security Static Analysis Tool

This repository contains security static analysis command line tool that leverages local LLM capabilities to perform comprehensive security vulnerability detection in source code.

## AeyeGuard_cmd.py - Recursive Security Scanner

A wrapper tool that recursively scans directories for source code files and delegates security analysis to language-specific analyzers.

**Current Support:**
- C# files (`.cs`) via `cs/AeyeGuard_cs.py`
- Java files (`.java`) via `java/AeyeGuard_java.py`
- React/TypeScript and React/JavsScript files (`.tsx`, `.jsx`) via `react/AeyeGuard_react.py`

### Language-Specific Analyzers

#### cs/AeyeGuard_cs.py - C# Security Analyzer
Analyzes C# source code files for .NET security vulnerabilities including SQL injection, authentication issues, cryptography weaknesses, and .NET-specific security patterns.

#### java/AeyeGuard_java.py - Java Security Analyzer
Analyzes Java source code files for security vulnerabilities including SQL injection, insecure deserialization, authentication issues, cryptography weaknesses, and Java-specific security patterns.

#### react/AeyeGuard_react.py - React/TypeScript and React/Javascript Security Analyzer
Analyzes React/TypeScript and React/Javascript files for frontend security issues including XSS, dangerouslySetInnerHTML, authentication bypass, state management security, and React Hooks vulnerabilities.

## Quick Start

### Prerequisites

1. **Python 3.8 or higher**
2. **LM Studio** running locally with a loaded model
   - Default URL: `http://localhost:1234`
   - Recommended model: `qwen/qwen3-coder-30b`

### Installation

```bash
# Clone or download this repository
cd /path/to/analyzer

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Scan a directory recursively (output to console)
python AeyeGuard_cmd.py /path/to/codebase

# Scan and save output to file
python AeyeGuard_cmd.py /path/to/codebase --output-file report.txt

# Scan with severity filter
python AeyeGuard_cmd.py /path/to/codebase --severity high

# Exclude certain directories
python AeyeGuard_cmd.py /path/to/codebase --exclude "*/obj/*" --exclude "*/bin/*" --exclude "*/node_modules/*"

# Parallel analysis with 4 workers
python AeyeGuard_cmd.py /path/to/codebase --parallel 4

# Analyze single C# file
python cs/AeyeGuard_cs.py /path/to/file.cs
```

## Command-Line Options

### AeyeGuard_cmd.py Options

#### Required Arguments
- `input_directory` - Path to the directory to scan recursively

#### LLM Configuration (forwarded to analyzer)
- `--model MODEL` - LLM model name (default: `qwen/qwen3-coder-30b`)
- `--lm-studio-url URL` - LM Studio endpoint URL (default: `http://localhost:1234`)
- `--temperature FLOAT` - LLM temperature 0.0-1.0 (default: `0.2`)
- `--max-tokens INT` - Maximum tokens for LLM response (default: `4096`)

#### Filtering Options
- `--severity LEVEL` - Minimum severity to report: `critical`, `high`, `medium`, `low`, `info` (default: `info`)
- `--exclude PATTERN` - Glob pattern to exclude (can be repeated)
  - Examples: `*/bin/*`, `*/obj/*`, `*/node_modules/*`, `*Test.cs`
- `--max-files INT` - Maximum number of files to analyze (useful for testing)

#### Output Options
- `--output-file PATH` - Save report to file (text format) instead of console

#### Performance Options
- `--parallel INT` - Number of parallel file analyses (default: `1`)
  - Use 2-4 for faster scans on multi-core systems
  - Higher values use more memory and CPU

#### Other Options
- `--config PATH` - Configuration file (YAML or JSON) - forwarded to analyzer
- `--continue-on-error` - Continue if a file analysis fails (default: enabled)
- `--verbose` - Enable verbose logging
- `--version` - Show version information
- `--help` - Show help message

## Output Format

The tool outputs text-based reports with the following structure:

### Summary Section
- Scan metadata (completion time, duration, directory scanned)
- Files scanned count
- Analysis summary (successful/failed analyses)
- Severity breakdown (files with critical/high findings, clean files)

### Critical/High Findings Section
- List of files with critical severity findings
- List of files with high severity findings

### Failed Analyses Section
- List of files that failed to analyze
- Error messages for each failure

### Detailed Output Section
- Complete output from each file's analysis
- Includes file path, status, duration, and exit code
- Full text output from the individual analyzer (`cs/secscan_cs.py`)

The output can be displayed to console or saved to a file using `--output-file`.

## Exit Codes

- `0` - Success, no critical or high severity findings
- `1` - High severity findings detected, or operational error
- `2` - Critical severity findings detected
- `130` - Interrupted by user (Ctrl+C)

## Examples

### Example 1: Basic Scan
```bash
python AeyeGuard_cmd.py ~/projects/my-app
```

This scans all supported files (C# and React/TypeScript) in `~/projects/my-app` recursively and displays results in the console.

### Example 2: Production Scan with Filters
```bash
python AeyeGuard_cmd.py ~/projects/my-app \
  --severity medium \
  --exclude "*/bin/*" \
  --exclude "*/obj/*" \
  --exclude "*Test.cs" \
  --exclude "*Generated.cs" \
  --output-file security-report.txt
```

This scans for medium+ severity findings, excludes build directories and test files, and saves results to a text file.

### Example 3: Fast Parallel Scan
```bash
python AeyeGuard_cmd.py ~/projects/my-app \
  --parallel 4 \
  --severity high \
  --verbose
```

This uses 4 parallel workers for faster scanning and only reports high+ severity findings.

### Example 4: Limited Test Scan
```bash
python AeyeGuard_cmd.py ~/projects/my-app \
  --max-files 5 \
  --verbose
```

This scans only the first 5 C# files found, useful for testing configuration.

### Example 5: Custom LLM Configuration
```bash
python AeyeGuard_cmd.py ~/projects/my-app \
  --model qwen/qwen3-coder-70b \
  --lm-studio-url http://192.168.1.100:1234 \
  --temperature 0.1 \
  --max-tokens 8192
```

This uses a different model and LM Studio instance with custom parameters.

## Common Exclude Patterns

```bash
# Exclude build artifacts
--exclude "*/bin/*" --exclude "*/obj/*" --exclude "*/dist/*"

# Exclude test files
--exclude "*Test.cs" --exclude "*Tests.cs" --exclude "*/test/*"

# Exclude generated code
--exclude "*Generated.cs" --exclude "*.Designer.cs" --exclude "*.g.cs"

# Exclude dependencies
--exclude "*/node_modules/*" --exclude "*/packages/*" --exclude "*/vendor/*"

# Exclude specific directories
--exclude "*/migrations/*" --exclude "*/wwwroot/*"
```

## Troubleshooting

### LM Studio Connection Issues

**Problem:** "Failed to connect to LM Studio"

**Solutions:**
1. Ensure LM Studio is running
2. Verify a model is loaded in LM Studio
3. Check the URL is correct (default: `http://localhost:1234`)
4. Try specifying the URL explicitly: `--lm-studio-url http://localhost:1234`

### No Files Found

**Problem:** "No files found to analyze"

**Solutions:**
1. Verify the directory path is correct
2. Check that C# files (`.cs`) exist in the directory
3. Review exclude patterns - you may be excluding too much
4. Use `--verbose` to see which files are being excluded

### Analysis Timeout

**Problem:** Individual file analysis times out (10 minutes)

**Solutions:**
1. The file may be too large (>10,000 lines)
2. Try using a faster/smaller model
3. Increase `--temperature` slightly (may reduce processing time)
4. Consider splitting large files

### Slow Performance

**Problem:** Scanning is very slow

**Solutions:**
1. Use `--parallel 4` for parallel processing
2. Use `--severity high` to focus on critical issues
3. Exclude unnecessary directories (build, test, generated code)
4. Use a faster model if available

### Memory Issues

**Problem:** High memory usage during scan

**Solutions:**
1. Reduce `--parallel` value (use 1 or 2)
2. Use `--max-files` to limit scope
3. Scan subdirectories separately

## Architecture

```
AeyeGuard_cmd.py (Recursive Scanner)
    |
    +-- Discovers .cs files recursively
    |
    +-- For each file:
        |
        +-- Calls cs/AeyeGuard_cs.py
            |
            +-- Reads C# file
            +-- Connects to LM Studio
            +-- Performs security analysis
            +-- Returns JSON results
    |
    +-- Aggregates all results
    +-- Formats output (console/json/markdown/sarif)
```

## Implementation guidelines

See [docs/AeyeGuard_specifications.md](docs/AeyeGuard_specifications.md) for detailed requirements and implementation guidelines.

## License

[MIT License](https://github.com/ettoremessina/AeyeGuard_cmd?tab=MIT-1-ov-file#)

## Info

For issues, questions, or contributions, please refer to the project information on [AeyeGuard: a reliable and capable static code analyzer command line powered by a local LLM](https://ettoremessina.tech/agentic-applications/aeyeguard-a-reliable-and-capable-static-code-analyzer-command-line-powered-by-a-local-llm/) post on my website [https://ettoremessina.tech/](https://ettoremessina.tech/).
