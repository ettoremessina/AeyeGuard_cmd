# AeyeGuard_cmd.py - Requirements Specification

## Overview
`AeyeGuard_cmd.py` is a recursive security static analysis tool that scans directories for source code files and delegates security analysis to language-specific analyzers. It serves as a wrapper and orchestrator for individual file analyzers like `AeyeGuard_cs.py`.

## Purpose
To provide a unified interface for security scanning of entire codebases by:
- Recursively traversing directory structures
- Identifying files by extension
- Delegating analysis to appropriate language-specific scanners
- Aggregating and presenting consolidated results

## Core Requirements

### 1. Input Processing
- **Primary Input**: Accept a directory path as the main argument
- **Validation**: Verify that the input path exists and is a directory
- **Error Handling**: Provide clear error messages for invalid inputs

### 2. Recursive Directory Traversal
- **Recursion**: Traverse all subdirectories recursively from the root input directory
- **File Discovery**: Identify all files within the directory tree
- **Extension Filtering**: Filter files based on supported extensions
- **Current Support**: Support `.cs` (C#), `.tsx`, `.jsx` (React TypeScript/JavaScript), and `.java` (Java) files
- **Auto-Exclusion**: Automatically exclude common build/cache directories (bin, obj, .vs, .git, .svn, node_modules, __pycache__, .pytest_cache, packages, .nuget, TestResults, Migrations)
- **Extensibility**: Design to easily add support for additional file extensions in the future

### 3. File Type Processing

#### C# Files (.cs)
- **Detection**: Identify all files with `.cs` extension
- **Delegation**: Call `cs/AeyeGuard_cs.py` for each C# file discovered
- **Argument Passing**: Pass the file path as input to `AeyeGuard_cs.py`
- **Option Forwarding**: Forward relevant command-line options to `AeyeGuard_cs.py`

#### React TypeScript/JavaScript Files (.tsx, .jsx)
- **Detection**: Identify all files with `.tsx` or `.jsx` extension
- **Delegation**: Call `react/AeyeGuard_react.py` for each React file discovered
- **Argument Passing**: Pass the file path as input to `AeyeGuard_react.py`
- **Option Forwarding**: Forward relevant command-line options to `AeyeGuard_react.py`

#### Java Files (.java)
- **Detection**: Identify all files with `.java` extension
- **Delegation**: Call `java/AeyeGuard_java.py` for each Java file discovered
- **Argument Passing**: Pass the file path as input to `AeyeGuard_java.py`
- **Option Forwarding**: Forward relevant command-line options to `AeyeGuard_java.py`

### 4. Output Capture and Aggregation
- **Capture**: Capture the complete output from each language-specific analyzer invocation
- **Aggregation**: Combine outputs from multiple file analyses into a single report
- **Structure**: Maintain clear association between findings and source files
- **Summary**: Provide an aggregated summary with:
  - Total files scanned count
  - Files with CRITICAL findings
  - Files with HIGH findings
  - Clean files (no issues)
  - Failed analyses
- **Exit Code Aggregation**: Aggregate exit codes from all analyzed files (0=clean, 1=high, 2=critical)

### 5. Command-Line Options

#### Options to Forward to Language-Specific Analyzers
The following options should be available in `AeyeGuard_cmd.py` and forwarded to all language-specific analyzers (AeyeGuard_cs.py, AeyeGuard_react.py, etc.):

1. **--model** (string)
   - LLM model name to use for analysis
   - Default: `qwen/qwen3-coder-30b`
   - Forwarded to all analyzers via `--model`

2. **--lm-studio-url** (string)
   - LM Studio endpoint URL
   - Default: `http://localhost:1234`
   - Forwarded to all analyzers via `--lm-studio-url`

3. **--temperature** (float)
   - LLM temperature setting
   - Default: `0.0` (deterministic analysis)
   - Range: `0.0` to `1.0`
   - Forwarded to: Language-specific analyzers via `--temperature`

4. **--max-tokens** (integer)
   - Maximum tokens for LLM response
   - Default: `4096`
   - Forwarded to all analyzers via `--max-tokens`

5. **--severity** (choice)
   - Minimum severity level to report
   - Choices: `critical`, `high`, `medium`, `low`, `info`
   - Default: `info`
   - Forwarded to all analyzers via `--severity`

6. **--config** (string)
   - Configuration file path (YAML or JSON)
   - Optional
   - Forwarded to all analyzers via `--config`

7. **--verbose** (flag)
   - Enable verbose logging for both AeyeGuard_cmd.py and analyzers
   - Forwarded to all analyzers via `--verbose`

#### AeyeGuard_cmd.py Specific Options

1. **input_directory** (positional, required)
   - Path to the directory to scan recursively
   - Must be a valid directory path

2. **--output-file** (string)
   - Path to save the aggregated report (text format)
   - Optional
   - If not specified, output to console
   - Format: Plain text with sections for summary, critical findings, high findings, failed analyses, and detailed output

3. **--exclude** (string, repeatable)
   - Glob patterns for files/directories to exclude
   - Examples: `*/node_modules/*`, `*/bin/*`, `*/obj/*`
   - Can be specified multiple times
   - Note: Common folders are automatically excluded (see Auto-Exclusion in section 2)

4. **--max-files** (integer)
   - Maximum number of files to analyze
   - Optional (no limit by default)
   - Useful for testing or limiting long-running scans

5. **--parallel** (integer)
   - Number of parallel file analyses to run
   - Default: `1` (sequential processing)
   - Values > 1 enable parallel processing using ProcessPoolExecutor

6. **--continue-on-error** (flag)
   - Continue scanning remaining files if analysis of one file fails
   - Default: `True`
   - Failed files are logged and included in the final report

## Output Format Requirements

### Text Output (Console and File)
The tool produces a comprehensive text-based report with the following sections:

1. **Header Section**
   - Scan completion timestamp
   - Total duration in seconds
   - Input directory path
   - Total files scanned count

2. **Analysis Summary**
   - Successful analyses count
   - Failed analyses count
   - Files with CRITICAL findings count
   - Files with HIGH findings count
   - Clean files (no issues) count

3. **Files with Critical Findings** (if any)
   - List of file paths with critical severity findings

4. **Files with High Severity Findings** (if any)
   - List of file paths with high severity findings

5. **Failed Analyses** (if any)
   - File paths and error details for failed analyses

6. **Detailed Analysis Output**
   - Full output from each file's analysis
   - File path, status, duration, and exit code for each file
   - Individual analyzer output (findings, recommendations, etc.)

### Progress Logging (Console Only)
- Real-time progress indicators: `[N/Total] Analyzing: file_path`
- Completion status with duration: `-> Completed in X.Xs (exit code: N)`
- Warning messages for failures: `-> ERROR` or `-> TIMEOUT`

### Future Output Formats (Not Yet Implemented)
The following output formats are planned for future releases:

- **JSON**: Structured output for programmatic consumption
- **Markdown**: Formatted report with hierarchical structure
- **SARIF**: Standards-compliant format for integration with security tools

Currently, only text format output is supported (console or file via `--output-file`).

## Error Handling Requirements

1. **Invalid Directory**: Exit with error code 1 and clear message
2. **File Analysis Failure**:
   - Log error with file path and reason
   - Continue with remaining files if `--continue-on-error` is set
   - Include failed files in final report
3. **LLM Connection Failure**:
   - Fail fast with error code 1
   - Provide troubleshooting guidance
4. **Interrupted Scan** (Ctrl+C):
   - Clean shutdown
   - Option to save partial results
   - Exit code 130

## Performance Requirements

1. **Progress Indication**: Show real-time progress for long-running scans
2. **Resource Management**: Limit memory usage when processing many files
3. **Parallel Processing**: Support concurrent file analysis to reduce total scan time
4. **Cancellation**: Allow graceful cancellation without corrupting output

## Exit Codes

- `0`: Success, no critical or high severity findings
- `1`: High severity findings detected, or operational error
- `2`: Critical severity findings detected
- `130`: Interrupted by user (Ctrl+C)

## Future Extensibility

### Current Design Features
1. **Plugin Architecture**: Modular design supports multiple language analyzers
2. **File Type Registry**: `get_analyzer_for_file()` function maps extensions to analyzer scripts
3. **Option Forwarding**: Common options forwarded to all language-specific analyzers
4. **Implemented Languages**:
   - C# (.cs)
   - React TypeScript/JavaScript (.tsx, .jsx)
   - Java (.java)

### Planned Extensions
- Support for additional languages:
  - Python (.py)
  - JavaScript/TypeScript (.js, .ts)
  - Go (.go)
  - Rust (.rs)
- Multiple output formats (JSON, Markdown, SARIF)
- Integration with CI/CD pipelines
- Baseline comparison (compare current scan with previous results)
- Incremental scanning (scan only changed files)
- Custom analyzer registration system

## Dependencies

1. Python 3.8 or higher
2. Language-specific analyzers:
   - `cs/AeyeGuard_cs.py` for C# files
   - `react/AeyeGuard_react.py` for React TypeScript/JavaScript files
   - `java/AeyeGuard_java.py` for Java files
3. LM Studio instance running and accessible (default: http://localhost:1234)
4. Standard library modules only (no external dependencies for AeyeGuard_cmd.py):
   - `os`, `sys`, `argparse`, `pathlib`, `subprocess`, `logging`, `signal`
   - `datetime`, `fnmatch`, `concurrent.futures`
5. Individual analyzers have their own dependencies (see cs/requirements.txt)

## Usage Examples

```bash
# Basic scan of a directory (output to console)
python AeyeGuard_cmd.py /path/to/codebase

# Scan with text output saved to file
python AeyeGuard_cmd.py /path/to/codebase --output-file report.txt

# Scan with severity filter and excluding certain directories
python AeyeGuard_cmd.py /path/to/codebase --severity high --exclude "*/obj/*" --exclude "*/bin/*"

# Parallel scan with custom model (4 workers)
python AeyeGuard_cmd.py /path/to/codebase --parallel 4 --model qwen/qwen3-coder-30b --verbose

# Limited scan for testing (first 5 files only)
python AeyeGuard_cmd.py /path/to/codebase --max-files 5 --verbose

# Scan with all options
python AeyeGuard_cmd.py /path/to/codebase \
  --model qwen/qwen3-coder-30b \
  --lm-studio-url http://localhost:1234 \
  --temperature 0.0 \
  --max-tokens 4096 \
  --severity medium \
  --output-file security_report.txt \
  --parallel 4 \
  --exclude "*/test/*" \
  --exclude "*/mock/*" \
  --verbose
```

## Implementation Notes

1. **Subprocess Management**: Uses `subprocess.run()` with capture_output=True to invoke language-specific analyzers
2. **Output Capture**: Captures text output (stdout/stderr) from each analyzer invocation
3. **Timeout Handling**: 10-minute timeout per file analysis to prevent hanging
4. **Parallel Processing**: Uses `concurrent.futures.ProcessPoolExecutor` for parallel file analysis
5. **Signal Handling**: Graceful shutdown on Ctrl+C (SIGINT) with partial results saved
6. **Logging**: Structured logging with configurable verbosity (--verbose flag)
7. **Directory Exclusion**: Two-tier exclusion system:
   - Automatic exclusion of common folders (DEFAULT_EXCLUDE_FOLDERS)
   - User-specified glob patterns (--exclude)
8. **Analyzer Routing**: `get_analyzer_for_file()` maps extensions to analyzer scripts:
   - `.cs` → `cs/AeyeGuard_cs.py`
   - `.tsx`, `.jsx` → `react/AeyeGuard_react.py`
   - `.java` → `java/AeyeGuard_java.py`
