# AeyeGuard_javs.py - Security Static Analysis Tool for java Files

## Overview
A Python-based security static analysis tool that leverages local LLM capabilities to perform comprehensive security vulnerability detection in java source code files.

## Purpose
Delegate strong static security analysis of java code to a local Large Language Model, enabling:
- Privacy-preserving code analysis (all processing done locally)
- Deep security vulnerability detection
- Context-aware threat identification
- Detailed security recommendations

## Technical Stack
- **Language**: Python 3.8+
- **LLM Framework**: LangChain
- **LLM Provider**: LM Studio (local)
- **Default Model**: qwen/qwen3-coder-30b
- **Input**: java source code files (.java)

## Core Requirements

### 1. Input Processing
- Accept a single java file path as command-line argument
- Validate file existence and readability
- Validate .java file extension (enforced)
- Handle multiple file encodings with fallback (UTF-8, UTF-16, Latin-1)
- Read and process java source code
- Warn if file exceeds 10,000 lines (may require chunking)

### 2. LLM Integration
- Connect to LM Studio local server (default: http://localhost:1234)
- Use LangChain for LLM orchestration
- Support configurable model selection (default: qwen/qwen3-coder-30b)
- Test connection before starting analysis
- Handle connection failures gracefully with clear error messages
- Implement retry logic for transient failures (via LLMConnector module)
- Support custom LM Studio endpoints via --lm-studio-url argument

### 3. Security Analysis Capabilities
The tool should identify and analyze:

#### 3.1 Input Validation Vulnerabilities
- SQL injection risks
- Command injection vulnerabilities
- Path traversal issues
- XML/XXE injection
- LDAP injection
- Unvalidated redirects

#### 3.2 Authentication & Authorization
- Weak authentication mechanisms
- Missing authorization checks
- Insecure credential storage
- Session management issues
- Privilege escalation risks

#### 3.3 Cryptography Issues
- Weak cryptographic algorithms
- Hardcoded secrets/keys
- Insecure random number generation
- Improper certificate validation
- Weak password hashing

#### 3.4 Data Exposure
- Sensitive data in logs
- Information disclosure
- Insecure deserialization
- Missing data encryption
- PII handling issues

#### 3.5 Code Quality & Logic
- Race conditions
- Null reference vulnerabilities
- Resource leaks
- Infinite loops
- Exception handling issues

#### 3.6 Java Specific Vulnerabilities
- Insecure deserialization
- Reflection Abuse
- ClassLoader Manipulation
- JNI (Java Native Interface) Issues
- JMX (Java Management Extensions) Exposure
- Expression Language (EL) Injection
- SpEL (Spring Expression Language) Injection
- JNDI Injection
- SecurityManager Bypass
- Type Confusion via Generics Erasure
- Cloneable Exploitation
- Finalizer Attacks

### 4. Analysis Output
The tool should provide:

#### 4.1 Structured Report
- Vulnerability severity (Critical, High, Medium, Low, Info)
- CWE (Common Weakness Enumeration) identifiers
- Affected code locations (file, line numbers)
- Vulnerability description
- Exploitation scenario
- Remediation recommendations
- Code snippets showing the issue
- Suggested fix/patch

#### 4.2 Output Formats
All formats are fully implemented via the OutputFormatter module:
- **Console** (default): Human-readable summary with findings
- **JSON**: Machine-readable structured output
- **Markdown**: Formatted report with sections and code blocks
- **SARIF**: Standards-compliant format for IDE integration

#### 4.3 Metrics
- Total vulnerabilities found
- Severity distribution
- Analysis duration
- Confidence scores per finding

### 5. Command-Line Interface

```bash
# Basic usage
python AeyeGuard_java.py <file.java>

# With options
python AeyeGuard_java.py <file.java> --model <model-name> --output <format> --verbose

# Configuration
python AeyeGuard_java.py <file.java> --lm-studio-url <url> --temperature <value>
```

#### CLI Arguments
- `input_file` (positional, required): Path to java file
- `--model`: LLM model name (default: `qwen/qwen3-coder-30b`)
- `--lm-studio-url`: LM Studio endpoint (default: `http://localhost:1234`)
- `--temperature`: LLM temperature (default: `0.0` for deterministic analysis)
- `--max-tokens`: Maximum tokens for response (default: `4096`)
- `--output`: Output format [console|json|markdown|sarif] (default: `console`)
- `--output-file`: Save report to file (optional)
- `--severity`: Minimum severity to report [critical|high|medium|low|info] (default: `info`)
- `--config`: Configuration file path (YAML or JSON)
- `--verbose`: Enable detailed logging
- `--version`: Show version and exit

### 6. Analysis Workflow

The tool follows this execution sequence:

1. **Argument Parsing**: Parse CLI arguments and validate inputs
2. **Configuration Loading**: Load config from file, environment, and CLI (with precedence)
3. **File Validation**: Verify file exists, is readable, and has .java extension
4. **File Reading**: Read file with multi-encoding fallback (UTF-8, UTF-16, Latin-1)
5. **File Size Check**: Warn if file exceeds 10,000 lines
6. **LLM Connection Test**: Verify LM Studio is accessible before analysis
7. **Security Analysis**: Send code to LLM with security-focused prompts
8. **Response Parsing**: Extract findings from LLM response (via SecurityAnalyzer)
9. **Severity Filtering**: Filter findings based on --severity threshold
10. **Output Formatting**: Format results in requested format (Console, JSON, Markdown, SARIF)
11. **Output Display/Save**: Display to console or save to file
12. **Summary Display**: Show severity distribution and analysis metrics
13. **Exit Code**: Return appropriate exit code (0, 1, 2, or 130)

### 7. Prompt Engineering
- Design specialized security analysis prompts (implemented in SecurityAnalyzer)
- Include context about java security best practices
- Request structured output from LLM
- Use few-shot examples for consistency
- Implement chain-of-thought prompting for complex analysis

### 8. Error Handling
- Graceful handling of malformed java code
- Clear error messages for connection issues (file not found, connection failures)
- Validation of LLM responses (via SecurityAnalyzer parsing)
- Specific exception types: FileNotFoundError, ValueError, KeyboardInterrupt
- Exit codes for different error scenarios

### 9. Performance Requirements
- Support files up to 10,000 lines (warnings for larger files)
- Complete analysis within reasonable time (model-dependent)
- Efficient token usage through SecurityAnalyzer
- Memory-efficient file processing
- Chunking support for large files (implemented in SecurityAnalyzer)

### 10. Configuration
The tool uses a multi-source configuration system with precedence ordering:

**Configuration Precedence** (highest to lowest):
1. Command-line arguments (highest priority)
2. Environment variables
3. Configuration file (YAML/JSON via `--config`)
4. Hardcoded defaults

**Configuration Options**:
- **LM Studio Settings**: `lm_studio_url`, `model`
- **Model Parameters**: `temperature`, `max_tokens`
- **Output Settings**: `output` format, `output_file`, `severity` filter
- **Analysis Options**: Managed via SecurityAnalyzer module
- **Logging**: `verbose` flag for debug-level output

**Configuration Loading**:
Implemented in the `Config` module with `Config.load(config_file, cli_args)` method that merges all sources according to precedence.

### 11. Logging & Debugging
- Structured logging with timestamps and log levels
- Log levels: DEBUG (with --verbose), INFO, WARNING, ERROR, CRITICAL
- Performance metrics: Analysis duration, file size, lines of code
- Connection status logging
- Progress indicators for long-running analyses
- Error messages sanitized (no code leakage in logs)

### 12. Exit Codes
The tool uses specific exit codes to indicate analysis results:

- **0**: Success - No critical or high severity vulnerabilities found
- **1**: High severity vulnerabilities detected
- **2**: Critical severity vulnerabilities detected
- **130**: Interrupted by user (Ctrl+C / KeyboardInterrupt)

Exit codes enable CI/CD integration and automated decision-making based on severity.

### 13. Modular Architecture
The implementation uses a clean modular design with separation of concerns:

**Core Modules** (in `modules/` directory):

1. **config.py** - Configuration Management
   - Multi-source configuration loading (CLI, ENV, YAML, defaults)
   - Configuration validation and merging
   - Type-safe configuration access

2. **llm_connector.py** - LLM Communication
   - LM Studio API client using LangChain
   - Connection testing and health checks
   - Retry logic for transient failures
   - Request/response handling

3. **security_analyzer.py** - Security Analysis Engine
   - Prompt engineering for security analysis
   - LLM response parsing and validation
   - Chunking logic for large files
   - Findings extraction and structuring

4. **output_formatter.py** - Output Generation
   - Multiple output format support (Console, JSON, Markdown, SARIF)
   - Report generation and formatting
   - Severity-based filtering and sorting

**Main Script**: `AeyeGuard_java.py`
- CLI argument parsing
- Workflow orchestration
- File validation and reading
- Error handling and exit code management

## Non-Functional Requirements

### Security
- All analysis performed locally (no external API calls)
- No code exfiltration
- Secure handling of analyzed code in memory
- No persistent storage of analyzed code
- Input validation for all user inputs

### Reliability
- Consistent results for same input (temperature=0.0 by default)
- Robust error recovery with try-except blocks
- Validation of LLM output format via SecurityAnalyzer
- Graceful degradation on connection failures
- Multi-encoding fallback for file reading
- Proper exception handling with specific error messages

### Maintainability
- Modular architecture with clear separation of concerns
- Docstrings for all major functions and classes
- Type hints throughout (Python typing module)
- Four distinct modules for different responsibilities
- Clean error handling patterns
- Configurable behavior via CLI and config files

### Usability
- Clear, actionable output in multiple formats
- Progress indicators with file size and line count
- Informative logging at appropriate levels
- Helpful error messages for common issues (file not found, connection failures)
- Severity-based summary output
- Analysis duration reporting
- Warning messages for large files

## Dependencies

**Runtime Dependencies** (see `requirements.txt`):
```
langchain>=0.3.0
langchain-community>=0.3.0
requests>=2.31.0
pyyaml>=6.0
python-dotenv>=1.0.0
```

**Built-in Modules Used**:
- `argparse` - Command-line argument parsing
- `sys`, `os` - System and file operations
- `pathlib` - Path manipulation
- `json` - JSON output formatting
- `logging` - Structured logging
- `datetime` - Timestamp generation
- `typing` - Type hints

**Python Version**: 3.8 or higher

## Current Implementation Status

**Fully Implemented**:
- ✅ Single java file analysis
- ✅ LM Studio integration with LangChain
- ✅ Multi-format output (Console, JSON, Markdown, SARIF)
- ✅ Configurable via CLI, ENV, and config files
- ✅ Severity filtering
- ✅ Exit codes for CI/CD integration
- ✅ Multi-encoding file support
- ✅ Modular architecture
- ✅ Connection testing
- ✅ Progress indicators and logging

**Handled by Parent Tool** (`AeyeGuard_cmd.py`):
- ✅ Multiple files/directory scanning
- ✅ Parallel processing
- ✅ Recursive directory traversal

## Future Enhancements (Planned)
- Incremental analysis (scan only changed code)
- Custom rule definitions and security patterns
- Comparison with other SAST tools (e.g., SonarQube)
- Historical tracking of vulnerabilities
- Baseline comparison (diff between scans)
- Enhanced chunking strategies for very large files
- IDE plugins (VS Code, Visual Studio)
- Web UI for visualization

## Success Criteria

**Achieved**:
- ✅ Identifies common java security vulnerabilities using LLM analysis
- ✅ Provides structured output with severity levels and recommendations
- ✅ Operates entirely offline (local LM Studio)
- ✅ Supports multiple output formats for different use cases
- ✅ Integrates with CI/CD via exit codes
- ✅ Easy to use with sensible defaults
- ✅ Produces consistent results (temperature=0.0 default)
- ✅ Handles files up to 10,000+ lines (with chunking support)
- ✅ Configurable via multiple methods (CLI, ENV, config file)
- ✅ Clear error messages and logging
