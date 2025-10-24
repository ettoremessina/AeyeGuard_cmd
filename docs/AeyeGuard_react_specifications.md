# AeyeGuard_react.py - Security Static Analysis Tool for TypeScript React Files

## Overview
A Python-based security static analysis tool that leverages local LLM capabilities to perform comprehensive security vulnerability detection in TypeScript React (TSX/JSX) source code files.

## Purpose
Delegate strong static security analysis of React TypeScript code to a local Large Language Model, enabling:
- Privacy-preserving code analysis (all processing done locally)
- Deep security vulnerability detection in React applications
- Context-aware threat identification for frontend applications
- Detailed security recommendations for React/TypeScript patterns

## Technical Stack
- **Language**: Python 3.8+
- **LLM Framework**: LangChain
- **LLM Provider**: LM Studio (local)
- **Default Model**: qwen/qwen3-coder-30b
- **Input**: TypeScript React files (.tsx, .jsx, .ts with React imports)

## Core Requirements

### 1. Input Processing
- Accept a single React TypeScript file path as command-line argument
- Validate file existence and readability using `validate_react_file()`
- Support React file extensions (.tsx, .jsx, and .ts files with React imports)
- Handle multiple file encodings with fallback (UTF-8, UTF-16, Latin-1)
- Read and process TypeScript/JSX source code
- Parse React files using ReactParser module to detect:
  - Component count and types (functional, class components)
  - Hooks usage patterns
  - TypeScript vs JavaScript detection
- Warn if file exceeds 10,000 lines (may require chunking)

### 2. LLM Integration
- Connect to LM Studio local server (default: http://localhost:1234)
- Use LangChain for LLM orchestration
- Support configurable model selection (default: qwen/qwen3-coder-30b)
- Test connection before starting analysis
- Handle connection failures gracefully with clear error messages
- Implement retry logic for transient failures (via LLMConnector module)
- Support custom LM Studio endpoints via --lm-studio-url argument
- Display framework and React version info during connection

### 3. Security Analysis Capabilities
The tool should identify and analyze React/TypeScript-specific vulnerabilities:

#### 3.1 Cross-Site Scripting (XSS) Vulnerabilities
- **dangerouslySetInnerHTML usage**: Detect unsanitized HTML injection
- **Unsafe DOM manipulation**: Direct DOM access bypassing React's virtual DOM
- **Unescaped user input**: User data rendered without proper escaping
- **Dynamic script injection**: Dynamic creation of script tags or event handlers
- **innerHTML/outerHTML usage**: Direct manipulation of HTML content
- **URL-based XSS**: Unsanitized URLs in href, src attributes
- **eval() and Function() constructor**: Dynamic code execution
- **React refs misuse**: Direct DOM manipulation via refs with user input

#### 3.2 Authentication & Authorization Issues
- **Missing authentication checks**: Unprotected routes or components
- **Client-side authorization only**: Auth logic that can be bypassed
- **Token storage issues**: Tokens in localStorage/sessionStorage without encryption
- **Insecure session management**: Weak session handling in React apps
- **Missing CSRF protection**: State-changing operations without CSRF tokens
- **Exposed API keys**: Hardcoded keys in frontend code
- **JWT vulnerabilities**: Weak JWT validation or storage

#### 3.3 State Management Security
- **Sensitive data in Redux/state**: PII or credentials in client-side state
- **State mutation vulnerabilities**: Improper state updates leading to race conditions
- **Unvalidated state transitions**: Missing validation on state changes
- **Context API misuse**: Sensitive data propagation without access control
- **Prop drilling sensitive data**: Passing secrets through component hierarchies
- **State persistence issues**: Sensitive data persisted in localStorage/IndexedDB

#### 3.4 API & Data Handling
- **Insecure API calls**: HTTP instead of HTTPS for sensitive endpoints
- **Missing input validation**: Accepting untrusted data without validation
- **API key exposure**: Hardcoded API keys in source code
- **CORS misconfigurations**: Overly permissive CORS policies
- **GraphQL injection**: Unsanitized queries in GraphQL operations
- **Missing rate limiting**: No client-side rate limiting for API calls
- **Unvalidated redirects**: Open redirect vulnerabilities
- **Path traversal in routes**: Dynamic routing with unvalidated paths

#### 3.5 Third-Party Dependencies & Imports
- **Vulnerable npm packages**: Known vulnerabilities in dependencies
- **Unsafe dynamic imports**: Code splitting with user-controlled paths
- **CDN security**: External scripts loaded without integrity checks
- **Prototype pollution**: Vulnerable to prototype pollution attacks
- **Supply chain risks**: Unverified third-party components

#### 3.6 React-Specific Patterns & Hooks
- **useEffect dependencies**: Missing dependencies causing stale closures
- **Memory leaks**: Uncleared timers, subscriptions, or event listeners
- **Infinite render loops**: Dependency arrays causing infinite updates
- **Unsafe hooks usage**: Conditional hooks or hooks in loops
- **Key prop issues**: Missing or non-unique keys in lists
- **Ref callback issues**: Unsafe ref callback patterns
- **Context performance**: Unnecessary re-renders exposing timing attacks

#### 3.7 Data Exposure & Privacy
- **Console.log in production**: Sensitive data logged to browser console
- **Error boundaries exposing data**: Stack traces revealing sensitive info
- **Analytics data leakage**: PII sent to analytics without sanitization
- **Local storage exposure**: Sensitive data in unencrypted local storage
- **Redux DevTools in production**: State inspector enabled in production builds
- **Source maps in production**: Exposing original source code

#### 3.8 Component Security
- **Unsafe component composition**: User-controlled component rendering
- **Dynamic component loading**: Components loaded from untrusted sources
- **Props injection**: Unvalidated props spreading ({...userProps})
- **Children validation**: Accepting arbitrary children without validation
- **Higher-order component vulnerabilities**: HOCs that modify security props
- **Render props security**: Unsafe render prop patterns

#### 3.9 TypeScript-Specific Issues
- **Type assertion abuse**: 'as any' bypassing type safety for security checks
- **Missing type guards**: Unvalidated type narrowing
- **Unsafe type coercion**: Type casting that removes security validations
- **Generic type vulnerabilities**: Overly permissive generic constraints
- **'any' type usage**: Loss of type safety in security-critical code

#### 3.10 Build & Configuration
- **Environment variable exposure**: Secrets in REACT_APP_ or VITE_ variables
- **Development mode in production**: Debug features left enabled
- **Source map exposure**: Full source code available in production
- **Unminified bundles**: Readable production code
- **Webpack/Vite misconfigurations**: Public path vulnerabilities

#### 3.11 Modern React Patterns
- **Server Components security**: Improper server/client boundary handling
- **Suspense boundary issues**: Error information leakage in Suspense fallbacks
- **Streaming SSR vulnerabilities**: Data leakage in streamed responses
- **RSC serialization issues**: Unsafe serialization in Server Components
- **Action security**: Unvalidated server actions

### 4. Analysis Output
The tool should provide:

#### 4.1 Structured Report
- Vulnerability severity (Critical, High, Medium, Low, Info)
- CWE (Common Weakness Enumeration) identifiers
- OWASP Top 10 mapping (when applicable)
- Affected code locations (file, line numbers, column numbers)
- Vulnerability description
- React/TypeScript context
- Exploitation scenario
- Real-world attack examples
- Remediation recommendations
- Code snippets showing the issue
- Suggested fix/patch with React best practices
- Links to React security documentation

#### 4.2 Output Formats
All formats are fully implemented via the OutputFormatter module:
- **Console** (default): Human-readable summary with findings and React metadata
- **JSON**: Machine-readable structured output with component analysis
- **Markdown**: Formatted report with sections, code blocks, and React patterns
- **SARIF**: Standards-compliant format for IDE integration

#### 4.3 Metrics
- Total vulnerabilities found
- Severity distribution
- Component-level security score
- Analysis duration
- Confidence scores per finding
- Code coverage (lines analyzed)

### 5. Command-Line Interface

```bash
# Basic usage
python AeyeGuard_react.py <file.tsx>

# With options
python AeyeGuard_react.py <file.tsx> --model <model-name> --output <format> --verbose

# Configuration
python AeyeGuard_react.py <file.tsx> --lm-studio-url <url> --temperature <value>

# React-specific options
python AeyeGuard_react.py <file.tsx> --react-version 18 --check-hooks --check-performance
```

#### CLI Arguments

**Core Arguments:**
- `input_file` (positional, required): Path to TSX/JSX file

**LLM Configuration:**
- `--model`: LLM model name (default: `qwen/qwen3-coder-30b`)
- `--lm-studio-url`: LM Studio endpoint (default: `http://localhost:1234`)
- `--temperature`: LLM temperature (default: `0.0` for deterministic analysis)
- `--max-tokens`: Maximum tokens for response (default: `4096`)

**Output Configuration:**
- `--output`: Output format [console|json|markdown|sarif] (default: `console`)
- `--output-file`: Save report to file (optional)
- `--severity`: Minimum severity to report [critical|high|medium|low|info] (default: `info`)

**React-Specific Options:**
- `--react-version`: Target React version (default: `18`)
- `--check-hooks`: Enable React Hooks security analysis (default: `True`, enabled)
- `--check-performance`: Include performance-related security issues (default: `False`)
- `--framework`: Framework variant [react|next|remix|gatsby] (default: `react`)
- `--include-dependencies`: Analyze imported dependencies (default: `False`)

**General Options:**
- `--config`: Configuration file path (YAML or JSON)
- `--verbose`: Enable detailed logging
- `--version`: Show version and exit

### 6. Analysis Workflow

The tool follows this execution sequence:

1. **Argument Parsing**: Parse CLI arguments and validate inputs
2. **File Validation**: Validate React file using `validate_react_file()` for .tsx/.jsx extensions
3. **Configuration Loading**: Load config from file, environment, and CLI (with precedence)
4. **File Reading**: Read file with multi-encoding fallback (UTF-8, UTF-16, Latin-1)
5. **File Size Check**: Warn if file exceeds 10,000 lines
6. **React File Parsing**: Use ReactParser to extract:
   - Component count and types
   - Hooks usage patterns
   - TypeScript vs JavaScript detection
7. **LLM Connection Test**: Verify LM Studio is accessible before analysis
8. **Security Analysis**: Send code to LLM with React-specific security prompts
9. **Response Parsing**: Extract findings from LLM response (via SecurityAnalyzer)
10. **Severity Filtering**: Filter findings based on --severity threshold
11. **Metadata Enrichment**: Add file info, component analysis, and framework details
12. **Output Formatting**: Format results in requested format (Console, JSON, Markdown, SARIF)
13. **Output Display/Save**: Display to console or save to file
14. **Summary Display**: Show severity distribution, framework, React version, and analysis metrics
15. **Exit Code**: Return appropriate exit code (0, 1, 2, or 130)

### 7. Prompt Engineering
- Design specialized security analysis prompts for React/TypeScript (implemented in SecurityAnalyzer)
- Include context about React security best practices (React docs, OWASP)
- Request structured output from LLM
- Use few-shot examples for consistency (XSS, auth issues, etc.)
- Implement chain-of-thought prompting for complex component analysis
- Include React-specific security patterns in system prompt
- Provide examples of secure and insecure React patterns

### 8. Error Handling
- Graceful handling of malformed JSX/TSX syntax via validate_react_file()
- Clear error messages for file validation failures
- Clear error messages for connection issues (LM Studio not accessible)
- Validation of LLM responses (via SecurityAnalyzer parsing)
- Specific exception types: FileNotFoundError, ValueError, KeyboardInterrupt
- Exit codes for different error scenarios
- Multi-encoding fallback for file reading errors

### 9. Performance Requirements
- Support files up to 10,000 lines (warnings for larger files)
- Complete analysis within reasonable time (model-dependent)
- Efficient token usage for large component files through SecurityAnalyzer
- Memory-efficient file processing
- Chunking support for large files (implemented in SecurityAnalyzer)
- ReactParser provides quick component/hook detection before full analysis

### 10. Configuration
The tool uses a multi-source configuration system with precedence ordering:

**Configuration Precedence** (highest to lowest):
1. Command-line arguments (highest priority)
2. Environment variables
3. Configuration file (YAML/JSON via `--config`)
4. Hardcoded defaults

**Configuration Options**:
- **LLM Settings**: `lm_studio_url`, `model`, `temperature`, `max_tokens`
- **Output Settings**: `output` format, `output_file`, `severity` filter
- **React-Specific Settings**: `react_version`, `check_hooks`, `check_performance`, `framework`, `include_dependencies`
- **Analysis Options**: Managed via SecurityAnalyzer module
- **Logging**: `verbose` flag for debug-level output

**Configuration Loading**:
Implemented in the `Config` module with `Config.load(config_file, cli_args)` method that merges all sources according to precedence.

### 11. Configuration File Format
Support configuration via:
- Configuration file (YAML/JSON)
- Environment variables
- Command-line arguments (highest priority)

Configuration options:
```yaml
# LLM Settings
model: "qwen/qwen3-coder-30b"
lm_studio_url: "http://localhost:1234"
temperature: 0.0
max_tokens: 4096

# Output Settings
output_format: "console"
output_file: null
severity_filter: "info"

# React-Specific Settings
react_version: 18
check_hooks: true
check_performance: false
framework: "react"  # react, next, remix, gatsby

# Analysis Settings
chunk_size: 5000
enable_chunking: true
retry_attempts: 3
retry_delay: 2
timeout: 300

# Security Rules
custom_rules:
  dangerous_functions:
    - "dangerouslySetInnerHTML"
    - "eval"
    - "Function"
    - "innerHTML"
    - "document.write"

  sensitive_storage_keys:
    - "token"
    - "password"
    - "secret"
    - "apikey"
    - "credential"

  unsafe_attributes:
    - "dangerouslySetInnerHTML"
    - "srcDoc"

  framework_specific:
    next:
      - "getServerSideProps without validation"
      - "API routes without auth"
```

### 12. Logging & Debugging
- Structured logging with timestamps and log levels
- Log levels: DEBUG (with --verbose), INFO, WARNING, ERROR, CRITICAL
- Performance metrics: Analysis duration, file size, lines of code
- React metadata logging: Component count, hooks used, TypeScript detection
- Connection status logging
- Framework and React version information
- Progress indicators for long-running analyses
- Error messages sanitized (no code leakage in logs)

### 13. Exit Codes
The tool uses specific exit codes to indicate analysis results:

- **0**: Success - No critical or high severity vulnerabilities found
- **1**: High severity vulnerabilities detected
- **2**: Critical severity vulnerabilities detected
- **130**: Interrupted by user (Ctrl+C / KeyboardInterrupt)

Exit codes enable CI/CD integration and automated decision-making based on severity.

### 14. Modular Architecture
The implementation uses a clean modular design with separation of concerns:

**Core Modules** (in `modules/` directory):

1. **config.py** - Configuration Management
   - Multi-source configuration loading (CLI, ENV, YAML, defaults)
   - Configuration validation and merging
   - Type-safe configuration access
   - React-specific configuration options

2. **llm_connector.py** - LLM Communication
   - LM Studio API client using LangChain
   - Connection testing and health checks
   - Retry logic for transient failures
   - Request/response handling

3. **security_analyzer.py** - Security Analysis Engine
   - Prompt engineering for React/TypeScript security analysis
   - LLM response parsing and validation
   - Chunking logic for large files
   - Findings extraction and structuring

4. **output_formatter.py** - Output Generation
   - Multiple output format support (Console, JSON, Markdown, SARIF)
   - Report generation and formatting
   - Severity-based filtering and sorting
   - React metadata integration

5. **react_parser.py** - React File Analysis
   - React file validation (`validate_react_file()`)
   - Component detection and counting
   - Hooks usage pattern analysis
   - TypeScript vs JavaScript detection
   - File metadata extraction

**Main Script**: `AeyeGuard_react.py`
- CLI argument parsing with React-specific options
- Workflow orchestration
- File validation and reading
- ReactParser integration
- Error handling and exit code management

## Non-Functional Requirements

### Security
- All analysis performed locally (no external API calls)
- No code exfiltration
- Secure handling of analyzed code in memory
- No persistent storage of analyzed code
- Input validation for all user inputs
- Sanitize output to prevent injection in reports

### Reliability
- Consistent results for same input (temperature=0.0 by default)
- Robust error recovery with try-except blocks
- Validation of LLM output format via SecurityAnalyzer
- Graceful degradation on connection failures
- Multi-encoding fallback for file reading
- Proper exception handling with specific error messages
- React file validation before analysis
- JSX/TSX parsing via ReactParser module

### Maintainability
- Modular architecture with clear separation of concerns (5 distinct modules)
- Docstrings for all major functions and classes
- Type hints throughout (Python typing module)
- Five specialized modules for different responsibilities
- Clean error handling patterns
- Configurable behavior via CLI and config files
- React-specific ReactParser module for extensibility

### Usability
- Clear, actionable output in multiple formats
- Progress indicators with file size, line count, and React metadata
- Informative logging at appropriate levels
- Helpful error messages for common issues (file validation, connection failures)
- Severity-based summary output
- Analysis duration reporting
- Framework and React version display
- Component and hooks usage summary
- Warning messages for large files
- React-specific context in all outputs

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
- `logging` - Structured logging
- `datetime` - Timestamp generation
- `typing` - Type hints

**Python Version**: 3.8 or higher

## Project Structure
```
secscan_react/
   AeyeGuard_react.py              # Main entry point
   modules/
      __init__.py
      config.py                 # Configuration management
      llm_connector.py          # LLM integration
      security_analyzer.py      # Security analysis logic
      output_formatter.py       # Output formatting
      react_parser.py           # React/TSX parsing utilities
      vulnerability_patterns.py # React vulnerability patterns
   requirements.txt              # Python dependencies
   config.example.yaml           # Example configuration
   README.md                     # Documentation
   QUICKSTART.md                 # Quick start guide
   docs/
       specifications.md         # This file
```

## React Security Knowledge Base

The LLM prompt should include awareness of:

1. **React Security Documentation**
   - Official React security guidelines
   - dangerouslySetInnerHTML warnings
   - XSS prevention in React

2. **OWASP Guidelines for SPAs**
   - OWASP Top 10 for frontend
   - Client-side security best practices

3. **React Patterns to Flag**
   - Direct DOM manipulation bypassing React
   - Unsafe use of refs with user input
   - Missing key props in lists
   - Unvalidated props spreading

4. **TypeScript Security**
   - Type assertions removing safety
   - 'any' type in security-critical code
   - Missing type guards

5. **Modern React Features**
   - Server Components security boundaries
   - Suspense and error boundaries
   - Streaming SSR considerations

## Current Implementation Status

**Fully Implemented**:
- ✅ Single React/TypeScript file analysis (.tsx, .jsx)
- ✅ LM Studio integration with LangChain
- ✅ Multi-format output (Console, JSON, Markdown, SARIF)
- ✅ Configurable via CLI, ENV, and config files
- ✅ Severity filtering
- ✅ Exit codes for CI/CD integration
- ✅ Multi-encoding file support (UTF-8, UTF-16, Latin-1)
- ✅ Modular architecture with 5 core modules
- ✅ Connection testing before analysis
- ✅ Progress indicators and logging
- ✅ React-specific features:
  - ✅ ReactParser for component/hooks detection
  - ✅ React version configuration
  - ✅ Framework selection (React, Next.js, Remix, Gatsby)
  - ✅ Hooks security analysis (enabled by default)
  - ✅ Performance checking option
  - ✅ Dependency analysis option
  - ✅ React metadata in output

**Handled by Parent Tool** (`secscan.py`):
- ✅ Multiple files/directory scanning
- ✅ Parallel processing
- ✅ Recursive directory traversal

## Exit Codes (Implemented)

- **0**: Success (no critical/high vulnerabilities)
- **1**: High severity vulnerabilities found
- **2**: Critical severity vulnerabilities found
- **130**: Interrupted by user (Ctrl+C)

## Future Enhancements (Planned)

- Multi-file analysis with import tracking
- Component dependency graph analysis
- Integration with React DevTools
- Integration with ESLint security plugins
- Custom rule definitions (user-extensible)
- Comparison with other tools (Snyk, npm audit)
- Support for Vue.js, Angular (separate analyzers)
- CI/CD pipeline integration
- Web UI for visualization
- Historical vulnerability tracking
- IDE plugins (VS Code, WebStorm)
- Real-time analysis during development
- Fix suggestions with automated patches

## Success Criteria

**Achieved**:
- ✅ Identifies common React/TypeScript security vulnerabilities using LLM analysis
- ✅ Provides structured output with severity levels and recommendations
- ✅ Operates entirely offline (local LM Studio)
- ✅ Supports multiple output formats for different use cases
- ✅ Integrates with CI/CD via exit codes
- ✅ Easy to use with sensible defaults
- ✅ Produces consistent results (temperature=0.0 default)
- ✅ Handles files up to 10,000+ lines (with chunking support)
- ✅ Configurable via multiple methods (CLI, ENV, config file)
- ✅ Clear error messages and logging
- ✅ React-specific features:
  - ✅ Component and hooks analysis
  - ✅ Framework-aware analysis (React, Next.js, Remix, Gatsby)
  - ✅ TypeScript detection and reporting
  - ✅ React metadata in all outputs

## Example Use Cases

### Use Case 1: XSS Detection
```tsx
// Input file with vulnerability
function UserProfile({ user }) {
  return <div dangerouslySetInnerHTML={{ __html: user.bio }} />; // CRITICAL
}
```

**Expected Output:**
- Severity: CRITICAL
- CWE-79: Cross-site Scripting (XSS)
- Location: Line 3
- Issue: Unsanitized user input rendered with dangerouslySetInnerHTML
- Remediation: Use DOMPurify or remove dangerouslySetInnerHTML

### Use Case 2: Insecure State Storage
```tsx
// Input file with vulnerability
const saveToken = (token: string) => {
  localStorage.setItem('authToken', token); // HIGH
};
```

**Expected Output:**
- Severity: HIGH
- CWE-312: Cleartext Storage of Sensitive Information
- Location: Line 3
- Issue: Authentication token stored in localStorage without encryption
- Remediation: Use secure, httpOnly cookies or encrypted storage

### Use Case 3: Missing Hook Dependencies
```tsx
// Input file with vulnerability
useEffect(() => {
  fetchData(userId); // MEDIUM - userId not in dependencies
}, []); // Missing dependency
```

**Expected Output:**
- Severity: MEDIUM
- Issue: Stale closure may cause security bypass
- Location: Line 2-3
- Remediation: Add userId to dependency array or use useCallback

## Integration with secscan.py

When integrated with the recursive scanner:
- secscan.py will detect .tsx, .jsx, .ts files with React imports
- Delegate to AeyeGuard_react.py for analysis
- Forward common options (model, temperature, severity, etc.)
- Aggregate results with other language analyzers

## Testing Strategy

1. **Unit Tests**: Test individual vulnerability detection patterns
2. **Integration Tests**: Test with real React components
3. **Regression Tests**: Maintain suite of known vulnerabilities
4. **False Positive Tests**: Ensure safe patterns aren't flagged
5. **Performance Tests**: Benchmark against large component files
