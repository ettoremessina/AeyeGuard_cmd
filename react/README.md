# AeyeGuard_react - Security Static Analysis Tool for React TypeScript Files

A Python-based security static analysis tool that leverages local LLM capabilities to perform comprehensive security vulnerability detection in React/TypeScript source code files.

## Features

- **Local LLM Analysis**: Uses LM Studio for completely offline security analysis
- **React-Specific Security Checks**: Identifies XSS, authentication issues, unsafe hooks patterns, and more
- **TypeScript Support**: Analyzes TypeScript-specific security issues
- **Multiple Frameworks**: Supports React, Next.js, Remix, and Gatsby
- **Multiple Output Formats**: Console, JSON, Markdown, and SARIF
- **Smart Chunking**: Handles large files by intelligently splitting them for analysis
- **Detailed Reports**: Includes CWE identifiers, exploitation scenarios, and remediation advice

## Prerequisites

1. **Python 3.8 or higher**
2. **LM Studio** installed and running
   - Download from: https://lmstudio.ai/
   - Load a code analysis model (recommended: qwen/qwen3-coder-30b)

## Installation

1. Navigate to the tsx directory:
```bash
cd tsx
```

2. Install Python dependencies:
```bash
pip install -r ../requirements.txt
```

3. Verify setup:
```bash
python AeyeGuard_react.py --help
```

## Quick Start

1. Start LM Studio and load a model (e.g., qwen/qwen3-coder-30b)

2. Run analysis on a React TypeScript file:
```bash
python AeyeGuard_react.py path/to/component.tsx
```

3. View the security analysis results in your console

## Usage Examples

### Basic Analysis
```bash
python AeyeGuard_react.py component.tsx
```

### Save Report to File
```bash
python AeyeGuard_react.py component.tsx --output json --output-file report.json
```

### Next.js Project Analysis
```bash
python AeyeGuard_react.py page.tsx --framework next --react-version 18
```

### Filter by Severity
```bash
python AeyeGuard_react.py component.tsx --severity high
```

### Verbose Output
```bash
python AeyeGuard_react.py component.tsx --verbose
```

### Use Configuration File
```bash
cp config.example.yaml config.yaml
# Edit config.yaml with your preferences
python AeyeGuard_react.py component.tsx --config config.yaml
```

## Security Focus Areas

The tool analyzes React/TypeScript code for:

### Cross-Site Scripting (XSS)
- dangerouslySetInnerHTML with user input
- Direct DOM manipulation (innerHTML, outerHTML)
- Unsafe ref usage
- Dynamic script injection
- eval() or Function() constructor

### Authentication & Authorization
- Client-side only auth checks
- Token storage in localStorage
- Hardcoded API keys
- Missing CSRF protection
- JWT vulnerabilities

### State Management
- Sensitive data in Redux/Context state
- State mutation vulnerabilities
- Race conditions
- PII in client-side state

### React Hooks & Patterns
- useEffect missing dependencies
- Memory leaks
- Infinite render loops
- Conditional hooks
- Missing key props

### Data Exposure
- console.log with sensitive data
- Error boundaries exposing info
- Redux DevTools in production
- Source maps exposure

### TypeScript Issues
- Type assertion to 'any'
- Missing type guards
- Unsafe type coercion

### Modern React (18+)
- Server Components security
- Suspense error leakage
- Streaming SSR issues
- Server actions validation

## Command-Line Options

```bash
python AeyeGuard_react.py <file.tsx> [options]
```

### Required
- `input_file` - Path to TSX/JSX file to analyze

### LLM Configuration
- `--model MODEL` - LLM model name (default: qwen/qwen3-coder-30b)
- `--lm-studio-url URL` - LM Studio endpoint (default: http://localhost:1234)
- `--temperature FLOAT` - LLM temperature (default: 0.0)
- `--max-tokens INT` - Max tokens for response (default: 4096)

### Output Options
- `--output FORMAT` - Output format: console, json, markdown, sarif (default: console)
- `--output-file PATH` - Save report to file
- `--severity LEVEL` - Minimum severity: critical, high, medium, low, info (default: info)

### React-Specific Options
- `--react-version VERSION` - Target React version (default: 18)
- `--check-hooks` - Enable Hooks analysis (default: enabled)
- `--check-performance` - Include performance security issues
- `--framework NAME` - Framework: react, next, remix, gatsby (default: react)
- `--include-dependencies` - Analyze imports

### General Options
- `--config PATH` - Configuration file (YAML or JSON)
- `--verbose` - Enable verbose logging
- `--version` - Show version
- `--help` - Show help message

## Exit Codes

- `0` - Success (no critical/high vulnerabilities)
- `1` - High severity vulnerabilities found
- `2` - Critical severity vulnerabilities found
- `130` - Interrupted by user (Ctrl+C)

## Example Vulnerable Patterns

The tool detects patterns like:

### XSS via dangerouslySetInnerHTML
```tsx
// CRITICAL
function UserProfile({ user }) {
  return <div dangerouslySetInnerHTML={{ __html: user.bio }} />;
}
```

### Token in localStorage
```tsx
// HIGH
localStorage.setItem('authToken', token);
```

### Missing Hook Dependencies
```tsx
// MEDIUM
useEffect(() => {
  fetchData(userId);
}, []); // Missing userId
```

### Hardcoded Secrets
```tsx
// CRITICAL
const API_KEY = "sk-1234567890";
```

## Testing

Test the analyzer with the included vulnerable example:

```bash
python AeyeGuard_react.py ../examples/example_vulnerable.tsx
```

This file contains multiple security issues that the analyzer should detect.

## Configuration File

Create a `config.yaml` from the example:

```bash
cp config.example.yaml config.yaml
```

Configure settings like:
- LLM model and endpoint
- React version and framework
- Output format and severity filter
- Custom security rules

## Project Structure

```
react/
├── AeyeGuard_react.py          # Main entry point
├── modules/
│   ├── config.py             # Configuration management
│   ├── llm_connector.py      # LM Studio integration
│   ├── security_analyzer.py  # Security analysis logic
│   ├── output_formatter.py   # Output formatting
│   ├── react_parser.py       # React/TSX parsing
│   └── vulnerability_patterns.py  # Vulnerability patterns
├── requirements.txt          # Python dependencies
├── config.example.yaml       # Example configuration
└── docs/
    └── specificatios.md      # Detailed specifications
```

## Troubleshooting

### "Cannot connect to LM Studio"
- Ensure LM Studio is running
- Verify the URL (default: http://localhost:1234)
- Check if a model is loaded in LM Studio

### "Invalid React file"
- Ensure file has .tsx, .jsx, .ts, or .js extension
- For .ts/.js files, ensure they import React

### Analysis Takes Too Long
- Try a smaller model
- Reduce --max-tokens parameter
- Enable chunking for large files

### Poor Quality Results
- Use a larger, more capable model
- Ensure temperature is set to 0.0 for consistency
- Verify the model is designed for code analysis

## Integration

To integrate with the recursive scanner:

```bash
# From project root
python AeyeGuard_cmd.py /path/to/react/project --include-tsx
```

(Note: Recursive scanner integration for TSX files is planned)

## Security Note

This tool is designed for defensive security purposes only. Do not use it to:
- Create exploits or malicious code
- Perform unauthorized security testing
- Harvest credentials or sensitive data

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

[Your License Here]

## Support

For issues or questions:
- Check the [specifications document](docs/specificatios.md)
- Review this README
- Open an issue on GitHub
