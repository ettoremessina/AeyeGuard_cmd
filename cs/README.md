# AeyeGuard_cs - Security Static Analysis Tool for C# Files

A Python-based security static analysis tool that leverages local LLM capabilities to perform comprehensive security vulnerability detection in C# source code files. All analysis is performed locally using LM Studio, ensuring privacy and security of your code.

## Features

- **Local LLM Analysis**: Uses LM Studio for completely offline security analysis
- **Comprehensive Security Checks**: Identifies SQL injection, XSS, authentication issues, cryptography weaknesses, and more
- **Multiple Output Formats**: Console, JSON, Markdown, and SARIF
- **Smart Chunking**: Handles large files by intelligently splitting them for analysis
- **Detailed Reports**: Includes CWE identifiers, exploitation scenarios, and remediation advice
- **Configurable**: Supports configuration files, environment variables, and CLI arguments

## Security Focus Areas

The tool analyzes C# code for:

1. **Input Validation Vulnerabilities**
   - SQL injection
   - Command injection
   - Path traversal
   - XML/XXE injection
   - LDAP injection

2. **Authentication & Authorization**
   - Weak authentication mechanisms
   - Missing authorization checks
   - Insecure credential storage
   - Session management issues

3. **Cryptography Issues**
   - Weak algorithms
   - Hardcoded secrets
   - Insecure random number generation
   - Improper certificate validation

4. **Data Exposure**
   - Sensitive data in logs
   - Information disclosure
   - Insecure deserialization
   - PII handling issues

5. **Code Quality & Logic**
   - Race conditions
   - Null reference vulnerabilities
   - Resource leaks
   - Exception handling issues

6. **.NET Specific Issues**
   - Unsafe reflection usage
   - Dynamic code execution risks
   - Insecure XML parsing
   - ViewState vulnerabilities

## Prerequisites

1. **Python 3.8 or higher**
2. **LM Studio** installed and running
   - Download from: https://lmstudio.ai/
   - Load a code analysis model (recommended: qwen/qwen3-coder-30b)

## Installation

1. Clone or download this repository:
```bash
git clone <repository-url>
cd secscan_cs
```

2. Install Python dependencies:
```bash
pip install -r ../requirements.txt
```

3. Make the script executable (optional):
```bash
chmod +x AeyeGuard_cs.py
```

## Quick Start

1. Start LM Studio and load a model (e.g., qwen/qwen3-coder-30b)

2. Run analysis on a C# file:
```bash
python AeyeGuard_cs.py path/to/your/file.cs
```

3. View the security analysis results in your console

## Usage Examples

### Basic Usage

Analyze a C# file with default settings:
```bash
python AeyeGuard_cs.py example.cs
```

### Output Formats

#### Console Output (Default)
```bash
python AeyeGuard_cs.py example.cs
```

#### JSON Output
```bash
python AeyeGuard_cs.py example.cs --output json
```

#### Save to File
```bash
python AeyeGuard_cs.py example.cs --output json --output-file report.json
```

#### Markdown Report
```bash
python AeyeGuard_cs.py example.cs --output markdown --output-file report.md
```

#### SARIF Format (for IDE integration)
```bash
python AeyeGuard_cs.py example.cs --output sarif --output-file report.sarif
```

### Configuration Options

#### Use Different Model
```bash
python AeyeGuard_cs.py example.cs --model "codellama/CodeLlama-13b-Instruct"
```

#### Custom LM Studio URL
```bash
python AeyeGuard_cs.py example.cs --lm-studio-url http://192.168.1.100:1234
```

#### Adjust Temperature (0.0 - 1.0)
```bash
python AeyeGuard_cs.py example.cs --temperature 0.1
```

#### Filter by Severity
Show only critical and high severity findings:
```bash
python AeyeGuard_cs.py example.cs --severity high
```

#### Verbose Logging
```bash
python AeyeGuard_cs.py example.cs --verbose
```

### Using Configuration File

1. Copy the example configuration:
```bash
cp config.example.yaml config.yaml
```

2. Edit `config.yaml` with your preferences

3. Run with configuration:
```bash
python AeyeGuard_cs.py example.cs --config config.yaml
```

### Environment Variables

Set environment variables for persistent configuration:
```bash
export SECSCAN_MODEL="qwen/qwen3-coder-30b"
export SECSCAN_LM_STUDIO_URL="http://localhost:1234"
export SECSCAN_TEMPERATURE="0.2"

python AeyeGuard_cs.py example.cs
```

## Configuration Precedence

Configuration is loaded in the following order (highest priority first):

1. Command-line arguments
2. Environment variables
3. Configuration file
4. Default values

## Output Format Examples

### Console Output
```
🔴 CRITICAL SEVERITY (2 findings)
======================================================================

1. SQL Injection in User Query
   Line: 45
   CWE: CWE-89

   Description:
   User input is directly concatenated into SQL query without validation...

   Vulnerable Code:
   > string query = "SELECT * FROM Users WHERE id = " + userId;

   Remediation:
   Use parameterized queries...
```

### JSON Output
```json
{
  "findings": [
    {
      "title": "SQL Injection in User Query",
      "severity": "critical",
      "cwe_id": "CWE-89",
      "line_number": 45,
      "description": "...",
      "remediation": "..."
    }
  ],
  "summary": {
    "total_findings": 2,
    "severity_distribution": {
      "critical": 2,
      "high": 0,
      "medium": 0
    }
  }
}
```

## Exit Codes

- `0`: Success (no critical/high vulnerabilities)
- `1`: High severity vulnerabilities found
- `2`: Critical severity vulnerabilities found
- `130`: Interrupted by user (Ctrl+C)

## Performance Tips

1. **Large Files**: The tool automatically chunks files larger than 5,000 lines
2. **Model Selection**: Larger models provide better analysis but are slower
3. **Temperature**: Lower temperature (0.1-0.2) provides more consistent results
4. **Timeout**: Adjust `--max-tokens` if analysis times out

## Troubleshooting

### "Cannot connect to LM Studio"
- Ensure LM Studio is running
- Verify the URL (default: http://localhost:1234)
- Check if a model is loaded in LM Studio

### "Model not found"
- Load the model in LM Studio first
- The tool will use whatever model is currently loaded

### Analysis Takes Too Long
- Try a smaller model
- Reduce `max_tokens` parameter
- Enable chunking for large files

### Poor Quality Results
- Use a larger, more capable model
- Lower the temperature to 0.1 for more consistent results
- Ensure your model is designed for code analysis

## Project Structure

```
secscan_cs/
├── AeyeGuard_cs.py              # Main entry point
├── modules/
│   ├── __init__.py
│   ├── config.py              # Configuration management
│   ├── llm_connector.py       # LLM integration
│   ├── security_analyzer.py   # Security analysis logic
│   └── output_formatter.py    # Output formatting
├── requirements.txt           # Python dependencies
├── config.example.yaml        # Example configuration
└── README.md                  # This file
```

## Architecture

The tool follows a modular architecture:

1. **Main Script** (`AeyeGuard_cs.py`): CLI interface and orchestration
2. **Config Module**: Multi-source configuration management
3. **LLM Connector**: LM Studio API integration with retry logic
4. **Security Analyzer**: Analysis orchestration and prompt engineering
5. **Output Formatter**: Multi-format report generation

## Development

### Running Tests
```bash
# Install dev dependencies
pip install pytest pytest-cov

# Run tests
pytest tests/
```

### Adding Custom Security Rules

Edit your configuration file to add custom patterns:
```yaml
custom_rules:
  dangerous_functions:
    - "System.Diagnostics.Process.Start"
    - "CustomDangerousFunction"
```

## Limitations

- Analysis quality depends on the LLM model used
- Large files (>10,000 lines) may require significant processing time
- The tool identifies potential vulnerabilities; manual review is recommended
- Not a replacement for comprehensive security testing

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

[Your License Here]

## Security

This tool is designed for defensive security purposes only. Do not use it to:
- Create exploits or malicious code
- Perform unauthorized security testing
- Harvest credentials or sensitive data

## Acknowledgments

- Built with [LangChain](https://www.langchain.com/)
- Uses [LM Studio](https://lmstudio.ai/) for local LLM inference
- Inspired by traditional SAST tools like SonarQube and Semgrep

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check the [specifications document](../docs/AeyeGuard_cs_specifications.md)
- Review the [troubleshooting section](#troubleshooting)

## Changelog

### Version 1.0.0
- Initial release
- Support for C# security analysis
- Multiple output formats
- Configurable LLM integration
- Chunking for large files
