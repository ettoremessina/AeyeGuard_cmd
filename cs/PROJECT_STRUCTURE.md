# Project Structure

```
secscan_cs/
│
├── AeyeGuard_cs.py                 # Main entry point - CLI interface
│
├── modules/                      # Core modules
│   ├── __init__.py              # Package initialization
│   ├── config.py                # Configuration management
│   ├── llm_connector.py         # LM Studio API integration
│   ├── security_analyzer.py     # Security analysis orchestration
│   └── output_formatter.py      # Report formatting (JSON, MD, SARIF, Console)
│
├── README.md                     # Main documentation
├── QUICKSTART.md                 # Quick start guide
│
├── config.example.yaml           # Example configuration file
├── .env.example                  # Example environment variables
└── .gitignore                    # Git ignore rules

```

## Module Descriptions

### AeyeGuard_cs.py
- Main entry point for the application
- Handles command-line argument parsing
- Orchestrates the analysis workflow
- Manages file I/O and error handling
- Returns appropriate exit codes

### modules/config.py
- Multi-source configuration management
- Loads settings from:
  - Configuration files (YAML/JSON)
  - Environment variables
  - Command-line arguments
- Validates configuration parameters
- Provides default values

### modules/llm_connector.py
- Interfaces with LM Studio local server
- Implements OpenAI-compatible API calls
- Provides retry logic for failed requests
- Handles connection testing
- Supports structured (JSON) output parsing

### modules/security_analyzer.py
- Core security analysis logic
- Prompt engineering for security analysis
- Handles large file chunking
- Processes and validates LLM responses
- Deduplicates findings
- Assigns severity levels and CWE IDs

### modules/output_formatter.py
- Generates reports in multiple formats:
  - Console (human-readable with colors/emojis)
  - JSON (machine-readable)
  - Markdown (documentation-friendly)
  - SARIF (IDE integration)
- Groups findings by severity
- Formats code snippets and remediation advice

## Data Flow

```
┌─────────────────┐
│   C# File       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  AeyeGuard_cs.py  │ ◄─── Configuration
│  (Main Entry)   │      (CLI/ENV/File)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Config Module  │
│  Load Settings  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  LLM Connector  │ ◄─── LM Studio API
│  Test Connection│      (localhost:1234)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Security        │
│ Analyzer        │
│ - Build Prompts │
│ - Send to LLM   │
│ - Parse Results │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Output          │
│ Formatter       │
│ - Format Report │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Console/File    │
│ Output          │
└─────────────────┘
```

## Key Design Decisions

### Modular Architecture
- Separation of concerns for maintainability
- Easy to add new output formats
- Simple to swap LLM providers
- Testable components

### Local-First
- All analysis performed locally
- No external API calls
- Complete privacy for source code
- Works offline

### Flexible Configuration
- Multiple configuration sources
- Clear precedence order
- Environment-specific settings
- Sensible defaults

### Robust Error Handling
- Retry logic for transient failures
- Graceful degradation
- Helpful error messages
- Multiple encoding support

### Extensible
- Easy to add new security checks
- Custom rule support
- Plugin-ready architecture
- Multiple output formats

## Dependencies

### Core Dependencies
- **langchain** - LLM orchestration framework
- **langchain-community** - Community LLM integrations
- **requests** - HTTP client for LM Studio API
- **pyyaml** - YAML configuration file support
- **python-dotenv** - Environment variable loading

### Optional Dependencies
- **colorlog** - Enhanced colored logging
- **pytest** - Testing framework (dev)
- **pytest-cov** - Code coverage (dev)

## Configuration Precedence

```
┌─────────────────────────────────────┐
│  1. Command-line Arguments          │  Highest Priority
│     --model, --temperature, etc.    │
├─────────────────────────────────────┤
│  2. Environment Variables           │
│     SECSCAN_MODEL, SECSCAN_URL      │
├─────────────────────────────────────┤
│  3. Configuration File              │
│     config.yaml                     │
├─────────────────────────────────────┤
│  4. Default Values                  │  Lowest Priority
│     Built into code                 │
└─────────────────────────────────────┘
```

## Security Considerations

1. **Local Analysis Only** - No code sent to external services
2. **No Persistent Storage** - Code not saved to disk (except user choice)
3. **Input Validation** - All user inputs validated
4. **Secure Defaults** - Conservative default settings
5. **Log Sanitization** - Sensitive data removed from logs

## Performance Characteristics

- **Small Files (<1000 lines)**: 30-60 seconds
- **Medium Files (1000-5000 lines)**: 1-3 minutes
- **Large Files (5000-10000 lines)**: 3-10 minutes
- **Very Large Files (>10000 lines)**: Auto-chunked, varies

*Times depend on model size and hardware*

## Future Enhancements

- [ ] Multi-file/directory scanning
- [ ] Parallel analysis of multiple files
- [ ] CI/CD integration scripts
- [ ] Custom security rule DSL
- [ ] Web UI dashboard
- [ ] VS Code extension
- [ ] Support for other languages (Java, Python, etc.)
- [ ] Incremental analysis (scan only changes)
- [ ] Database for historical tracking
