# Quick Start Guide - AeyeGuard_cs

Get up and running with AeyeGuard_cs in 5 minutes!

## Step 1: Install Dependencies

```bash
pip install -r ../requirements.txt
```

## Step 2: Start LM Studio

1. Download and install LM Studio from https://lmstudio.ai/
2. Launch LM Studio
3. Download and load the model `qwen/qwen3-coder-30b` (or any code-capable model)
4. Start the local server (should run on http://localhost:1234)

## Step 3: Verify Setup

```bash
python ../tests/cs/setup_test.py
```

This will check:
- Python version (need 3.8+)
- Required packages
- LM Studio connection
- Loaded models

## Step 4: Run Your First Scan

Try scanning the example vulnerable C# file:

```bash
python AeyeGuard_cs.py ../examples/example_vulnerable.cs
```

You should see a security analysis report identifying various vulnerabilities!

## Step 5: Scan Your Own Code

```bash
python AeyeGuard_cs.py path/to/your/file.cs
```

## Common Commands

### Save report to file
```bash
python AeyeGuard_cs.py file.cs --output json --output-file report.json
```

### Show only critical/high issues
```bash
python AeyeGuard_cs.py file.cs --severity high
```

### Use a different model
```bash
python AeyeGuard_cs.py file.cs --model "your-model-name"
```

### Enable verbose logging
```bash
python AeyeGuard_cs.py file.cs --verbose
```

## Troubleshooting

### "Cannot connect to LM Studio"
- Make sure LM Studio is running
- Check that the server is started in LM Studio
- Default URL is http://localhost:1234

### "No model loaded"
- Load a model in LM Studio before scanning
- Recommended: qwen/qwen3-coder-30b

### Analysis is slow
- This is normal for large files or complex code
- Larger models provide better results but are slower
- Consider using a smaller model for faster analysis

### Poor quality results
- Use a larger, more capable model
- Lower the temperature: `--temperature 0.1`
- Ensure the model is designed for code analysis

## Next Steps

1. Read the full [README.md](README.md) for detailed usage
2. Check [docs/AeyeGuard_cs_specifications.md](../docs/AeyeGuard_cs_specifications.md) for technical details
3. Customize [config.example.yaml](config.example.yaml) for your needs

## Example Output

When you run the scan, you'll see output like:

```
🔴 CRITICAL SEVERITY (2 findings)
======================================================================

1. SQL Injection in User Query
   Line: 45
   CWE: CWE-89

   Description:
   User input is directly concatenated into SQL query...

   Remediation:
   Use parameterized queries with SqlParameter...
```

## Support

- Issues: Open a GitHub issue
- Documentation: See README.md
- Configuration: See config.example.yaml

Happy scanning! 🔒
