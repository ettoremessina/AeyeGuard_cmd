#!/bin/bash
# Test script for React security analyzer

echo "Testing React Security Analyzer"
echo "================================"
echo ""

# Check if LM Studio is running
echo "Checking LM Studio connection..."
curl -s http://localhost:1234/v1/models > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "ERROR: Cannot connect to LM Studio at http://localhost:1234"
    echo "Please start LM Studio and load a model before running this test."
    exit 1
fi
echo "✓ LM Studio is running"
echo ""

# Run analysis with verbose output
echo "Running analysis on example_vulnerable.tsx..."
echo "This may take a few minutes..."
echo ""

python3 ../../react/AeyeGuard_react.py ../../examples/example_vulnerable.tsx --verbose

echo ""
echo "================================"
echo "Test complete!"
echo ""
echo "Check for:"
echo "  - example_vulnerable_llm_response.txt (full LLM response)"
echo "  - Console output showing detected vulnerabilities"
