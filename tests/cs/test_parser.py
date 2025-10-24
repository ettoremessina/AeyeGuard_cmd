#!/usr/bin/env python3
"""
Test utility to debug the text parser with sample responses.
"""

import sys
sys.path.insert(0, '../../cs')
from modules.security_analyzer import SecurityAnalyzer
from modules.config import Config

def test_parser(sample_text: str):
    """Test the parser with sample text."""
    # Create a dummy config and analyzer
    config = Config()

    # Create SecurityAnalyzer instance (we just need the parser method)
    class DummyLLM:
        pass

    analyzer = SecurityAnalyzer(DummyLLM(), config)

    # Parse the text
    result = analyzer._parse_text_for_summary(sample_text)

    print("="*70)
    print("PARSING TEST RESULTS")
    print("="*70)
    print(f"Total Findings: {result['total_findings']}")
    print(f"Has Vulnerabilities: {result['has_vulnerabilities']}")
    print(f"\nSeverity Distribution:")
    for severity, count in result['severity_distribution'].items():
        if count > 0:
            print(f"  {severity.capitalize()}: {count}")
    print("="*70)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Read from file
        with open(sys.argv[1], 'r') as f:
            sample_text = f.read()
    else:
        # Use sample text from stdin or default
        print("Enter sample LLM response (Ctrl+D when done):")
        sample_text = sys.stdin.read()

    if sample_text.strip():
        test_parser(sample_text)
    else:
        print("No input provided. Usage:")
        print("  python test_parser.py <file>")
        print("  cat response.txt | python test_parser.py")
        print("  python test_parser.py  (then paste text and press Ctrl+D)")
