#!/usr/bin/env python3
"""
Test the parser without requiring LLM Studio.
This simulates what the LLM might respond.
"""

import sys
import logging
from pathlib import Path

# Add modules to path
sys.path.insert(0, str(Path(__file__).parent / '../../react'))

from modules.security_analyzer import SecurityAnalyzer
from modules.config import Config

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Sample LLM responses to test parser
test_responses = {
    "formatted": """
Analysis of ../examples/example_vulnerable.tsx:

## Findings

### 1. XSS via dangerouslySetInnerHTML

**Title**: Unsafe use of dangerouslySetInnerHTML
**Severity**: critical
**CWE ID**: CWE-79
**Line Number**: 14
**Description**: User-controlled bio data is rendered directly with dangerouslySetInnerHTML
**Remediation**: Use DOMPurify to sanitize HTML

### 2. Hardcoded API Key

**Title**: Hardcoded API key exposed
**Severity**: critical
**CWE ID**: CWE-798
**Line Number**: 40
**Description**: API key hardcoded in source code
**Remediation**: Use environment variables

### 3. Token in localStorage

**Title**: Authentication token stored in localStorage
**Severity**: high
**CWE ID**: CWE-312
**Line Number**: 20
**Description**: Sensitive token stored in localStorage without encryption
**Remediation**: Use secure httpOnly cookies
""",

    "plain": """
I found several security vulnerabilities in this React component:

1. dangerouslySetInnerHTML vulnerability - This is critical because user input is being rendered as HTML without sanitization
2. localStorage is being used to store authentication tokens - This is a high severity issue
3. eval() is being used with user input - Critical security risk
4. useEffect is missing dependencies - Medium severity issue
5. console.log with sensitive data - Low severity
""",

    "minimal": """
Found 5 vulnerabilities:
- XSS via dangerouslySetInnerHTML (critical)
- Hardcoded API key (critical)
- localStorage token storage (high)
- eval usage (critical)
- Missing useEffect deps (medium)
"""
}

def test_parser(response_text: str, test_name: str):
    """Test the parser with a sample response."""
    print(f"\n{'='*60}")
    print(f"Testing: {test_name}")
    print(f"{'='*60}\n")

    # Create minimal config
    config = Config()

    # Create analyzer (without LLM)
    analyzer = SecurityAnalyzer(None, config)

    # Test the parser
    result = analyzer._parse_text_for_summary(response_text)

    print(f"Results:")
    print(f"  Total findings: {result['total_findings']}")
    print(f"  Has vulnerabilities: {result['has_vulnerabilities']}")
    print(f"  Severity distribution:")
    for severity, count in result['severity_distribution'].items():
        if count > 0:
            print(f"    {severity}: {count}")

    return result

# Run tests
print("React Security Analyzer - Parser Test")
print("="*60)

for name, response in test_responses.items():
    result = test_parser(response, name)

    if result['total_findings'] == 0:
        print(f"\n⚠️  WARNING: Parser found 0 findings in '{name}' format!")
    else:
        print(f"\n✓ Parser successfully detected {result['total_findings']} findings")

print(f"\n{'='*60}")
print("Test complete!")
print("="*60)
