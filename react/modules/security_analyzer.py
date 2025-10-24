"""
Security Analyzer module for React/TypeScript code analysis.

Orchestrates security analysis using LLM with specialized React security prompts.
"""

import logging
import re
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class SecurityAnalyzer:
    """Performs security analysis on React/TypeScript code using LLM."""

    # Severity levels in order
    SEVERITY_LEVELS = ['info', 'low', 'medium', 'high', 'critical']

    def __init__(self, llm_connector, config):
        """
        Initialize security analyzer.

        Args:
            llm_connector: LLMConnector instance
            config: Configuration object
        """
        self.llm = llm_connector
        self.config = config

    def analyze(self, code: str, file_path: str) -> Dict[str, Any]:
        """
        Perform comprehensive security analysis on React/TypeScript code.

        Args:
            code: React/TypeScript source code to analyze
            file_path: Path to the file being analyzed

        Returns:
            Analysis results dictionary
        """
        logger.info("Starting React security analysis...")

        # Check if chunking is needed
        lines = code.splitlines()
        if len(lines) > self.config.chunk_size and self.config.enable_chunking:
            logger.info(f"File has {len(lines)} lines, using chunked analysis")
            return self._analyze_chunked(code, file_path)
        else:
            return self._analyze_single(code, file_path)

    def _analyze_single(self, code: str, file_path: str) -> Dict[str, Any]:
        """
        Analyze code in a single pass.

        Args:
            code: React/TypeScript source code
            file_path: File path

        Returns:
            Analysis results
        """
        # Build prompts
        system_prompt = self._build_system_prompt()
        user_prompt = self._build_analysis_prompt(code, file_path)

        # Get LLM response
        logger.info("Requesting analysis from LLM...")
        response = self.llm.generate_structured(
            prompt=user_prompt,
            system_prompt=system_prompt
        )

        if not response:
            logger.error("Failed to get response from LLM")
            return self._create_empty_result(file_path, error="LLM analysis failed")

        # Process plain text response
        return self._process_text_response(response, file_path)

    def _analyze_chunked(self, code: str, file_path: str) -> Dict[str, Any]:
        """
        Analyze code in chunks for large files.

        Args:
            code: React/TypeScript source code
            file_path: File path

        Returns:
            Combined analysis results
        """
        lines = code.splitlines()
        chunk_size = self.config.chunk_size
        chunks = []

        # Split into chunks with overlap for context
        overlap = 50  # lines of overlap
        for i in range(0, len(lines), chunk_size - overlap):
            chunk_lines = lines[i:i + chunk_size]
            chunk_code = '\n'.join(chunk_lines)
            chunks.append({
                'code': chunk_code,
                'start_line': i + 1,
                'end_line': min(i + chunk_size, len(lines))
            })

        logger.info(f"Split file into {len(chunks)} chunks")

        all_findings = []

        # Analyze each chunk
        for idx, chunk in enumerate(chunks):
            logger.info(f"Analyzing chunk {idx + 1}/{len(chunks)} (lines {chunk['start_line']}-{chunk['end_line']})")

            system_prompt = self._build_system_prompt()
            user_prompt = self._build_analysis_prompt(
                chunk['code'],
                file_path,
                chunk_info=f"Lines {chunk['start_line']}-{chunk['end_line']}"
            )

            response = self.llm.generate_structured(
                prompt=user_prompt,
                system_prompt=system_prompt
            )

            if response:
                # Parse each chunk's response
                chunk_summary = self._parse_text_for_summary(response)

                # Store the text response for this chunk
                all_findings.append({
                    'chunk': idx + 1,
                    'lines': f"{chunk['start_line']}-{chunk['end_line']}",
                    'analysis': response,
                    'summary': chunk_summary
                })

        # Combine all chunk analyses
        combined_text = "\n\n" + "="*80 + "\n\n"
        combined_text = combined_text.join([
            f"CHUNK {chunk['chunk']} (Lines {chunk['lines']}):\n\n{chunk['analysis']}"
            for chunk in all_findings
        ])

        # Aggregate summaries from all chunks
        total_findings = sum(chunk['summary']['total_findings'] for chunk in all_findings)
        combined_severity = {level: 0 for level in self.SEVERITY_LEVELS}
        for chunk in all_findings:
            for severity, count in chunk['summary']['severity_distribution'].items():
                combined_severity[severity] += count

        has_vulnerabilities = any(chunk['summary']['has_vulnerabilities'] for chunk in all_findings)

        logger.info(f"Combined {len(all_findings)} chunks - Total findings: {total_findings}")

        # Build combined result with text
        result = {
            'findings': [],
            'analysis_text': combined_text,
            'summary': {
                'total_findings': total_findings,
                'severity_distribution': combined_severity,
                'file_analyzed': file_path,
                'chunks_analyzed': len(all_findings),
                'has_vulnerabilities': has_vulnerabilities
            },
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'tool': 'AeyeGuard_react',
                'version': '1.0.0',
                'model': self.config.model,
                'output_type': 'text',
                'chunked': True
            }
        }

        return result

    def _build_system_prompt(self) -> str:
        """Build system prompt for LLM with React/TypeScript focus."""
        framework_context = ""
        if self.config.framework != 'react':
            framework_context = f"\nNote: This code uses {self.config.framework.upper()}. "
            framework_context += f"Consider {self.config.framework}-specific security patterns and best practices."

        hooks_context = ""
        if self.config.check_hooks:
            hooks_context = "\nPay special attention to React Hooks usage:\n"
            hooks_context += "- Missing dependencies in useEffect/useCallback/useMemo\n"
            hooks_context += "- Memory leaks from uncleared subscriptions\n"
            hooks_context += "- Infinite render loops\n"
            hooks_context += "- Stale closures causing security bypasses\n"

        return f"""You are an expert security analyst specializing in React, TypeScript, and modern JavaScript security.
Your task is to perform comprehensive static security analysis on React/TypeScript code to identify potential vulnerabilities and security issues.
{framework_context}{hooks_context}
Focus on identifying:

1. **Cross-Site Scripting (XSS) Vulnerabilities**
   - dangerouslySetInnerHTML with unsanitized input
   - Direct DOM manipulation (innerHTML, outerHTML, document.write)
   - Unsafe ref usage with user input
   - URL-based XSS in href/src attributes
   - Dynamic script injection
   - eval() or Function() constructor usage

2. **Authentication & Authorization Issues**
   - Client-side only authentication checks
   - Token storage in localStorage/sessionStorage
   - Hardcoded API keys or secrets in code
   - Missing CSRF protection
   - Insecure session management
   - JWT vulnerabilities

3. **State Management Security**
   - Sensitive data exposed in Redux/Context state
   - Race conditions from improper state updates
   - Unvalidated state transitions
   - PII in client-side state
   - State persistence security issues

4. **API & Data Handling**
   - HTTP URLs (should be HTTPS)
   - Missing input validation
   - Unvalidated redirects (open redirect)
   - GraphQL injection risks
   - CORS misconfigurations
   - Path traversal in dynamic routes

5. **React-Specific Patterns & Hooks**
   - useEffect missing dependencies (stale closures)
   - Memory leaks (timers, subscriptions, listeners)
   - Infinite render loops
   - Conditional hooks or hooks in loops
   - Missing or non-unique key props
   - Unsafe component composition

6. **Data Exposure & Privacy**
   - console.log with sensitive data
   - Error boundaries exposing stack traces
   - Analytics data leakage
   - Redux DevTools enabled in production
   - Source maps in production
   - PII handling violations

7. **TypeScript Security Issues**
   - Type assertion to 'any' bypassing safety
   - Missing type guards
   - Unsafe type coercion
   - Overly permissive generic types

8. **Component Security**
   - User-controlled component rendering
   - Dynamic component loading from untrusted sources
   - Unvalidated props spreading (...props)
   - Unsafe HOC patterns
   - Children validation issues

9. **Build & Configuration**
   - Environment variables with secrets (REACT_APP_, VITE_)
   - Development mode in production
   - Debug features enabled
   - Webpack/Vite misconfigurations

10. **Modern React Patterns (React 18+)**
    - Server Components boundary violations
    - Suspense error information leakage
    - Streaming SSR data leakage
    - Unvalidated server actions

For each vulnerability found, provide a detailed analysis in plain text format with:
- Clear title and description
- Severity level (critical, high, medium, low, or info)
- CWE identifier if applicable
- Specific line number(s) where the issue occurs
- Code snippet showing the vulnerable code
- Exploitation scenario explaining how it could be exploited in a React application
- Detailed remediation advice with React/TypeScript code examples
- Links to React security documentation when relevant

Be thorough but accurate. Only report actual security issues, not style or minor code quality issues unless they have security implications.
Consider the React component lifecycle, hooks behavior, and TypeScript type system in your analysis.
Provide your analysis in a clear, readable text format."""

    def _build_analysis_prompt(self, code: str, file_path: str, chunk_info: Optional[str] = None) -> str:
        """
        Build analysis prompt for LLM.

        Args:
            code: React/TypeScript code to analyze
            file_path: File path
            chunk_info: Optional chunk information

        Returns:
            Formatted prompt
        """
        chunk_text = f" ({chunk_info})" if chunk_info else ""

        framework_hint = f"This is a {self.config.framework.upper()} project. " if self.config.framework != 'react' else ""

        react_version_hint = f"Target React version: {self.config.react_version}. " if self.config.react_version else ""

        prompt = f"""Analyze the following React/TypeScript code for security vulnerabilities{chunk_text}:

File: {file_path}
{framework_hint}{react_version_hint}

```typescript
{code}
```

Perform a comprehensive security analysis and provide your findings in clear, readable text format.

For each vulnerability you find, please include:
- Title: Brief title of the vulnerability
- Severity: critical, high, medium, low, or info
- CWE ID: CWE identifier if applicable
- Line Number: Specific line number(s) where the issue occurs
- Description: Detailed description of the security issue in React/TypeScript context
- Vulnerable Code: Code snippet showing the vulnerable pattern
- Exploitation: How this could be exploited in a React application
- Remediation: Detailed fix with React/TypeScript code example
- Confidence: high, medium, or low

Guidelines:
- Be thorough and examine all code paths and component interactions
- Focus on security-relevant issues only
- Consider React component lifecycle and hooks behavior
- Understand TypeScript type safety implications
- Provide accurate line numbers
- Include CWE identifiers where applicable
- Give practical React-specific remediation advice
- Only include findings you are confident about
- If no vulnerabilities found, state that clearly

Please provide your analysis now."""

        return prompt

    def _process_text_response(self, response: str, file_path: str) -> Dict[str, Any]:
        """
        Process plain text LLM response and extract summary information.

        Args:
            response: LLM response text
            file_path: File path

        Returns:
            Processed analysis result with text stored and parsed summary
        """
        logger.info(f"Received text response ({len(response)} characters)")

        # Log first 500 characters of response for debugging
        logger.debug("Response preview (first 500 chars):")
        logger.debug(response[:500])

        # Save full response to debug file if verbose logging
        if logger.isEnabledFor(logging.DEBUG):
            try:
                from pathlib import Path
                debug_file = Path(file_path).parent / f"{Path(file_path).stem}_llm_response.txt"
                with open(debug_file, 'w', encoding='utf-8') as f:
                    f.write(response)
                logger.debug(f"Saved full LLM response to: {debug_file}")
            except Exception as e:
                logger.warning(f"Could not save debug file: {e}")

        # Parse the response to extract findings information
        findings_summary = self._parse_text_for_summary(response)

        # Store the raw text analysis with parsed summary
        result = {
            'findings': [],
            'analysis_text': response,
            'summary': {
                'total_findings': findings_summary['total_findings'],
                'severity_distribution': findings_summary['severity_distribution'],
                'file_analyzed': file_path,
                'has_vulnerabilities': findings_summary['has_vulnerabilities']
            },
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'tool': 'AeyeGuard_react',
                'version': '1.0.0',
                'model': self.config.model,
                'framework': self.config.framework,
                'react_version': self.config.react_version,
                'output_type': 'text'
            }
        }

        logger.info(f"Parsed {findings_summary['total_findings']} findings from text response")
        if findings_summary['total_findings'] > 0:
            logger.info(f"Severity distribution: {findings_summary['severity_distribution']}")

        return result

    def _parse_text_for_summary(self, response: str) -> Dict[str, Any]:
        """
        Parse text response to extract summary information.

        Args:
            response: LLM response text

        Returns:
            Dictionary with findings count and severity distribution
        """
        response_lower = response.lower()

        # Initialize counters
        severity_counts = {level: 0 for level in self.SEVERITY_LEVELS}
        total_findings = 0
        has_vulnerabilities = False

        # Check for "no vulnerabilities" or similar phrases
        no_vuln_patterns = [
            r'no\s+(?:security\s+)?(?:vulnerabilities|issues|problems|findings)\s+(?:found|detected|identified)',
            r'(?:does not|doesn\'t)\s+(?:contain|have)\s+(?:any\s+)?(?:security\s+)?(?:vulnerabilities|issues)',
            r'(?:appears?|seems?)\s+(?:to be\s+)?(?:secure|safe)',
            r'clean\s+(?:from\s+)?(?:security\s+)?(?:vulnerabilities|issues)',
            r'no\s+(?:obvious|apparent|significant)\s+(?:security\s+)?(?:vulnerabilities|issues)'
        ]

        # Check if no vulnerabilities were found
        is_clean = any(re.search(pattern, response_lower) for pattern in no_vuln_patterns)

        if is_clean:
            logger.debug("Detected 'no vulnerabilities found' in response")
            return {
                'total_findings': 0,
                'severity_distribution': severity_counts,
                'has_vulnerabilities': False
            }

        # Pattern to identify severity mentions (multiple formats)
        severity_patterns = {
            'critical': [
                r'\bseverity\s*:\s*critical\b',
                r'\bcritical\s+severity\b',
                r'\*\*severity\*\*\s*:\s*critical\b',
                r'severity:\s*\*\*critical\*\*',
            ],
            'high': [
                r'\bseverity\s*:\s*high\b',
                r'\bhigh\s+severity\b',
                r'\*\*severity\*\*\s*:\s*high\b',
                r'severity:\s*\*\*high\*\*',
            ],
            'medium': [
                r'\bseverity\s*:\s*medium\b',
                r'\bmedium\s+severity\b',
                r'\*\*severity\*\*\s*:\s*medium\b',
                r'severity:\s*\*\*medium\*\*',
            ],
            'low': [
                r'\bseverity\s*:\s*low\b',
                r'\blow\s+severity\b',
                r'\*\*severity\*\*\s*:\s*low\b',
                r'severity:\s*\*\*low\*\*',
            ],
            'info': [
                r'\bseverity\s*:\s*info(?:rmational)?\b',
                r'\binfo(?:rmational)?\s+severity\b',
                r'\*\*severity\*\*\s*:\s*info\b',
                r'severity:\s*\*\*info\*\*',
            ],
        }

        # Count severity mentions
        for severity, patterns in severity_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, response_lower)
                if matches:
                    logger.debug(f"Found {len(matches)} {severity} severity mentions with pattern: {pattern}")
                severity_counts[severity] += len(matches)

        # Pattern: Look for numbered findings
        numbered_findings = re.findall(r'(?:^|\n)\s*(?:finding\s+)?(\d+)[\.:)\]]\s+', response_lower, re.MULTILINE)
        if numbered_findings:
            max_finding_number = max(int(n) for n in numbered_findings)
            logger.debug(f"Found {max_finding_number} numbered findings")
            total_findings = max(total_findings, max_finding_number)

        # Pattern: Look for title patterns indicating findings
        title_patterns = [
            r'(?:^|\n)\s*(?:title|vulnerability|issue|finding)\s*:\s*[^\n]+',
            r'(?:^|\n)\s*##\s+[^\n]+(?:vulnerability|xss|injection|exposure|security)',
        ]
        for pattern in title_patterns:
            matches = re.findall(pattern, response_lower, re.MULTILINE)
            if matches:
                logger.debug(f"Found {len(matches)} title patterns")
                total_findings = max(total_findings, len(matches))

        # Pattern: Look for React-specific vulnerability keywords
        react_vuln_keywords = [
            r'\bdangerouslysetinnerhtml\b.*(?:vulnerability|xss|unsafe)',
            r'\beval\b.*(?:vulnerability|injection|unsafe)',
            r'\blocalstorage\b.*(?:token|password|credential|unsafe)',
            r'\bsessionstorage\b.*(?:token|password|credential)',
            r'\bapi[_\s-]?key\b.*(?:hardcoded|exposed)',
            r'\buseeffect\b.*(?:missing|dependency|stale)',
            r'\binnerhtml\b.*(?:xss|unsafe|vulnerability)',
            r'\bopen\s+redirect\b',
            r'\bclient[_\s-]side\s+auth(?:entication)?\b',
            r'\btype\s+assertion\b.*\bany\b',
        ]

        keyword_count = 0
        for pattern in react_vuln_keywords:
            matches = list(re.finditer(pattern, response_lower))
            if matches:
                keyword_count += len(matches)
                logger.debug(f"Found {len(matches)} React vulnerability keywords: {pattern}")

        if keyword_count > 0:
            logger.debug(f"Estimated {keyword_count} vulnerabilities from React keywords")
            total_findings = max(total_findings, keyword_count)

        # Calculate total from severity counts
        severity_total = sum(severity_counts.values())
        total_findings = max(total_findings, severity_total)

        # If we found any severity mentions or patterns, we have vulnerabilities
        has_vulnerabilities = total_findings > 0

        # If severity mentions but no specific count, estimate
        if has_vulnerabilities and total_findings == 0:
            total_findings = 1  # At least one finding mentioned

        # If we have findings but no severity distribution, try to infer from keywords
        if total_findings > 0 and severity_total == 0:
            # Critical keywords
            if re.search(r'\b(?:dangerouslysetinnerhtml|eval|rce|hardcoded.*(?:key|password|secret))\b', response_lower):
                severity_counts['critical'] = total_findings
            # High keywords
            elif re.search(r'\b(?:xss|injection|localstorage.*token|open\s+redirect|client.*auth)\b', response_lower):
                severity_counts['high'] = total_findings
            else:
                severity_counts['medium'] = total_findings

        logger.info(f"Parsed summary - Total: {total_findings}, Severity dist: {severity_counts}, Has vulns: {has_vulnerabilities}")

        return {
            'total_findings': total_findings,
            'severity_distribution': severity_counts,
            'has_vulnerabilities': has_vulnerabilities
        }

    def _create_empty_result(self, file_path: str, error: Optional[str] = None) -> Dict[str, Any]:
        """
        Create empty result (for errors).

        Args:
            file_path: File path
            error: Error message

        Returns:
            Empty result dictionary
        """
        result = {
            'findings': [],
            'summary': {
                'total_findings': 0,
                'severity_distribution': {level: 0 for level in self.SEVERITY_LEVELS},
                'file_analyzed': file_path
            },
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'tool': 'AeyeGuard_react',
                'version': '1.0.0',
                'model': self.config.model,
                'framework': self.config.framework
            }
        }

        if error:
            result['metadata']['error'] = error

        return result
