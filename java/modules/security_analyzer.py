"""
Security Analyzer module for Java code analysis.

Orchestrates security analysis using LLM with specialized prompts.
"""

import logging
import json
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class SecurityAnalyzer:
    """Performs security analysis on Java code using LLM."""

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
        Perform comprehensive security analysis on Java code.

        Args:
            code: Java source code to analyze
            file_path: Path to the file being analyzed

        Returns:
            Analysis results dictionary
        """
        logger.info("Starting security analysis...")

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
            code: Java source code
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
            code: Java source code
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
                'tool': 'AeyeGuard_java',
                'version': '1.0.0',
                'model': self.config.model,
                'output_type': 'text',
                'chunked': True
            }
        }

        return result

    def _build_system_prompt(self) -> str:
        """Build system prompt for LLM."""
        return """You are an expert security analyst specializing in Java and JVM security.
Your task is to perform comprehensive static security analysis on Java code to identify potential vulnerabilities and security issues.

Focus on identifying:
1. Input validation vulnerabilities (SQL injection, command injection, path traversal, XXE, LDAP injection)
2. Authentication and authorization issues
3. Cryptography weaknesses (weak algorithms, hardcoded secrets, weak random number generation)
4. Data exposure risks (sensitive data in logs, information disclosure, insecure deserialization)
5. Code quality issues that could lead to security problems (race conditions, null references, resource leaks)
6. Java-specific vulnerabilities:
   - Insecure deserialization (ObjectInputStream)
   - Reflection Abuse (Class.forName, Method.invoke)
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

For each vulnerability found, provide a detailed analysis in plain text format with:
- Clear title and description
- Severity level (critical, high, medium, low, or info)
- CWE identifier if applicable
- Specific line number(s) where the issue occurs
- Code snippet showing the vulnerable code
- Exploitation scenario explaining how it could be exploited
- Detailed remediation advice with code examples

Be thorough but accurate. Only report actual security issues, not style or minor code quality issues unless they have security implications.
Provide your analysis in a clear, readable text format."""

    def _build_analysis_prompt(self, code: str, file_path: str, chunk_info: Optional[str] = None) -> str:
        """
        Build analysis prompt for LLM.

        Args:
            code: Java code to analyze
            file_path: File path
            chunk_info: Optional chunk information

        Returns:
            Formatted prompt
        """
        chunk_text = f" ({chunk_info})" if chunk_info else ""

        prompt = f"""Analyze the following Java code for security vulnerabilities{chunk_text}:

File: {file_path}

```java
{code}
```

Perform a comprehensive security analysis and provide your findings in clear, readable text format.

For each vulnerability you find, please include:
- Title: Brief title of the vulnerability
- Severity: critical, high, medium, low, or info
- CWE ID: CWE identifier if applicable
- Line Number: Specific line number(s) where the issue occurs
- Description: Detailed description of the security issue
- Vulnerable Code: Code snippet showing the vulnerable code
- Exploitation: How this could be exploited
- Remediation: Detailed fix with code example
- Confidence: high, medium, or low

Guidelines:
- Be thorough and examine all code paths
- Focus on security-relevant issues only
- Provide accurate line numbers
- Include CWE identifiers where applicable
- Give practical remediation advice
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
                'tool': 'AeyeGuard_java',
                'version': '1.0.0',
                'model': self.config.model,
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
        import re

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

        # Patterns to identify vulnerability sections and their severities
        # Look for patterns like "Title:", "Severity: high", "1.", "Finding 1:", etc.

        # Pattern 1: Look for explicit severity mentions
        severity_patterns = {
            'critical': [
                r'\bseverity\s*:\s*critical\b',
                r'\bcritical\s+severity\b',
                r'\[critical\]',
                r'🔴',
                r'\bcritical\s+vulnerability\b',
                r'\bcritical\s+issue\b'
            ],
            'high': [
                r'\bseverity\s*:\s*high\b',
                r'\bhigh\s+severity\b',
                r'\[high\]',
                r'🟠',
                r'\bhigh\s+vulnerability\b',
                r'\bhigh\s+risk\b'
            ],
            'medium': [
                r'\bseverity\s*:\s*medium\b',
                r'\bmedium\s+severity\b',
                r'\[medium\]',
                r'🟡',
                r'\bmedium\s+vulnerability\b',
                r'\bmedium\s+risk\b'
            ],
            'low': [
                r'\bseverity\s*:\s*low\b',
                r'\blow\s+severity\b',
                r'\[low\]',
                r'🔵',
                r'\blow\s+vulnerability\b',
                r'\blow\s+risk\b'
            ],
            'info': [
                r'\bseverity\s*:\s*info(?:rmational)?\b',
                r'\binfo(?:rmational)?\s+severity\b',
                r'\[info\]',
                r'ℹ️',
                r'\binformational\b'
            ]
        }

        # Count severity mentions
        for severity, patterns in severity_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, response_lower)
                severity_counts[severity] += len(matches)

        # Pattern 2: Look for numbered findings (1., 2., Finding 1:, etc.)
        numbered_findings = re.findall(r'(?:^|\n)\s*(?:finding\s+)?(\d+)[\.:)\]]\s+', response_lower, re.MULTILINE)
        if numbered_findings:
            max_finding_number = max(int(n) for n in numbered_findings)
            logger.debug(f"Found {max_finding_number} numbered findings")
            total_findings = max(total_findings, max_finding_number)

        # Pattern 3: Look for title patterns
        title_patterns = [
            r'(?:^|\n)\s*(?:title|vulnerability|issue|finding)\s*:\s*[^\n]+',
            r'(?:^|\n)\s*##\s+[^\n]+(?:vulnerability|injection|exposure|weakness)',
            r'(?:^|\n)\s*\*\*(?:title|vulnerability|issue|finding)\s*:\s*\*\*',
        ]
        for pattern in title_patterns:
            matches = re.findall(pattern, response_lower, re.MULTILINE)
            if matches:
                logger.debug(f"Found {len(matches)} title-like patterns with pattern: {pattern}")
                total_findings = max(total_findings, len(matches))

        # Pattern 4: Look for vulnerability keywords as a fallback
        vuln_keywords = [
            r'\b(?:sql|command|ldap|xml|xpath)\s+injection\b',
            r'\bcross[- ]site\s+(?:scripting|xss)\b',
            r'\bpath\s+traversal\b',
            r'\b(?:weak|insecure)\s+(?:encryption|cryptography|algorithm)\b',
            r'\bhardcoded\s+(?:password|secret|key|credential)\b',
            r'\b(?:authentication|authorization)\s+(?:bypass|flaw|weakness)\b',
            r'\binsecure\s+deserialization\b',
            r'\b(?:xxe|xml\s+external\s+entity)\b',
            r'\bremote\s+code\s+execution\b',
            r'\breflection\s+abuse\b',
            r'\bjndi\s+injection\b',
            r'\bspel\s+injection\b',
            r'\bel\s+injection\b',
            r'\bclassloader\s+manipulation\b',
            r'\bsecurity\s+(?:vulnerability|issue|flaw|weakness)\b'
        ]

        keyword_matches = []
        for pattern in vuln_keywords:
            matches = list(re.finditer(pattern, response_lower))
            if matches:
                keyword_matches.extend(matches)
                logger.debug(f"Found {len(matches)} vulnerability keyword matches: {pattern}")

        if keyword_matches:
            # Count unique vulnerability types (based on position to avoid duplicates)
            unique_positions = set((m.start() // 100) for m in keyword_matches)  # Group by ~100 char chunks
            keyword_count = len(unique_positions)
            logger.debug(f"Estimated {keyword_count} unique vulnerabilities from keywords")
            total_findings = max(total_findings, keyword_count)

        # Calculate total from severity counts
        severity_total = sum(severity_counts.values())
        total_findings = max(total_findings, severity_total)

        # If we found any severity mentions or patterns, we have vulnerabilities
        has_vulnerabilities = total_findings > 0

        # If severity mentions but no specific count, estimate
        if has_vulnerabilities and total_findings == 0:
            total_findings = 1  # At least one finding mentioned

        # If we have findings but no severity distribution, try to infer
        if total_findings > 0 and severity_total == 0:
            # Look for vulnerability-related keywords to estimate severity
            if re.search(r'\b(?:sql\s+injection|command\s+injection|rce|remote\s+code\s+execution|authentication\s+bypass|jndi\s+injection|insecure\s+deserialization)\b', response_lower):
                severity_counts['critical'] = total_findings
            elif re.search(r'\b(?:xss|csrf|path\s+traversal|xml\s+injection|ldap\s+injection|reflection\s+abuse|spel\s+injection)\b', response_lower):
                severity_counts['high'] = total_findings
            else:
                severity_counts['medium'] = total_findings

        logger.info(f"Parsed summary - Total: {total_findings}, Severity dist: {severity_counts}, Has vulns: {has_vulnerabilities}")

        # If parsing found nothing but response is substantial, log warning
        if total_findings == 0 and len(response) > 100 and not is_clean:
            logger.warning("Parser found 0 findings but response is substantial. Response might be in unexpected format.")
            logger.warning(f"Response length: {len(response)} characters")
            logger.warning(f"First 200 chars: {response[:200]}")

        return {
            'total_findings': total_findings,
            'severity_distribution': severity_counts,
            'has_vulnerabilities': has_vulnerabilities
        }

    def _validate_finding(self, finding: Dict[str, Any]) -> bool:
        """
        Validate a single finding.

        Args:
            finding: Finding dictionary

        Returns:
            True if valid
        """
        required_fields = ['title', 'description', 'severity']

        # Check required fields
        for field in required_fields:
            if field not in finding or not finding[field]:
                logger.warning(f"Finding missing required field: {field}")
                return False

        # Validate severity
        if finding['severity'].lower() not in self.SEVERITY_LEVELS:
            logger.warning(f"Invalid severity level: {finding['severity']}")
            return False

        return True

    def _normalize_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize finding to standard format.

        Args:
            finding: Raw finding dictionary

        Returns:
            Normalized finding
        """
        return {
            'title': finding['title'].strip(),
            'description': finding['description'].strip(),
            'severity': finding['severity'].lower(),
            'cwe_id': finding.get('cwe_id', 'N/A'),
            'line_number': finding.get('line_number', 0),
            'code_snippet': finding.get('code_snippet', '').strip(),
            'exploitation_scenario': finding.get('exploitation_scenario', '').strip(),
            'remediation': finding.get('remediation', '').strip(),
            'confidence': finding.get('confidence', 'medium').lower()
        }

    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove duplicate findings based on title and line number.

        Args:
            findings: List of findings

        Returns:
            Deduplicated list
        """
        seen = set()
        unique_findings = []

        for finding in findings:
            key = (finding['title'], finding.get('line_number', 0))

            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)

        removed_count = len(findings) - len(unique_findings)
        if removed_count > 0:
            logger.info(f"Removed {removed_count} duplicate findings")

        return unique_findings

    def _build_result(self, findings: List[Dict[str, Any]], file_path: str) -> Dict[str, Any]:
        """
        Build final analysis result.

        Args:
            findings: List of findings
            file_path: File path

        Returns:
            Complete result dictionary
        """
        # Calculate severity distribution
        severity_dist = {level: 0 for level in self.SEVERITY_LEVELS}
        for finding in findings:
            severity = finding['severity']
            severity_dist[severity] = severity_dist.get(severity, 0) + 1

        # Sort findings by severity (critical first)
        findings.sort(
            key=lambda f: (
                -self.SEVERITY_LEVELS.index(f['severity']),
                f.get('line_number', 0)
            )
        )

        return {
            'findings': findings,
            'summary': {
                'total_findings': len(findings),
                'severity_distribution': severity_dist,
                'file_analyzed': file_path
            },
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'tool': 'AeyeGuard_java',
                'version': '1.0.0',
                'model': self.config.model
            }
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
                'tool': 'AeyeGuard_java',
                'version': '1.0.0',
                'model': self.config.model
            }
        }

        if error:
            result['metadata']['error'] = error

        return result
