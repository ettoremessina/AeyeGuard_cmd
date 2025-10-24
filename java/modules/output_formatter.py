"""
Output Formatter module for generating reports in various formats.

Supports: Console, JSON, Markdown, and SARIF formats.
"""

import json
import logging
from enum import Enum
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)


class OutputFormat(Enum):
    """Supported output formats."""
    CONSOLE = "console"
    JSON = "json"
    MARKDOWN = "markdown"
    SARIF = "sarif"


class OutputFormatter:
    """Formats analysis results into various output formats."""

    def __init__(self, analysis_result: Dict[str, Any], config):
        """
        Initialize output formatter.

        Args:
            analysis_result: Analysis result dictionary
            config: Configuration object
        """
        self.result = analysis_result
        self.config = config

    def format(self, output_format: OutputFormat) -> str:
        """
        Format results according to specified format.

        Args:
            output_format: Desired output format

        Returns:
            Formatted output string
        """
        if output_format == OutputFormat.CONSOLE:
            return self._format_console()
        elif output_format == OutputFormat.JSON:
            return self._format_json()
        elif output_format == OutputFormat.MARKDOWN:
            return self._format_markdown()
        elif output_format == OutputFormat.SARIF:
            return self._format_sarif()
        else:
            raise ValueError(f"Unsupported output format: {output_format}")

    def _format_console(self) -> str:
        """Format for console output (human-readable)."""
        output_lines = []

        # Check if we have text-based analysis
        if 'analysis_text' in self.result:
            metadata = self.result.get('metadata', {})
            summary = self.result.get('summary', {})

            output_lines.append("=" * 70)
            output_lines.append("SECURITY ANALYSIS REPORT")
            output_lines.append("=" * 70)
            output_lines.append(f"\nFile: {summary.get('file_analyzed', 'N/A')}")
            output_lines.append(f"Model: {metadata.get('model', 'N/A')}")
            output_lines.append(f"Timestamp: {metadata.get('timestamp', 'N/A')}")

            if summary.get('chunks_analyzed'):
                output_lines.append(f"Chunks Analyzed: {summary['chunks_analyzed']}")

            # Display summary information
            total_findings = summary.get('total_findings', 0)
            output_lines.append(f"\nTotal Findings: {total_findings}")

            if total_findings > 0:
                severity_dist = summary.get('severity_distribution', {})
                output_lines.append("\nSeverity Distribution:")
                for severity in ['critical', 'high', 'medium', 'low', 'info']:
                    count = severity_dist.get(severity, 0)
                    if count > 0:
                        severity_symbols = {
                            'critical': '🔴',
                            'high': '🟠',
                            'medium': '🟡',
                            'low': '🔵',
                            'info': 'ℹ️'
                        }
                        symbol = severity_symbols.get(severity, '•')
                        output_lines.append(f"  {symbol} {severity.capitalize()}: {count}")

            output_lines.append("\n" + "=" * 70)
            output_lines.append("\nDETAILED ANALYSIS:\n")
            output_lines.append(self.result['analysis_text'])
            output_lines.append("\n" + "=" * 70)

            return '\n'.join(output_lines)

        # Fallback to old format if findings are present
        findings = self.result.get('findings', [])
        summary = self.result.get('summary', {})
        metadata = self.result.get('metadata', {})

        if not findings:
            output_lines.append("No security issues found.")
            return '\n'.join(output_lines)

        # Group by severity
        by_severity = {}
        for finding in findings:
            severity = finding['severity']
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)

        # Display findings by severity
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        severity_symbols = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🔵',
            'info': 'ℹ️'
        }

        for severity in severity_order:
            if severity not in by_severity:
                continue

            severity_findings = by_severity[severity]
            symbol = severity_symbols.get(severity, '•')

            output_lines.append(f"\n{symbol} {severity.upper()} SEVERITY ({len(severity_findings)} findings)")
            output_lines.append("=" * 70)

            for idx, finding in enumerate(severity_findings, 1):
                output_lines.append(f"\n{idx}. {finding['title']}")

                if finding.get('line_number'):
                    output_lines.append(f"   Line: {finding['line_number']}")

                if finding.get('cwe_id') and finding['cwe_id'] != 'N/A':
                    output_lines.append(f"   CWE: {finding['cwe_id']}")

                output_lines.append(f"\n   Description:")
                output_lines.append(f"   {finding['description']}")

                if finding.get('code_snippet'):
                    output_lines.append(f"\n   Vulnerable Code:")
                    snippet_lines = finding['code_snippet'].split('\n')
                    for line in snippet_lines[:5]:  # Limit to 5 lines
                        output_lines.append(f"   > {line}")
                    if len(snippet_lines) > 5:
                        output_lines.append(f"   > ... ({len(snippet_lines) - 5} more lines)")

                if finding.get('exploitation_scenario'):
                    output_lines.append(f"\n   Exploitation:")
                    output_lines.append(f"   {finding['exploitation_scenario']}")

                if finding.get('remediation'):
                    output_lines.append(f"\n   Remediation:")
                    remediation_lines = finding['remediation'].split('\n')
                    for line in remediation_lines[:3]:  # Limit to 3 lines
                        output_lines.append(f"   {line}")
                    if len(remediation_lines) > 3:
                        output_lines.append(f"   ... (see full report for complete remediation)")

                output_lines.append("\n" + "-" * 70)

        return '\n'.join(output_lines)

    def _format_json(self) -> str:
        """Format as JSON."""
        # For text-based analysis, create a simpler JSON structure
        if 'analysis_text' in self.result:
            json_output = {
                'analysis': self.result['analysis_text'],
                'summary': self.result.get('summary', {}),
                'metadata': self.result.get('metadata', {})
            }
            return json.dumps(json_output, indent=2, ensure_ascii=False)

        return json.dumps(self.result, indent=2, ensure_ascii=False)

    def _format_markdown(self) -> str:
        """Format as Markdown."""
        output_lines = []

        summary = self.result.get('summary', {})
        metadata = self.result.get('metadata', {})

        # Header
        output_lines.append("# Security Analysis Report")
        output_lines.append("")
        output_lines.append(f"**File:** {summary.get('file_analyzed', 'N/A')}")
        output_lines.append(f"**Timestamp:** {metadata.get('timestamp', 'N/A')}")
        output_lines.append(f"**Tool:** {metadata.get('tool', 'N/A')} v{metadata.get('version', 'N/A')}")
        output_lines.append(f"**Model:** {metadata.get('model', 'N/A')}")

        if summary.get('chunks_analyzed'):
            output_lines.append(f"**Chunks Analyzed:** {summary['chunks_analyzed']}")

        output_lines.append("")

        # Check if we have text-based analysis
        if 'analysis_text' in self.result:
            # Add summary section
            output_lines.append("## Summary")
            output_lines.append("")

            total_findings = summary.get('total_findings', 0)
            output_lines.append(f"- **Total Findings:** {total_findings}")

            if total_findings > 0:
                severity_dist = summary.get('severity_distribution', {})
                output_lines.append("")
                output_lines.append("**Severity Distribution:**")
                output_lines.append("")
                for severity in ['critical', 'high', 'medium', 'low', 'info']:
                    count = severity_dist.get(severity, 0)
                    if count > 0:
                        severity_badges = {
                            'critical': '🔴 Critical',
                            'high': '🟠 High',
                            'medium': '🟡 Medium',
                            'low': '🔵 Low',
                            'info': 'ℹ️ Info'
                        }
                        badge = severity_badges.get(severity, severity.capitalize())
                        output_lines.append(f"- {badge}: {count}")

            output_lines.append("")
            output_lines.append("## Detailed Analysis")
            output_lines.append("")
            output_lines.append(self.result['analysis_text'])
            output_lines.append("")
            return '\n'.join(output_lines)

        # Fallback to old format if findings are present
        findings = self.result.get('findings', [])

        # Summary
        output_lines.append("## Summary")
        output_lines.append("")
        output_lines.append(f"- **Total Findings:** {summary.get('total_findings', 0)}")

        severity_dist = summary.get('severity_distribution', {})
        output_lines.append(f"- **Critical:** {severity_dist.get('critical', 0)}")
        output_lines.append(f"- **High:** {severity_dist.get('high', 0)}")
        output_lines.append(f"- **Medium:** {severity_dist.get('medium', 0)}")
        output_lines.append(f"- **Low:** {severity_dist.get('low', 0)}")
        output_lines.append(f"- **Info:** {severity_dist.get('info', 0)}")
        output_lines.append("")

        if not findings:
            output_lines.append("No security issues found.")
            return '\n'.join(output_lines)

        # Findings
        output_lines.append("## Findings")
        output_lines.append("")

        for idx, finding in enumerate(findings, 1):
            severity = finding['severity'].upper()
            severity_badge = {
                'CRITICAL': '🔴 CRITICAL',
                'HIGH': '🟠 HIGH',
                'MEDIUM': '🟡 MEDIUM',
                'LOW': '🔵 LOW',
                'INFO': 'ℹ️ INFO'
            }.get(severity, severity)

            output_lines.append(f"### {idx}. {finding['title']}")
            output_lines.append("")
            output_lines.append(f"**Severity:** {severity_badge}")

            if finding.get('cwe_id') and finding['cwe_id'] != 'N/A':
                output_lines.append(f"**CWE:** {finding['cwe_id']}")

            if finding.get('line_number'):
                output_lines.append(f"**Line:** {finding['line_number']}")

            if finding.get('confidence'):
                output_lines.append(f"**Confidence:** {finding['confidence'].title()}")

            output_lines.append("")

            # Description
            output_lines.append("**Description:**")
            output_lines.append("")
            output_lines.append(finding['description'])
            output_lines.append("")

            # Code snippet
            if finding.get('code_snippet'):
                output_lines.append("**Vulnerable Code:**")
                output_lines.append("")
                output_lines.append("```java")
                output_lines.append(finding['code_snippet'])
                output_lines.append("```")
                output_lines.append("")

            # Exploitation
            if finding.get('exploitation_scenario'):
                output_lines.append("**Exploitation Scenario:**")
                output_lines.append("")
                output_lines.append(finding['exploitation_scenario'])
                output_lines.append("")

            # Remediation
            if finding.get('remediation'):
                output_lines.append("**Remediation:**")
                output_lines.append("")
                output_lines.append(finding['remediation'])
                output_lines.append("")

            output_lines.append("---")
            output_lines.append("")

        return '\n'.join(output_lines)

    def _format_sarif(self) -> str:
        """
        Format as SARIF (Static Analysis Results Interchange Format).

        SARIF is a standard format for static analysis tools.
        See: https://sarifweb.azurewebsites.net/
        """
        metadata = self.result.get('metadata', {})
        summary = self.result.get('summary', {})

        # For text-based analysis, create a single informational result
        if 'analysis_text' in self.result:
            sarif = {
                "version": "2.1.0",
                "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "AeyeGuard_java",
                                "version": metadata.get('version', '1.0.0'),
                                "informationUri": "https://github.com/yourusername/AeyeGuard_java",
                                "semanticVersion": metadata.get('version', '1.0.0')
                            }
                        },
                        "results": [
                            {
                                "ruleId": "AEYEGUARD-TEXT-ANALYSIS",
                                "level": "note",
                                "message": {
                                    "text": "Security analysis completed. See full analysis in properties."
                                },
                                "properties": {
                                    "fullAnalysis": self.result['analysis_text'],
                                    "fileAnalyzed": summary.get('file_analyzed', 'unknown')
                                }
                            }
                        ],
                        "invocations": [
                            {
                                "executionSuccessful": True,
                                "endTimeUtc": metadata.get('timestamp', datetime.now().isoformat())
                            }
                        ]
                    }
                ]
            }
            return json.dumps(sarif, indent=2, ensure_ascii=False)

        # Fallback to old format for structured findings
        findings = self.result.get('findings', [])

        # Map severity to SARIF levels
        severity_map = {
            'critical': 'error',
            'high': 'error',
            'medium': 'warning',
            'low': 'warning',
            'info': 'note'
        }

        # Build SARIF results
        results = []
        for finding in findings:
            result = {
                "ruleId": finding.get('cwe_id', 'AEYEGUARD-001'),
                "level": severity_map.get(finding['severity'], 'warning'),
                "message": {
                    "text": finding['description']
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": summary.get('file_analyzed', 'unknown')
                            },
                            "region": {
                                "startLine": finding.get('line_number', 1)
                            }
                        }
                    }
                ]
            }

            # Add properties
            properties = {
                "title": finding['title'],
                "severity": finding['severity'],
                "confidence": finding.get('confidence', 'medium')
            }

            if finding.get('exploitation_scenario'):
                properties['exploitation'] = finding['exploitation_scenario']

            if finding.get('remediation'):
                properties['remediation'] = finding['remediation']

            if finding.get('code_snippet'):
                properties['codeSnippet'] = finding['code_snippet']

            result["properties"] = properties
            results.append(result)

        # Build SARIF document
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AeyeGuard_java",
                            "version": metadata.get('version', '1.0.0'),
                            "informationUri": "https://github.com/yourusername/AeyeGuard_java",
                            "semanticVersion": metadata.get('version', '1.0.0')
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": metadata.get('timestamp', datetime.now().isoformat())
                        }
                    ]
                }
            ]
        }

        return json.dumps(sarif, indent=2, ensure_ascii=False)
