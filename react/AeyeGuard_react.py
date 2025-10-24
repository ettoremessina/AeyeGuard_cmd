#!/usr/bin/env python3
"""
AeyeGuard_react.py - Security Static Analysis Tool for React TypeScript Files

A Python-based security static analysis tool that leverages local LLM capabilities
to perform comprehensive security vulnerability detection in React/TypeScript source code files.
"""

import sys
import os
import logging
import argparse
from pathlib import Path
from typing import Optional
from datetime import datetime

# Add modules directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Import modules
from modules.config import Config
from modules.llm_connector import LLMConnector
from modules.security_analyzer import SecurityAnalyzer
from modules.output_formatter import OutputFormatter, OutputFormat
from modules.react_parser import ReactParser, validate_react_file


def setup_logging(verbose: bool = False) -> None:
    """Configure logging based on verbosity level."""
    log_level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


def read_react_file(file_path: Path) -> str:
    """
    Read React/TypeScript file with proper encoding handling.

    Args:
        file_path: Path to the React file

    Returns:
        Content of the file as string

    Raises:
        Exception: If file cannot be read
    """
    encodings = ['utf-8', 'utf-16', 'latin-1']

    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                content = f.read()
            logging.info(f"Successfully read file with {encoding} encoding")
            return content
        except UnicodeDecodeError:
            continue
        except Exception as e:
            logging.error(f"Error reading file with {encoding}: {e}")
            continue

    raise Exception(f"Could not read file with any supported encoding: {encodings}")


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Security Static Analysis Tool for React TypeScript Files using Local LLM',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s component.tsx
  %(prog)s component.tsx --output json --output-file report.json
  %(prog)s component.tsx --model qwen/qwen3-coder-30b --verbose
  %(prog)s component.tsx --framework next --react-version 18 --check-hooks
        """
    )

    # Positional arguments
    parser.add_argument(
        'input_file',
        help='Path to React TypeScript/JSX file to analyze'
    )

    # LLM configuration
    parser.add_argument(
        '--model',
        default='qwen/qwen3-coder-30b',
        help='LLM model name (default: qwen/qwen3-coder-30b)'
    )

    parser.add_argument(
        '--lm-studio-url',
        default='http://localhost:1234',
        help='LM Studio endpoint URL (default: http://localhost:1234)'
    )

    parser.add_argument(
        '--temperature',
        type=float,
        default=0.0,
        help='LLM temperature (default: 0.0)'
    )

    parser.add_argument(
        '--max-tokens',
        type=int,
        default=4096,
        help='Maximum tokens for LLM response (default: 4096)'
    )

    # Output configuration
    parser.add_argument(
        '--output',
        choices=['console', 'json', 'markdown', 'sarif'],
        default='console',
        help='Output format (default: console)'
    )

    parser.add_argument(
        '--output-file',
        help='Save report to file'
    )

    parser.add_argument(
        '--severity',
        choices=['critical', 'high', 'medium', 'low', 'info'],
        default='info',
        help='Minimum severity level to report (default: info)'
    )

    # React-specific options
    parser.add_argument(
        '--react-version',
        type=int,
        default=18,
        help='Target React version (default: 18)'
    )

    parser.add_argument(
        '--check-hooks',
        action='store_true',
        default=True,
        help='Enable React Hooks security analysis (default: enabled)'
    )

    parser.add_argument(
        '--check-performance',
        action='store_true',
        help='Include performance-related security issues'
    )

    parser.add_argument(
        '--framework',
        choices=['react', 'next', 'remix', 'gatsby'],
        default='react',
        help='Framework variant (default: react)'
    )

    parser.add_argument(
        '--include-dependencies',
        action='store_true',
        help='Analyze imported dependencies'
    )

    # General options
    parser.add_argument(
        '--config',
        help='Configuration file path (YAML or JSON)'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )

    return parser.parse_args()


def main() -> int:
    """Main entry point for the React security scanner."""
    try:
        # Parse arguments
        args = parse_arguments()

        # Setup logging
        setup_logging(args.verbose)
        logger = logging.getLogger(__name__)

        logger.info("=" * 60)
        logger.info("Security Static Analysis Tool for React/TypeScript")
        logger.info("=" * 60)

        # Validate React file
        logger.info(f"Validating input file: {args.input_file}")
        is_valid, reason = validate_react_file(args.input_file)
        if not is_valid:
            logger.error(f"Invalid React file: {reason}")
            return 1

        file_path = Path(args.input_file)

        # Load configuration
        logger.info("Loading configuration...")
        config = Config.load(
            config_file=args.config,
            cli_args=vars(args)
        )

        # Read React file
        logger.info(f"Reading React file: {file_path}")
        react_content = read_react_file(file_path)

        lines_count = len(react_content.splitlines())
        logger.info(f"File size: {len(react_content)} bytes, {lines_count} lines")

        if lines_count > 10000:
            logger.warning(f"File has {lines_count} lines, which exceeds recommended limit of 10,000 lines")
            logger.warning("Analysis may take longer or require chunking")

        # Parse React file for metadata
        parser = ReactParser()
        file_info = parser.analyze_file_info(react_content, str(file_path))
        logger.info(f"Detected: {file_info['component_count']} component(s), "
                   f"{len(file_info['hooks_used'])} hook type(s), "
                   f"{'TypeScript' if file_info['is_typescript'] else 'JavaScript'}")

        # Initialize LLM connector
        logger.info(f"Connecting to LM Studio at {config.lm_studio_url}...")
        llm_connector = LLMConnector(config)

        if not llm_connector.test_connection():
            logger.error("Failed to connect to LM Studio")
            logger.error("Please ensure LM Studio is running and accessible")
            return 1

        logger.info(f"Using model: {config.model}")
        logger.info(f"Framework: {config.framework.upper()}, React version: {config.react_version}")

        # Initialize security analyzer
        logger.info("Initializing React security analyzer...")
        analyzer = SecurityAnalyzer(llm_connector, config)

        # Perform analysis
        logger.info("Performing security analysis...")
        logger.info("This may take several minutes depending on file size and model...")

        start_time = datetime.now()
        analysis_result = analyzer.analyze(react_content, str(file_path))
        end_time = datetime.now()

        analysis_duration = (end_time - start_time).total_seconds()
        logger.info(f"Analysis completed in {analysis_duration:.2f} seconds")

        # Add metadata
        analysis_result['metadata']['analysis_duration_seconds'] = analysis_duration
        analysis_result['metadata']['file_path'] = str(file_path)
        analysis_result['metadata']['file_size_bytes'] = len(react_content)
        analysis_result['metadata']['lines_of_code'] = lines_count
        analysis_result['metadata']['file_info'] = file_info

        # Filter by severity
        if args.severity != 'info':
            severity_order = ['info', 'low', 'medium', 'high', 'critical']
            min_index = severity_order.index(args.severity)

            filtered_findings = [
                f for f in analysis_result['findings']
                if severity_order.index(f['severity'].lower()) >= min_index
            ]

            original_count = len(analysis_result['findings'])
            analysis_result['findings'] = filtered_findings

            if original_count != len(filtered_findings):
                logger.info(f"Filtered {original_count - len(filtered_findings)} findings below '{args.severity}' severity")

        # Format output
        logger.info(f"Formatting output as {args.output}...")
        formatter = OutputFormatter(analysis_result, config)

        output_format = OutputFormat(args.output)
        formatted_output = formatter.format(output_format)

        # Save or display output
        if args.output_file:
            logger.info(f"Saving report to {args.output_file}")
            output_path = Path(args.output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(formatted_output)

            logger.info(f"Report saved successfully to {args.output_file}")
        else:
            # Display to console
            print("\n" + "=" * 60)
            print("ANALYSIS REPORT")
            print("=" * 60 + "\n")
            print(formatted_output)

        # Print summary
        total_findings = len(analysis_result['findings'])
        severity_counts = analysis_result['summary']['severity_distribution']

        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"Total findings: {total_findings}")
        print(f"Critical: {severity_counts.get('critical', 0)}")
        print(f"High: {severity_counts.get('high', 0)}")
        print(f"Medium: {severity_counts.get('medium', 0)}")
        print(f"Low: {severity_counts.get('low', 0)}")
        print(f"Info: {severity_counts.get('info', 0)}")
        print(f"Analysis duration: {analysis_duration:.2f} seconds")
        print(f"Framework: {config.framework.upper()}, React {config.react_version}")
        print("=" * 60)

        # Return exit code based on findings
        if severity_counts.get('critical', 0) > 0:
            logger.warning("Critical vulnerabilities found!")
            return 2
        elif severity_counts.get('high', 0) > 0:
            logger.warning("High severity vulnerabilities found!")
            return 1

        logger.info("Analysis completed successfully")
        return 0

    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user")
        return 130
    except FileNotFoundError as e:
        logging.error(f"File error: {e}")
        return 1
    except ValueError as e:
        logging.error(f"Validation error: {e}")
        return 1
    except Exception as e:
        logging.error(f"Unexpected error: {e}", exc_info=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
