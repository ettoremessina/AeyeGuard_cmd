#!/usr/bin/env python3
"""
AeyeGuard_cmd.py - Recursive Security Static Analysis Tool

A wrapper tool that recursively scans directories for source code files and
delegates security analysis to language-specific analyzers.
"""

import sys
import os
import logging
import argparse
import subprocess
import signal
from pathlib import Path
from typing import List, Optional, Set
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor, as_completed
from fnmatch import fnmatch


# Default folders to exclude during directory traversal
# These are common build artifacts, IDE folders, and cache directories
DEFAULT_EXCLUDE_FOLDERS = {
    'bin',           # Build output (C#, .NET)
    'obj',           # Build intermediates (C#, .NET)
    '.vs',           # Visual Studio cache
    '.git',          # Git repository data
    '.svn',          # Subversion repository data
    'node_modules',  # Node.js dependencies
    '__pycache__',   # Python cache
    '.pytest_cache', # Pytest cache
    'packages',      # NuGet packages folder
    '.nuget',        # NuGet cache
    'TestResults',   # Test output folder
    'Migrations',    # EF migrations folder
}

# Global flag for graceful shutdown
interrupted = False


def signal_handler(sig, frame):
    """Handle interrupt signals for graceful shutdown."""
    global interrupted
    interrupted = True
    print("\n\nReceived interrupt signal. Shutting down gracefully...")
    print("Saving partial results...")


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


def validate_directory(dir_path: str) -> Path:
    """
    Validate that the input path exists and is a directory.

    Args:
        dir_path: Path to validate

    Returns:
        Path object of the validated directory

    Raises:
        FileNotFoundError: If directory doesn't exist
        ValueError: If path is not a directory
    """
    path = Path(dir_path)

    if not path.exists():
        raise FileNotFoundError(f"Directory not found: {dir_path}")

    if not path.is_dir():
        raise ValueError(f"Path is not a directory: {dir_path}")

    return path


def should_exclude_directory(dir_name: str) -> bool:
    """
    Check if a directory should be excluded from traversal.

    Args:
        dir_name: Name of the directory (not full path)

    Returns:
        True if directory should be excluded, False otherwise
    """
    return dir_name in DEFAULT_EXCLUDE_FOLDERS


def should_exclude(file_path: Path, exclude_patterns: List[str], root_dir: Path) -> bool:
    """
    Check if a file should be excluded based on glob patterns.

    Args:
        file_path: Path to check
        exclude_patterns: List of glob patterns
        root_dir: Root directory for relative path calculation

    Returns:
        True if file should be excluded, False otherwise
    """
    if not exclude_patterns:
        return False

    # Convert to relative path for matching
    try:
        rel_path = file_path.relative_to(root_dir)
        rel_path_str = str(rel_path)

        for pattern in exclude_patterns:
            if fnmatch(rel_path_str, pattern) or fnmatch(str(file_path), pattern):
                return True
    except ValueError:
        # Path is not relative to root_dir
        pass

    return False


def discover_files(
    directory: Path,
    extensions: Set[str],
    exclude_patterns: List[str],
    max_files: Optional[int] = None
) -> List[Path]:
    """
    Recursively discover files with specified extensions.

    Args:
        directory: Root directory to scan
        extensions: Set of file extensions to include (e.g., {'.cs', '.java'})
        exclude_patterns: List of glob patterns to exclude
        max_files: Maximum number of files to discover (None for unlimited)

    Returns:
        List of discovered file paths
    """
    logger = logging.getLogger(__name__)
    discovered_files = []

    logger.info(f"Scanning directory: {directory}")
    logger.info(f"Looking for extensions: {', '.join(extensions)}")
    logger.info(f"Auto-excluding folders: {', '.join(sorted(DEFAULT_EXCLUDE_FOLDERS))}")

    if exclude_patterns:
        logger.info(f"Excluding patterns: {', '.join(exclude_patterns)}")

    try:
        for root, dirs, files in os.walk(directory):
            root_path = Path(root)

            # Filter out excluded directories to avoid traversing them
            # First, exclude default folders (bin, obj, .vs, etc.)
            # Then, exclude directories matching user-provided patterns
            dirs[:] = [
                d for d in dirs
                if not should_exclude_directory(d) and
                   not should_exclude(root_path / d, exclude_patterns, directory)
            ]

            for file in files:
                if interrupted:
                    logger.warning("File discovery interrupted")
                    break

                file_path = root_path / file

                # Check extension
                if file_path.suffix.lower() not in extensions:
                    continue

                # Check exclusion patterns
                if should_exclude(file_path, exclude_patterns, directory):
                    logger.debug(f"Excluding file: {file_path}")
                    continue

                discovered_files.append(file_path)
                logger.debug(f"Discovered: {file_path}")

                # Check max files limit
                if max_files and len(discovered_files) >= max_files:
                    logger.info(f"Reached maximum file limit: {max_files}")
                    return discovered_files

            if interrupted:
                break

    except Exception as e:
        logger.error(f"Error during file discovery: {e}")
        raise

    logger.info(f"Discovered {len(discovered_files)} files")
    return discovered_files


def get_analyzer_for_file(file_path: Path, script_dir: Path) -> Optional[Path]:
    """
    Determine which analyzer script to use based on file extension.

    Args:
        file_path: Path to the file
        script_dir: Base directory containing analyzer scripts

    Returns:
        Path to analyzer script or None if unsupported
    """
    extension = file_path.suffix.lower()

    if extension == '.cs':
        return script_dir / 'cs' / 'AeyeGuard_cs.py'
    elif extension in {'.tsx', '.jsx'}:
        return script_dir / 'react' / 'AeyeGuard_react.py'
    elif extension == '.java':
        return script_dir / 'java' / 'AeyeGuard_java.py'
    else:
        return None


def analyze_file(
    file_path: Path,
    script_dir: Path,
    forwarded_options: List[str],
    continue_on_error: bool = True
):
    """
    Analyze a single file using the language-specific analyzer.

    Args:
        file_path: Path to file to analyze
        script_dir: Base directory containing analyzer scripts
        forwarded_options: Command-line options to forward
        continue_on_error: Whether to continue on error

    Returns:
        Tuple of (file_path, status, duration, output, stderr)
    """
    logger = logging.getLogger(__name__)

    try:
        # Determine which analyzer to use
        analyzer_script = get_analyzer_for_file(file_path, script_dir)

        if not analyzer_script:
            logger.error(f"No analyzer available for file type: {file_path.suffix}")
            return (str(file_path), 'error', 0.0, '', f'Unsupported file type: {file_path.suffix}', -1)

        if not analyzer_script.exists():
            logger.error(f"Analyzer script not found: {analyzer_script}")
            return (str(file_path), 'error', 0.0, '', f'Analyzer not found: {analyzer_script}', -1)

        start_time = datetime.now()

        # Build command - no JSON, use console output
        cmd = [
            sys.executable,  # Use same Python interpreter
            str(analyzer_script),
            str(file_path)
        ] + forwarded_options

        logger.debug(f"Running command: {' '.join(cmd)}")

        # Run analyzer
        process_result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout per file
        )

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Capture text output
        if process_result.returncode in [0, 1, 2]:  # Success or findings detected
            return (str(file_path), 'success', duration, process_result.stdout, process_result.stderr, process_result.returncode)
        else:
            logger.error(f"Analysis failed for {file_path}: exit code {process_result.returncode}")
            return (str(file_path), 'error', duration, process_result.stdout, process_result.stderr, process_result.returncode)

    except subprocess.TimeoutExpired:
        logger.error(f"Timeout analyzing {file_path}")
        return (str(file_path), 'timeout', 600.0, '', 'Analysis timed out after 10 minutes', -1)

    except Exception as e:
        logger.error(f"Error analyzing {file_path}: {e}")
        if not continue_on_error:
            raise
        return (str(file_path), 'error', 0.0, '', str(e), -1)


def analyze_files_parallel(
    files: List[Path],
    script_dir: Path,
    forwarded_options: List[str],
    max_workers: int = 1,
    continue_on_error: bool = True
):
    """
    Analyze multiple files in parallel.

    Args:
        files: List of files to analyze
        script_dir: Base directory containing analyzer scripts
        forwarded_options: Options to forward to analyzer
        max_workers: Number of parallel workers
        continue_on_error: Whether to continue on error

    Returns:
        List of tuples: (file_path, status, duration, output, stderr, returncode)
    """
    logger = logging.getLogger(__name__)
    results = []

    if max_workers == 1:
        # Sequential processing
        for i, file_path in enumerate(files, 1):
            if interrupted:
                logger.warning("Analysis interrupted by user")
                break

            logger.info(f"[{i}/{len(files)}] Analyzing: {file_path}")
            result = analyze_file(file_path, script_dir, forwarded_options, continue_on_error)
            results.append(result)

            # Show brief result
            file_path_str, status, duration, output, stderr, returncode = result
            if status == 'success':
                logger.info(f"  -> Completed in {duration:.1f}s (exit code: {returncode})")
            else:
                logger.warning(f"  -> {status.upper()}")
    else:
        # Parallel processing
        logger.info(f"Running analysis with {max_workers} parallel workers")

        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {
                executor.submit(analyze_file, f, script_dir, forwarded_options, continue_on_error): f
                for f in files
            }

            completed = 0
            for future in as_completed(future_to_file):
                if interrupted:
                    logger.warning("Analysis interrupted by user")
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                file_path = future_to_file[future]
                completed += 1

                try:
                    result = future.result()
                    results.append(result)

                    file_path_str, status, duration, output, stderr, returncode = result
                    logger.info(f"[{completed}/{len(files)}] Completed: {file_path}")
                    if status == 'success':
                        logger.info(f"  -> Completed in {duration:.1f}s")
                    else:
                        logger.warning(f"  -> {status.upper()}")

                except Exception as e:
                    logger.error(f"Exception analyzing {file_path}: {e}")
                    results.append((str(file_path), 'error', 0.0, '', str(e), -1))

    return results


def format_output(results, scan_start_time, scan_end_time, input_dir, config_info, output_format='text'):
    """
    Format analysis results for output.

    Args:
        results: List of tuples (file_path, status, duration, output, stderr, returncode)
        scan_start_time: Start time of scan
        scan_end_time: End time of scan
        input_dir: Input directory path
        config_info: Configuration information
        output_format: Output format (text or file)

    Returns:
        Formatted output string
    """
    scan_duration = (scan_end_time - scan_start_time).total_seconds()

    lines = []
    lines.append("=" * 80)
    lines.append("RECURSIVE SECURITY SCAN RESULTS")
    lines.append("=" * 80)
    lines.append(f"Scan completed: {scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Duration: {scan_duration:.2f} seconds")
    lines.append(f"Directory: {input_dir}")
    lines.append(f"Files scanned: {len(results)}")
    lines.append("")

    # Count successful and failed analyses
    successful = sum(1 for r in results if r[1] == 'success')
    failed = sum(1 for r in results if r[1] != 'success')

    # Count by exit code for successful ones
    critical_findings = sum(1 for r in results if r[1] == 'success' and r[5] == 2)
    high_findings = sum(1 for r in results if r[1] == 'success' and r[5] == 1)
    clean_files = sum(1 for r in results if r[1] == 'success' and r[5] == 0)

    lines.append("ANALYSIS SUMMARY")
    lines.append("-" * 80)
    lines.append(f"  Successful analyses: {successful}")
    lines.append(f"  Failed analyses:     {failed}")
    lines.append("")
    lines.append(f"  Files with CRITICAL findings: {critical_findings}")
    lines.append(f"  Files with HIGH findings:     {high_findings}")
    lines.append(f"  Clean files (no issues):      {clean_files}")
    lines.append("")

    # Show files with critical findings
    if critical_findings > 0:
        lines.append("FILES WITH CRITICAL FINDINGS")
        lines.append("-" * 80)
        for file_path, status, duration, output, stderr, returncode in results:
            if status == 'success' and returncode == 2:
                lines.append(f"  {file_path}")
        lines.append("")

    # Show files with high findings
    if high_findings > 0:
        lines.append("FILES WITH HIGH SEVERITY FINDINGS")
        lines.append("-" * 80)
        for file_path, status, duration, output, stderr, returncode in results:
            if status == 'success' and returncode == 1:
                lines.append(f"  {file_path}")
        lines.append("")

    # Show failed analyses
    if failed > 0:
        lines.append("FAILED ANALYSES")
        lines.append("-" * 80)
        for file_path, status, duration, output, stderr, returncode in results:
            if status != 'success':
                lines.append(f"  {file_path}")
                lines.append(f"    Status: {status}")
                if stderr:
                    lines.append(f"    Error: {stderr[:200]}")
        lines.append("")

    lines.append("=" * 80)
    lines.append("")

    # Now append detailed output from each file
    lines.append("DETAILED ANALYSIS OUTPUT")
    lines.append("=" * 80)
    lines.append("")

    for file_path, status, duration, output, stderr, returncode in results:
        lines.append("=" * 80)
        lines.append(f"FILE: {file_path}")
        lines.append(f"Status: {status} | Duration: {duration:.2f}s | Exit code: {returncode}")
        lines.append("=" * 80)

        if output:
            lines.append(output)
        elif stderr:
            lines.append("STDERR:")
            lines.append(stderr)
        else:
            lines.append("(No output)")

        lines.append("")

    return "\n".join(lines)


def format_output_html(results, scan_start_time, scan_end_time, input_dir, config_info):
    """
    Format analysis results as HTML with nice styling.

    Args:
        results: List of tuples (file_path, status, duration, output, stderr, returncode)
        scan_start_time: Start time of scan
        scan_end_time: End time of scan
        input_dir: Input directory path
        config_info: Configuration information

    Returns:
        Formatted HTML string
    """
    scan_duration = (scan_end_time - scan_start_time).total_seconds()

    # Count successful and failed analyses
    successful = sum(1 for r in results if r[1] == 'success')
    failed = sum(1 for r in results if r[1] != 'success')

    # Count by exit code for successful ones
    critical_findings = sum(1 for r in results if r[1] == 'success' and r[5] == 2)
    high_findings = sum(1 for r in results if r[1] == 'success' and r[5] == 1)
    clean_files = sum(1 for r in results if r[1] == 'success' and r[5] == 0)

    # HTML template with embedded CSS
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Results - {scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}

        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 15px;
            margin-bottom: 30px;
            font-size: 2.5em;
        }}

        h2 {{
            color: #34495e;
            margin-top: 40px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #ecf0f1;
            font-size: 1.8em;
        }}

        h3 {{
            color: #7f8c8d;
            margin-top: 25px;
            margin-bottom: 15px;
            font-size: 1.3em;
        }}

        .meta-info {{
            background: #ecf0f1;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
        }}

        .meta-info p {{
            margin: 8px 0;
            font-size: 1.05em;
        }}

        .meta-info strong {{
            color: #2c3e50;
            min-width: 150px;
            display: inline-block;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}

        .summary-card {{
            background: #fff;
            border: 2px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            transition: transform 0.2s;
        }}

        .summary-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}

        .summary-card.critical {{
            border-color: #e74c3c;
            background: #fee;
        }}

        .summary-card.high {{
            border-color: #e67e22;
            background: #ffeaa7;
        }}

        .summary-card.clean {{
            border-color: #27ae60;
            background: #d5f5e3;
        }}

        .summary-card.failed {{
            border-color: #95a5a6;
            background: #ecf0f1;
        }}

        .summary-card .number {{
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }}

        .summary-card.critical .number {{
            color: #c0392b;
        }}

        .summary-card.high .number {{
            color: #d35400;
        }}

        .summary-card.clean .number {{
            color: #229954;
        }}

        .summary-card.failed .number {{
            color: #7f8c8d;
        }}

        .summary-card .label {{
            font-size: 1.1em;
            color: #555;
            font-weight: 600;
        }}

        .file-list {{
            background: #fafafa;
            border-left: 4px solid #3498db;
            padding: 15px 20px;
            margin: 15px 0;
            border-radius: 4px;
        }}

        .file-list.critical {{
            border-left-color: #e74c3c;
            background: #fee;
        }}

        .file-list.high {{
            border-left-color: #e67e22;
            background: #ffeaa7;
        }}

        .file-list.failed {{
            border-left-color: #95a5a6;
            background: #ecf0f1;
        }}

        .file-list ul {{
            list-style: none;
            padding-left: 0;
        }}

        .file-list li {{
            padding: 8px 0;
            font-family: 'Courier New', monospace;
            font-size: 0.95em;
            color: #555;
        }}

        .file-details {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            margin: 20px 0;
            overflow: hidden;
        }}

        .file-header {{
            background: #343a40;
            color: white;
            padding: 15px 20px;
            font-family: 'Courier New', monospace;
        }}

        .file-header .filename {{
            font-size: 1.2em;
            font-weight: bold;
            word-break: break-all;
        }}

        .file-meta {{
            display: flex;
            gap: 20px;
            margin-top: 8px;
            font-size: 0.9em;
            color: #adb5bd;
        }}

        .file-meta span {{
            display: flex;
            align-items: center;
            gap: 5px;
        }}

        .status-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
        }}

        .status-badge.success {{
            background: #27ae60;
            color: white;
        }}

        .status-badge.error {{
            background: #e74c3c;
            color: white;
        }}

        .exit-code {{
            padding: 4px 10px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-weight: bold;
        }}

        .exit-code.code-0 {{
            background: #d5f5e3;
            color: #229954;
        }}

        .exit-code.code-1 {{
            background: #ffeaa7;
            color: #d35400;
        }}

        .exit-code.code-2 {{
            background: #fee;
            color: #c0392b;
        }}

        .file-content {{
            padding: 20px;
            max-height: 600px;
            overflow-y: auto;
        }}

        .file-content pre {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 20px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            line-height: 1.5;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}

        .config-section {{
            background: #e8f4f8;
            border-left: 4px solid #3498db;
            padding: 20px;
            margin: 20px 0;
            border-radius: 4px;
        }}

        .config-section ul {{
            list-style: none;
            padding-left: 0;
        }}

        .config-section li {{
            padding: 5px 0;
            font-family: 'Courier New', monospace;
        }}

        .config-section strong {{
            color: #2c3e50;
            min-width: 180px;
            display: inline-block;
        }}

        .no-findings {{
            text-align: center;
            padding: 40px;
            color: #7f8c8d;
            font-style: italic;
        }}

        @media print {{
            body {{
                background: white;
                padding: 0;
            }}

            .container {{
                box-shadow: none;
                padding: 20px;
            }}

            .file-content {{
                max-height: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Security Scan Results</h1>

        <div class="meta-info">
            <p><strong>Scan Completed:</strong> {scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Duration:</strong> {scan_duration:.2f} seconds</p>
            <p><strong>Directory:</strong> {input_dir}</p>
            <p><strong>Files Scanned:</strong> {len(results)}</p>
        </div>

        <h2>📊 Analysis Summary</h2>

        <div class="summary-grid">
            <div class="summary-card critical">
                <div class="number">{critical_findings}</div>
                <div class="label">Critical Findings</div>
            </div>
            <div class="summary-card high">
                <div class="number">{high_findings}</div>
                <div class="label">High Severity</div>
            </div>
            <div class="summary-card clean">
                <div class="number">{clean_files}</div>
                <div class="label">Clean Files</div>
            </div>
            <div class="summary-card failed">
                <div class="number">{failed}</div>
                <div class="label">Failed Analyses</div>
            </div>
        </div>

        <div class="config-section">
            <h3>⚙️ Configuration</h3>
            <ul>
                <li><strong>Model:</strong> {config_info.get('model', 'N/A')}</li>
                <li><strong>LM Studio URL:</strong> {config_info.get('lm_studio_url', 'N/A')}</li>
                <li><strong>Temperature:</strong> {config_info.get('temperature', 'N/A')}</li>
                <li><strong>Max Tokens:</strong> {config_info.get('max_tokens', 'N/A')}</li>
                <li><strong>Severity Filter:</strong> {config_info.get('severity_filter', 'N/A')}</li>
                <li><strong>Parallel Workers:</strong> {config_info.get('parallel_workers', 'N/A')}</li>
            </ul>
        </div>
"""

    # Files with critical findings
    if critical_findings > 0:
        html += """
        <h2>🚨 Files with Critical Findings</h2>
        <div class="file-list critical">
            <ul>
"""
        for file_path, status, duration, output, stderr, returncode in results:
            if status == 'success' and returncode == 2:
                html += f"                <li>{file_path}</li>\n"
        html += """            </ul>
        </div>
"""

    # Files with high findings
    if high_findings > 0:
        html += """
        <h2>⚠️ Files with High Severity Findings</h2>
        <div class="file-list high">
            <ul>
"""
        for file_path, status, duration, output, stderr, returncode in results:
            if status == 'success' and returncode == 1:
                html += f"                <li>{file_path}</li>\n"
        html += """            </ul>
        </div>
"""

    # Failed analyses
    if failed > 0:
        html += """
        <h2>❌ Failed Analyses</h2>
        <div class="file-list failed">
            <ul>
"""
        for file_path, status, duration, output, stderr, returncode in results:
            if status != 'success':
                error_msg = stderr[:200] if stderr else 'No error message'
                html += f"                <li>{file_path}<br><small style='color:#e74c3c'>Error: {error_msg}</small></li>\n"
        html += """            </ul>
        </div>
"""

    # Detailed output
    html += """
        <h2>📄 Detailed Analysis Output</h2>
"""

    for file_path, status, duration, output, stderr, returncode in results:
        status_class = 'success' if status == 'success' else 'error'
        exit_code_class = f'code-{returncode}' if returncode in [0, 1, 2] else 'code-other'

        html += f"""
        <div class="file-details">
            <div class="file-header">
                <div class="filename">{file_path}</div>
                <div class="file-meta">
                    <span><span class="status-badge {status_class}">{status}</span></span>
                    <span>Duration: {duration:.2f}s</span>
                    <span>Exit Code: <span class="exit-code {exit_code_class}">{returncode}</span></span>
                </div>
            </div>
            <div class="file-content">
"""

        if output:
            # Escape HTML in output
            escaped_output = output.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            html += f"                <pre>{escaped_output}</pre>\n"
        elif stderr:
            escaped_stderr = stderr.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            html += f"                <pre>STDERR:\n{escaped_stderr}</pre>\n"
        else:
            html += "                <p class='no-findings'>No output</p>\n"

        html += """            </div>
        </div>
"""

    html += """
    </div>
</body>
</html>
"""

    return html


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Recursive Security Static Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/codebase
  %(prog)s /path/to/codebase --output-file report.txt
  %(prog)s /path/to/codebase --output-file report.html --output-format html
  %(prog)s /path/to/codebase --severity high --exclude "*/obj/*" --exclude "*/bin/*"
  %(prog)s /path/to/codebase --parallel 4 --verbose
        """
    )

    # Positional arguments
    parser.add_argument(
        'input_directory',
        help='Path to directory to scan recursively'
    )

    # Options forwarded to language-specific analyzers
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

    parser.add_argument(
        '--severity',
        choices=['critical', 'high', 'medium', 'low', 'info'],
        default='info',
        help='Minimum severity level to report (default: info)'
    )

    parser.add_argument(
        '--config',
        help='Configuration file path (YAML or JSON) - forwarded to analyzer'
    )

    # AeyeGuard_cmd.py specific options
    parser.add_argument(
        '--output-file',
        help='Path to save the aggregated report'
    )

    parser.add_argument(
        '--output-format',
        choices=['text', 'html'],
        default='text',
        help='Output format for the report (default: text)'
    )

    parser.add_argument(
        '--exclude',
        action='append',
        default=[],
        help='Glob patterns for files/directories to exclude (can be specified multiple times)'
    )

    parser.add_argument(
        '--max-files',
        type=int,
        help='Maximum number of files to analyze'
    )

    parser.add_argument(
        '--parallel',
        type=int,
        default=1,
        help='Number of parallel file analyses (default: 1)'
    )

    parser.add_argument(
        '--continue-on-error',
        action='store_true',
        default=True,
        help='Continue scanning if analysis of a file fails (default: True)'
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
    """Main entry point for the recursive security scanner."""
    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)

    try:
        # Parse arguments
        args = parse_arguments()

        # Setup logging
        setup_logging(args.verbose)
        logger = logging.getLogger(__name__)

        logger.info("=" * 80)
        logger.info("Recursive Security Static Analysis Tool")
        logger.info("=" * 80)

        # Validate input directory
        logger.info(f"Validating input directory: {args.input_directory}")
        input_dir = validate_directory(args.input_directory)

        # Determine script directory
        script_dir = Path(__file__).parent

        # Check that analyzers exist
        cs_analyzer = script_dir / 'cs' / 'AeyeGuard_cs.py'
        react_analyzer = script_dir / 'react' / 'AeyeGuard_react.py'
        java_analyzer = script_dir / 'java' / 'AeyeGuard_java.py'

        available_analyzers = []
        if cs_analyzer.exists():
            available_analyzers.append("C# (.cs)")
        if react_analyzer.exists():
            available_analyzers.append("React (.tsx, .jsx)")
        if java_analyzer.exists():
            available_analyzers.append("Java (.java)")

        if not available_analyzers:
            logger.error("No analyzer scripts found!")
            logger.error("Please ensure language analyzers exist (cs/, react/, java/)")
            return 1

        logger.info(f"Available analyzers: {', '.join(available_analyzers)}")

        # Build forwarded options
        forwarded_options = [
            '--model', args.model,
            '--lm-studio-url', args.lm_studio_url,
            '--temperature', str(args.temperature),
            '--max-tokens', str(args.max_tokens),
            '--severity', args.severity
        ]

        if args.config:
            forwarded_options.extend(['--config', args.config])

        if args.verbose:
            forwarded_options.append('--verbose')

        # Discover files
        scan_start_time = datetime.now()

        logger.info("Discovering files...")
        files = discover_files(
            input_dir,
            {'.cs', '.tsx', '.jsx', '.java'},  # C#, React TypeScript, and Java files
            args.exclude,
            args.max_files
        )

        if not files:
            logger.warning("No files found to analyze")
            return 0

        if interrupted:
            logger.warning("Scan interrupted during file discovery")
            return 130

        # Categorize files by type
        cs_files = [f for f in files if f.suffix.lower() == '.cs']
        tsx_files = [f for f in files if f.suffix.lower() in {'.tsx', '.jsx'}]
        java_files = [f for f in files if f.suffix.lower() == '.java']

        logger.info(f"Found {len(files)} files to analyze:")
        if cs_files:
            logger.info(f"  - {len(cs_files)} C# files (.cs)")
        if tsx_files:
            logger.info(f"  - {len(tsx_files)} React files (.tsx, .jsx)")
        if java_files:
            logger.info(f"  - {len(java_files)} Java files (.java)")

        # Test LLM connection before starting
        logger.info("Testing LLM connection...")
        # Test with any available analyzer
        test_analyzer = cs_analyzer if cs_analyzer.exists() else react_analyzer
        test_cmd = [
            sys.executable,
            str(test_analyzer),
            '--lm-studio-url', args.lm_studio_url,
            '--version'
        ]

        try:
            subprocess.run(test_cmd, capture_output=True, timeout=5)
        except Exception as e:
            logger.warning(f"Could not verify analyzer availability: {e}")

        # Analyze files
        logger.info("Starting security analysis...")
        results = analyze_files_parallel(
            files,
            script_dir,
            forwarded_options,
            args.parallel,
            args.continue_on_error
        )

        scan_end_time = datetime.now()
        scan_duration = (scan_end_time - scan_start_time).total_seconds()

        if interrupted:
            logger.warning("Scan interrupted during analysis")
            logger.info(f"Analyzed {len(results)} of {len(files)} files before interruption")

        # Format output
        logger.info("Formatting output...")

        config_info = {
            'model': args.model,
            'lm_studio_url': args.lm_studio_url,
            'temperature': args.temperature,
            'max_tokens': args.max_tokens,
            'severity_filter': args.severity,
            'parallel_workers': args.parallel,
            'exclude_patterns': args.exclude
        }

        # Format output based on requested format
        if args.output_format == 'html':
            formatted_output = format_output_html(
                results,
                scan_start_time,
                scan_end_time,
                str(input_dir),
                config_info
            )
        else:
            formatted_output = format_output(
                results,
                scan_start_time,
                scan_end_time,
                str(input_dir),
                config_info,
                'text'
            )

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
            print("\n" + formatted_output)

        # Determine exit code based on results
        critical_count = sum(1 for r in results if r[1] == 'success' and r[5] == 2)
        high_count = sum(1 for r in results if r[1] == 'success' and r[5] == 1)

        if interrupted:
            return 130
        elif critical_count > 0:
            logger.warning(f"Critical vulnerabilities found in {critical_count} files!")
            return 2
        elif high_count > 0:
            logger.warning(f"High severity vulnerabilities found in {high_count} files!")
            return 1

        logger.info("Scan completed successfully")
        return 0

    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
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
