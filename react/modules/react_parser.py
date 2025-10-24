"""
React/TSX/JSX parsing utilities.

Provides helper functions for analyzing React TypeScript files.
"""

import re
import logging
from typing import Dict, List, Set, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)


class ReactParser:
    """Parser for React TypeScript/JSX files."""

    # React component patterns
    FUNCTIONAL_COMPONENT_PATTERN = r'(?:export\s+)?(?:const|let|var|function)\s+(\w+)\s*[=:]\s*(?:\([^)]*\)|[^=]*)\s*(?:=>|:)'
    CLASS_COMPONENT_PATTERN = r'class\s+(\w+)\s+extends\s+(?:React\.)?(?:Component|PureComponent)'

    # Hook patterns
    HOOK_PATTERN = r'\b(use[A-Z]\w+)\s*\('

    # Dangerous patterns
    DANGEROUS_HTML_PATTERN = r'dangerouslySetInnerHTML\s*=\s*\{\s*\{?\s*__html\s*:'
    EVAL_PATTERN = r'\b(eval|Function)\s*\('
    INNERHTML_PATTERN = r'\.innerHTML\s*=|\.outerHTML\s*='

    # Storage patterns
    LOCALSTORAGE_PATTERN = r'localStorage\.(setItem|getItem)\s*\('
    SESSIONSTORAGE_PATTERN = r'sessionStorage\.(setItem|getItem)\s*\('

    # API patterns
    HTTP_URL_PATTERN = r'["\']http://[^"\']+["\']'

    def __init__(self):
        """Initialize React parser."""
        pass

    def detect_component_type(self, code: str) -> str:
        """
        Detect if code contains React components and their type.

        Args:
            code: TypeScript/JSX code

        Returns:
            Component type: 'functional', 'class', 'mixed', 'none'
        """
        has_functional = bool(re.search(self.FUNCTIONAL_COMPONENT_PATTERN, code))
        has_class = bool(re.search(self.CLASS_COMPONENT_PATTERN, code))

        if has_functional and has_class:
            return 'mixed'
        elif has_functional:
            return 'functional'
        elif has_class:
            return 'class'
        else:
            return 'none'

    def extract_hooks(self, code: str) -> List[str]:
        """
        Extract all React hooks used in the code.

        Args:
            code: TypeScript/JSX code

        Returns:
            List of hook names (e.g., ['useState', 'useEffect'])
        """
        matches = re.findall(self.HOOK_PATTERN, code)
        return list(set(matches))

    def has_dangerous_html(self, code: str) -> bool:
        """Check if code uses dangerouslySetInnerHTML."""
        return bool(re.search(self.DANGEROUS_HTML_PATTERN, code))

    def has_eval(self, code: str) -> bool:
        """Check if code uses eval or Function constructor."""
        return bool(re.search(self.EVAL_PATTERN, code))

    def has_direct_dom_manipulation(self, code: str) -> bool:
        """Check if code directly manipulates DOM."""
        return bool(re.search(self.INNERHTML_PATTERN, code))

    def has_storage_usage(self, code: str) -> Tuple[bool, bool]:
        """
        Check if code uses localStorage or sessionStorage.

        Returns:
            Tuple of (has_localStorage, has_sessionStorage)
        """
        has_local = bool(re.search(self.LOCALSTORAGE_PATTERN, code))
        has_session = bool(re.search(self.SESSIONSTORAGE_PATTERN, code))
        return (has_local, has_session)

    def has_http_urls(self, code: str) -> bool:
        """Check if code contains HTTP (non-HTTPS) URLs."""
        return bool(re.search(self.HTTP_URL_PATTERN, code))

    def extract_imports(self, code: str) -> List[str]:
        """
        Extract all import statements from code.

        Args:
            code: TypeScript/JSX code

        Returns:
            List of import statements
        """
        import_pattern = r'import\s+.*?from\s+["\']([^"\']+)["\']'
        matches = re.findall(import_pattern, code)
        return matches

    def detect_react_version_hints(self, code: str) -> Optional[int]:
        """
        Try to detect React version from code patterns.

        Args:
            code: TypeScript/JSX code

        Returns:
            Detected React version (17, 18, 19) or None
        """
        # React 18+ patterns
        if 'createRoot' in code or 'hydrateRoot' in code:
            return 18

        # React 17 patterns
        if 'ReactDOM.render' in code:
            return 17

        # Server Components (React 18+)
        if "'use server'" in code or '"use server"' in code:
            return 18

        # Default: cannot determine
        return None

    def is_typescript(self, code: str) -> bool:
        """
        Check if code uses TypeScript features.

        Args:
            code: Code to check

        Returns:
            True if TypeScript features detected
        """
        # Look for TypeScript syntax
        ts_patterns = [
            r':\s*(?:string|number|boolean|any|void|never|unknown)\b',  # Type annotations
            r'interface\s+\w+',  # Interfaces
            r'type\s+\w+\s*=',  # Type aliases
            r'<\w+>',  # Generic types
            r'as\s+(?:const|any|unknown|never)',  # Type assertions
        ]

        return any(re.search(pattern, code) for pattern in ts_patterns)

    def count_components(self, code: str) -> int:
        """
        Count the number of React components in the code.

        Args:
            code: TypeScript/JSX code

        Returns:
            Number of components found
        """
        functional_count = len(re.findall(self.FUNCTIONAL_COMPONENT_PATTERN, code))
        class_count = len(re.findall(self.CLASS_COMPONENT_PATTERN, code))
        return functional_count + class_count

    def extract_jsx_elements(self, code: str) -> List[str]:
        """
        Extract JSX element names from code.

        Args:
            code: TypeScript/JSX code

        Returns:
            List of JSX element names (e.g., ['div', 'span', 'Button'])
        """
        # Match opening JSX tags
        jsx_pattern = r'<(\w+)(?:\s|>|/)'
        matches = re.findall(jsx_pattern, code)

        # Filter out HTML elements, keep custom components
        custom_components = [m for m in matches if m[0].isupper()]
        return list(set(custom_components))

    def has_useeffect_without_deps(self, code: str) -> bool:
        """
        Check if code has useEffect without dependency array.

        Args:
            code: TypeScript/JSX code

        Returns:
            True if potentially problematic useEffect found
        """
        # This is a simplified check - full AST parsing would be more accurate
        useeffect_pattern = r'useEffect\s*\(\s*\([^)]*\)\s*=>\s*\{[^}]+\}\s*\)'
        return bool(re.search(useeffect_pattern, code))

    def analyze_file_info(self, code: str, file_path: str) -> Dict[str, any]:
        """
        Analyze React file and extract metadata.

        Args:
            code: TypeScript/JSX code
            file_path: Path to the file

        Returns:
            Dictionary with file analysis metadata
        """
        info = {
            'file_path': file_path,
            'file_extension': Path(file_path).suffix,
            'lines_of_code': len(code.splitlines()),
            'is_typescript': self.is_typescript(code),
            'component_type': self.detect_component_type(code),
            'component_count': self.count_components(code),
            'hooks_used': self.extract_hooks(code),
            'imports': self.extract_imports(code),
            'custom_components': self.extract_jsx_elements(code),
            'react_version_hint': self.detect_react_version_hints(code),
            'security_flags': {
                'has_dangerous_html': self.has_dangerous_html(code),
                'has_eval': self.has_eval(code),
                'has_direct_dom': self.has_direct_dom_manipulation(code),
                'has_localstorage': self.has_storage_usage(code)[0],
                'has_sessionstorage': self.has_storage_usage(code)[1],
                'has_http_urls': self.has_http_urls(code),
                'has_useeffect_issues': self.has_useeffect_without_deps(code),
            }
        }

        logger.debug(f"File analysis: {info['component_count']} components, "
                    f"{len(info['hooks_used'])} hooks, "
                    f"{'TypeScript' if info['is_typescript'] else 'JavaScript'}")

        return info


def validate_react_file(file_path: str) -> Tuple[bool, str]:
    """
    Validate if a file is a React TypeScript/JSX file.

    Args:
        file_path: Path to check

    Returns:
        Tuple of (is_valid, reason)
    """
    path = Path(file_path)

    # Check extension
    valid_extensions = {'.tsx', '.jsx', '.ts', '.js'}
    if path.suffix.lower() not in valid_extensions:
        return False, f"Invalid extension: {path.suffix}. Expected .tsx, .jsx, .ts, or .js"

    # Check if file exists
    if not path.exists():
        return False, f"File does not exist: {file_path}"

    if not path.is_file():
        return False, f"Path is not a file: {file_path}"

    try:
        # Try to read file
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read(1000)  # Read first 1000 chars

        # For .ts and .js files, check if they import React
        if path.suffix.lower() in {'.ts', '.js'}:
            if 'react' not in content.lower():
                return False, "File does not appear to use React (no React import found)"

        return True, "Valid React file"

    except Exception as e:
        return False, f"Error reading file: {e}"
