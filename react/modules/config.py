"""
Configuration management module for AeyeGuard_react.

Handles loading and merging configuration from multiple sources:
- Configuration files (YAML/JSON)
- Environment variables
- Command-line arguments
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class Config:
    """Configuration container for the React security scanner."""

    # LLM settings
    model: str = 'qwen/qwen3-coder-30b'
    lm_studio_url: str = 'http://localhost:1234'
    temperature: float = 0.0
    max_tokens: int = 4096

    # Output settings
    output_format: str = 'console'
    output_file: Optional[str] = None
    severity_filter: str = 'info'

    # React-specific settings
    react_version: int = 18
    check_hooks: bool = True
    check_performance: bool = False
    framework: str = 'react'  # react, next, remix, gatsby
    include_dependencies: bool = False

    # Analysis settings
    chunk_size: int = 5000  # lines per chunk for large files
    enable_chunking: bool = True
    retry_attempts: int = 3
    retry_delay: int = 2  # seconds
    timeout: int = 300  # seconds

    # Logging
    verbose: bool = False

    # Custom rules
    custom_rules: Dict[str, List[str]] = field(default_factory=lambda: {
        'dangerous_functions': [
            'dangerouslySetInnerHTML',
            'eval',
            'Function',
            'innerHTML',
            'outerHTML',
            'document.write'
        ],
        'sensitive_storage_keys': [
            'token',
            'password',
            'secret',
            'apikey',
            'credential'
        ],
        'unsafe_attributes': [
            'dangerouslySetInnerHTML',
            'srcDoc'
        ]
    })

    @classmethod
    def load(cls, config_file: Optional[str] = None, cli_args: Optional[Dict[str, Any]] = None) -> 'Config':
        """
        Load configuration from multiple sources with precedence:
        1. Command-line arguments (highest priority)
        2. Environment variables
        3. Configuration file
        4. Default values (lowest priority)

        Args:
            config_file: Path to configuration file (YAML or JSON)
            cli_args: Dictionary of CLI arguments

        Returns:
            Config instance with merged settings
        """
        config_dict = {}

        # 1. Load from configuration file
        if config_file:
            file_config = cls._load_from_file(config_file)
            if file_config:
                config_dict.update(file_config)
                logger.info(f"Loaded configuration from {config_file}")

        # 2. Load from environment variables
        env_config = cls._load_from_env()
        if env_config:
            config_dict.update(env_config)
            logger.debug(f"Loaded {len(env_config)} settings from environment variables")

        # 3. Apply CLI arguments (highest priority)
        if cli_args:
            cli_config = cls._filter_cli_args(cli_args)
            config_dict.update(cli_config)
            logger.debug(f"Applied {len(cli_config)} CLI arguments")

        # Create config instance
        return cls(**config_dict)

    @staticmethod
    def _load_from_file(file_path: str) -> Dict[str, Any]:
        """Load configuration from YAML or JSON file."""
        try:
            path = Path(file_path)
            if not path.exists():
                logger.warning(f"Configuration file not found: {file_path}")
                return {}

            with open(path, 'r', encoding='utf-8') as f:
                if file_path.endswith(('.yaml', '.yml')):
                    if not YAML_AVAILABLE:
                        logger.error("PyYAML not installed, cannot load YAML config")
                        return {}
                    return yaml.safe_load(f) or {}
                elif file_path.endswith('.json'):
                    return json.load(f)
                else:
                    logger.warning(f"Unsupported config file format: {file_path}")
                    return {}

        except Exception as e:
            logger.error(f"Error loading config file: {e}")
            return {}

    @staticmethod
    def _load_from_env() -> Dict[str, Any]:
        """Load configuration from environment variables."""
        env_config = {}

        env_mapping = {
            'SECSCAN_REACT_MODEL': 'model',
            'SECSCAN_REACT_LM_STUDIO_URL': 'lm_studio_url',
            'SECSCAN_REACT_TEMPERATURE': ('temperature', float),
            'SECSCAN_REACT_MAX_TOKENS': ('max_tokens', int),
            'SECSCAN_REACT_OUTPUT': 'output_format',
            'SECSCAN_REACT_SEVERITY': 'severity_filter',
            'SECSCAN_REACT_VERSION': ('react_version', int),
            'SECSCAN_REACT_FRAMEWORK': 'framework',
            'SECSCAN_REACT_VERBOSE': ('verbose', lambda x: x.lower() in ['true', '1', 'yes']),
        }

        for env_var, config_key in env_mapping.items():
            value = os.environ.get(env_var)
            if value is not None:
                if isinstance(config_key, tuple):
                    key, converter = config_key
                    try:
                        env_config[key] = converter(value)
                    except Exception as e:
                        logger.warning(f"Failed to convert {env_var}={value}: {e}")
                else:
                    env_config[config_key] = value

        return env_config

    @staticmethod
    def _filter_cli_args(cli_args: Dict[str, Any]) -> Dict[str, Any]:
        """Filter and map CLI arguments to config keys."""
        filtered = {}

        # Map CLI argument names to config attribute names
        arg_mapping = {
            'model': 'model',
            'lm_studio_url': 'lm_studio_url',
            'temperature': 'temperature',
            'max_tokens': 'max_tokens',
            'output': 'output_format',
            'output_file': 'output_file',
            'severity': 'severity_filter',
            'verbose': 'verbose',
            'config': None,  # Already processed
            'input_file': None,  # Not a config parameter
            'react_version': 'react_version',
            'check_hooks': 'check_hooks',
            'check_performance': 'check_performance',
            'framework': 'framework',
            'include_dependencies': 'include_dependencies',
        }

        for cli_key, config_key in arg_mapping.items():
            if config_key and cli_key in cli_args and cli_args[cli_key] is not None:
                filtered[config_key] = cli_args[cli_key]

        return filtered

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            'model': self.model,
            'lm_studio_url': self.lm_studio_url,
            'temperature': self.temperature,
            'max_tokens': self.max_tokens,
            'output_format': self.output_format,
            'output_file': self.output_file,
            'severity_filter': self.severity_filter,
            'react_version': self.react_version,
            'check_hooks': self.check_hooks,
            'check_performance': self.check_performance,
            'framework': self.framework,
            'include_dependencies': self.include_dependencies,
            'chunk_size': self.chunk_size,
            'enable_chunking': self.enable_chunking,
            'retry_attempts': self.retry_attempts,
            'retry_delay': self.retry_delay,
            'timeout': self.timeout,
            'verbose': self.verbose,
            'custom_rules': self.custom_rules,
        }
