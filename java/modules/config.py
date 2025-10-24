"""
Configuration management module for AeyeGuard_java.

Handles loading and merging configuration from multiple sources:
- Configuration files (YAML/JSON)
- Environment variables
- Command-line arguments
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class Config:
    """Configuration container for the Java security scanner."""

    # LLM settings
    model: str = 'qwen/qwen3-coder-30b'
    lm_studio_url: str = 'http://localhost:1234'
    temperature: float = 0.0  # Deterministic by default
    max_tokens: int = 4096

    # Output settings
    output_format: str = 'console'
    output_file: Optional[str] = None
    severity_filter: str = 'info'

    # Analysis settings
    chunk_size: int = 5000  # lines per chunk for large files
    enable_chunking: bool = True
    retry_attempts: int = 3
    retry_delay: int = 2  # seconds
    timeout: int = 300  # seconds

    # Logging
    verbose: bool = False

    # Custom patterns (for future use)
    custom_rules: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, config_file: Optional[str] = None, cli_args: Optional[Dict[str, Any]] = None) -> 'Config':
        """
        Load configuration from multiple sources with proper precedence.

        Precedence (highest to lowest):
        1. Command-line arguments
        2. Environment variables
        3. Configuration file
        4. Defaults

        Args:
            config_file: Path to configuration file (YAML or JSON)
            cli_args: Command-line arguments dictionary

        Returns:
            Config object with merged settings
        """
        config_dict = {}

        # 1. Load from config file
        if config_file:
            file_config = cls._load_config_file(config_file)
            config_dict.update(file_config)

        # 2. Load from environment variables
        env_config = cls._load_from_env()
        config_dict.update(env_config)

        # 3. Override with CLI arguments
        if cli_args:
            cli_config = cls._process_cli_args(cli_args)
            config_dict.update(cli_config)

        # Create config object
        config = cls(**{k: v for k, v in config_dict.items() if v is not None})

        logger.debug(f"Loaded configuration: {config}")
        return config

    @staticmethod
    def _load_config_file(config_file: str) -> Dict[str, Any]:
        """Load configuration from YAML or JSON file."""
        path = Path(config_file)

        if not path.exists():
            logger.warning(f"Configuration file not found: {config_file}")
            return {}

        try:
            with open(path, 'r') as f:
                if path.suffix in ['.yaml', '.yml']:
                    if not YAML_AVAILABLE:
                        logger.error("PyYAML is not installed. Cannot load YAML config.")
                        return {}
                    config = yaml.safe_load(f)
                elif path.suffix == '.json':
                    config = json.load(f)
                else:
                    logger.warning(f"Unknown config file format: {path.suffix}")
                    return {}

            logger.info(f"Loaded configuration from {config_file}")
            return config or {}

        except Exception as e:
            logger.error(f"Error loading config file: {e}")
            return {}

    @staticmethod
    def _load_from_env() -> Dict[str, Any]:
        """Load configuration from environment variables."""
        env_config = {}

        # Map environment variables to config keys
        env_mapping = {
            'SECSCAN_MODEL': 'model',
            'SECSCAN_LM_STUDIO_URL': 'lm_studio_url',
            'SECSCAN_TEMPERATURE': ('temperature', float),
            'SECSCAN_MAX_TOKENS': ('max_tokens', int),
            'SECSCAN_CHUNK_SIZE': ('chunk_size', int),
            'SECSCAN_RETRY_ATTEMPTS': ('retry_attempts', int),
            'SECSCAN_TIMEOUT': ('timeout', int),
        }

        for env_var, config_key in env_mapping.items():
            value = os.environ.get(env_var)
            if value is not None:
                # Handle type conversion if specified
                if isinstance(config_key, tuple):
                    config_key, type_func = config_key
                    try:
                        value = type_func(value)
                    except ValueError:
                        logger.warning(f"Invalid value for {env_var}: {value}")
                        continue

                env_config[config_key] = value
                logger.debug(f"Loaded {config_key} from environment")

        return env_config

    @staticmethod
    def _process_cli_args(cli_args: Dict[str, Any]) -> Dict[str, Any]:
        """Process and map CLI arguments to config keys."""
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
        }

        cli_config = {}
        for cli_key, config_key in arg_mapping.items():
            if cli_key in cli_args and cli_args[cli_key] is not None:
                cli_config[config_key] = cli_args[cli_key]

        return cli_config

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            'model': self.model,
            'lm_studio_url': self.lm_studio_url,
            'temperature': self.temperature,
            'max_tokens': self.max_tokens,
            'output_format': self.output_format,
            'output_file': self.output_file,
            'severity_filter': self.severity_filter,
            'chunk_size': self.chunk_size,
            'enable_chunking': self.enable_chunking,
            'retry_attempts': self.retry_attempts,
            'retry_delay': self.retry_delay,
            'timeout': self.timeout,
            'verbose': self.verbose,
        }

    def validate(self) -> bool:
        """
        Validate configuration parameters.

        Returns:
            True if configuration is valid

        Raises:
            ValueError: If configuration is invalid
        """
        if self.temperature < 0 or self.temperature > 2:
            raise ValueError(f"Temperature must be between 0 and 2: {self.temperature}")

        if self.max_tokens < 100:
            raise ValueError(f"max_tokens must be at least 100: {self.max_tokens}")

        if self.chunk_size < 100:
            raise ValueError(f"chunk_size must be at least 100: {self.chunk_size}")

        if self.retry_attempts < 0:
            raise ValueError(f"retry_attempts must be non-negative: {self.retry_attempts}")

        if not self.lm_studio_url.startswith(('http://', 'https://')):
            raise ValueError(f"Invalid LM Studio URL: {self.lm_studio_url}")

        return True
