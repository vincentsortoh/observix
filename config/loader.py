"""
Author: Vincent Sortoh
Created on: 2025-05-10

Configuration loading and management for Observix.

This module provides functions to load and manage configuration for OpenTelemetry
instrumentation, including settings for tracing, metrics, and auto-instrumentation.
"""

import os
import sys
import json
import yaml
import logging
import importlib.util
from pathlib import Path
from typing import Dict, Any, Optional, List, Union

# Default configuration
DEFAULT_CONFIG = {
    "service": {
        "name": "unnamed-service",
        "version": "1.0.0",
        "environment": "development"
    },
    "tracing": {
        "enabled": True,
        "exporters": ["console"],
        "otlp": {
            "endpoint": None,
            "headers": {}
        }
    },
    "metrics": {
        "enabled": True,
        "exporters": ["console"],
        "export_interval_millis": 30000,
        "otlp": {
            "endpoint": None,
            "headers": {}
        }
    },
    "logging": {
        "enabled": True,
        "level": "INFO",
        "format": "%(asctime)s [%(levelname)s] %(name)s - %(message)s [trace_id=%(otelTraceID)s span_id=%(otelSpanID)s]",
        "handlers": ["console"]
    },
    "auto_instrumentation": {
        "enabled": True,
        "libraries": None 
    },
    "security": {
        "sensitive_keys": None, 
        "redaction_value": "***REDACTED***",
        "enable_regex": True
    }
}

logger = logging.getLogger(__name__)

class ConfigurationError(Exception):
    """Exception raised for configuration errors."""
    pass

def deep_merge(source: Dict[str, Any], destination: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge two dictionaries.
    
    Args:
        source: Source dictionary
        destination: Destination dictionary (will be modified)
        
    Returns:
        dict: Merged dictionary
    """
    for key, value in source.items():
        if isinstance(value, dict):
            # Get node or create one
            node = destination.setdefault(key, {})
            if isinstance(node, dict):
                deep_merge(value, node)
            else:
                destination[key] = value
        else:
            destination[key] = value
            
    return destination

def _load_from_env(prefix: str = "OBSERVIX_") -> Dict[str, Any]:
    """
    Load configuration from environment variables.
    
    Environment variables should be prefixed with the specified prefix.
    Nested keys should be separated by double underscores.
    
    Examples:
        OBSERVIX_SERVICE__NAME=my-service
        OBSERVIX_TRACING__ENABLED=true
        OBSERVIX_METRICS__EXPORT_INTERVAL_MILLIS=60000
        
    Args:
        prefix: Prefix for environment variables
        
    Returns:
        dict: Configuration from environment variables
    """
    config = {}
    
    for key, value in os.environ.items():
        if not key.startswith(prefix):
            continue
            
        # Remove prefix and split by double underscore
        key_path = key[len(prefix):].lower().split("__")
        

        if value.lower() in ("true", "yes", "1"):
            value = True
        elif value.lower() in ("false", "no", "0"):
            value = False
        elif value.isdigit():
            value = int(value)
        elif value.replace(".", "", 1).isdigit() and value.count(".") == 1:
            value = float(value)
        elif value.lower() in ("null", "none"):
            value = None
        
        current = config
        for i, part in enumerate(key_path):
            if i == len(key_path) - 1:
                current[part] = value
            else:
                current = current.setdefault(part, {})
    
    return config

def _load_from_file(file_path: str) -> Dict[str, Any]:
    """
    Load configuration from a file.
    
    Supports JSON, YAML, and Python files.
    
    Args:
        file_path: Path to the configuration file
        
    Returns:
        dict: Configuration from the file
        
    Raises:
        ConfigurationError: If the file is not found or has an unsupported format
    """
    path = Path(file_path)
    
    if not path.exists():
        raise ConfigurationError(f"Configuration file not found: {file_path}")
    
    suffix = path.suffix.lower()
    
    try:
        if suffix in (".json",):
            with open(path) as f:
                return json.load(f)
        elif suffix in (".yaml", ".yml"):
            with open(path) as f:
                return yaml.safe_load(f)
        elif suffix in (".py",):

            module_name = path.stem
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                raise ConfigurationError(f"Cannot load Python config: {file_path}")
                
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Extract configuration from module
            config = {}
            for key, value in module.__dict__.items():
                if not key.startswith("_"):
                    config[key.lower()] = value
            
            return config
        else:
            
            raise ConfigurationError(f"Unsupported configuration file format: {suffix}")
    except Exception as e:
        raise ConfigurationError(f"Error loading configuration from {file_path}: {str(e)}")

def load_config(
    config_path: Optional[str] = None,
    env_prefix: str = "OBSERVIX_",
    merge_env: bool = True
) -> Dict[str, Any]:
    """
    Load configuration from multiple sources.
    
    Priority (highest to lowest):
    1. Environment variables (if merge_env is True)
    2. Configuration file (if provided)
    3. Default configuration
    
    Args:
        config_path: Path to configuration file
        env_prefix: Prefix for environment variables
        merge_env: Whether to merge environment variables
        
    Returns:
        dict: Merged configuration
    """
    # Start with default configuration
    config = DEFAULT_CONFIG.copy()
    # Load from file if provided
    if config_path:
        try:
            file_config = _load_from_file(config_path)
            config = deep_merge(file_config, config)
            logger.info(f"Loaded configuration from file: {config_path}")
        except ConfigurationError as e:
            logger.warning(str(e))
    
    # Load from environment variables if requested
    if merge_env:
        env_config = _load_from_env(env_prefix)
        if env_config:
            config = deep_merge(env_config, config)
            logger.info("Merged configuration from environment variables")
    
    return config

def apply_config(config: Dict[str, Any]) -> None:
    """
    Apply the loaded configuration to set up Observix components.
    
    This function is a convenience wrapper that initializes all Observix
    components according to the provided configuration.
    
    Args:
        config: Configuration dictionary
    """
    from observix.core.tracer import init_tracing
    from observix.core.metrics import init_metrics
    from observix.auto.instrumentor import auto_instrument_libraries
    from observix.logging_helpers.integrations import setup_logging
    from observix.utils.security import DataRedactor
    
    service_config = config.get("service", {})
    service_name = service_config.get("name", "unnamed-service")
    service_version = service_config.get("version", "1.0.0")
    service_env = service_config.get("environment", "development")
    

    if config.get("tracing", {}).get("enabled", True):
        tracing_config = config.get("tracing", {})
        exporters = tracing_config.get("exporters", ["console"])
        
        init_tracing(
            service_name=service_name,
            version=service_version,
            environment=service_env,
            exporters=exporters,
        )
        logger.info("Initialized tracing")
    
    if config.get("metrics", {}).get("enabled", True):
        metrics_config = config.get("metrics", {})
        exporters = metrics_config.get("exporters", ["console"])
        interval = metrics_config.get("export_interval_millis", 30000)
        
        init_metrics(
            service_name=service_name,
            version=service_version,
            environment=service_env,
            exporters=exporters,
            export_interval_millis=interval,
        )
        logger.info("Initialized metrics")
    
    if config.get("logging", {}).get("enabled", True):
        logging_config = config.get("logging", {})
        log_level = logging_config.get("level", "INFO")
        log_format = logging_config.get("format", "%(asctime)s [%(levelname)s] %(name)s - %(message)s [trace_id=%(otelTraceID)s span_id=%(otelSpanID)s]")
        
        setup_logging(
            level=log_level,
            format_string=log_format,
        )
        logger.info("Set up logging")
    
    security_config = config.get("security", {})
    sensitive_keys = security_config.get("sensitive_keys")
    redaction_value = security_config.get("redaction_value", "***REDACTED***")
    enable_regex = security_config.get("enable_regex", True)
    
    if any([sensitive_keys, redaction_value != "***REDACTED***", enable_regex != True]):
        from observix.utils.security import DataRedactor, default_redactor
        
        new_redactor = DataRedactor(
            sensitive_keys=sensitive_keys,
            redaction_value=redaction_value,
            enable_regex=enable_regex
        )
        
        # Replace the default redactor
        # Note: This is a bit hacky, but it's the simplest way to update the default redactor
        import observix.utils.security
        observix.utils.security.default_redactor = new_redactor
        logger.info("Updated security configuration")
    

    if config.get("auto_instrumentation", {}).get("enabled", True):
        auto_config = config.get("auto_instrumentation", {})
        libraries = auto_config.get("libraries")
        
        auto_instrument_libraries(libraries)
        logger.info("Applied auto-instrumentation")

def get_config_from_path(
    config_paths: Union[str, List[str]],
    env_prefix: str = "OBSERVIX_",
    merge_env: bool = True
) -> Dict[str, Any]:
    """
    Try loading configuration from multiple possible paths.
    
    Args:
        config_paths: Path or list of paths to configuration files
        env_prefix: Prefix for environment variables
        merge_env: Whether to merge environment variables
        
    Returns:
        dict: Loaded configuration
    """
    if isinstance(config_paths, str):
        config_paths = [config_paths]
    
    for path in config_paths:
        try:
            return load_config(path, env_prefix, merge_env)
        except Exception as e:
            logger.debug(f"Could not load config from {path}: {str(e)}")
    
    return load_config(None, env_prefix, merge_env) # If no config file worked, return defaults merged with env vars

def find_and_load_config(
    search_paths: List[str] = None,
    filenames: List[str] = None,
    env_prefix: str = "OBSERVIX_",
    merge_env: bool = True
) -> Dict[str, Any]:
    """
    Search for and load a configuration file.
    
    Default search paths:
    - Current directory
    - User's home directory
    - /etc/observix
    
    Default filenames:
    - observix.json
    - observix.yaml
    - observix.yml
    - observix.py
    
    Args:
        search_paths: List of directories to search
        filenames: List of filenames to try
        env_prefix: Prefix for environment variables
        merge_env: Whether to merge environment variables
        
    Returns:
        dict: Loaded configuration
    """
    search_paths = search_paths or [
        ".",
        str(Path.home()),
        "/etc/observix"
    ]
    
    filenames = filenames or [
        "observix.json",
        "observix.yaml",
        "observix.yml",
        "observix.py"
    ]
    
 
    env_config_path = os.environ.get(f"{env_prefix}CONFIG")    # Check for config path in environment variable
    if env_config_path:
        try:
            return load_config(env_config_path, env_prefix, merge_env)
        except Exception as e:
            logger.warning(f"Could not load config from environment variable path: {str(e)}")
    

    for path in search_paths:
        for name in filenames:
            config_path = os.path.join(path, name)
            try:
                if os.path.exists(config_path):
                    return load_config(config_path, env_prefix, merge_env)
            except Exception as e:
                logger.debug(f"Could not load config from {config_path}: {str(e)}")
    
    
    return load_config(None, env_prefix, merge_env) # If no config file found, return defaults merged with env vars