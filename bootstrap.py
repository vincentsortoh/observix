"""
Author: Vincent Sortoh
Created on: 2025-05-10

Observix bootstrap module.

This module provides a simple entry point for setting up the entire Observix
observability stack with a single function call.
"""
import json
import logging
import os
from typing import Dict, Any, Optional, List, Union

from core.tracer import init_tracing, get_tracer
from core.metrics import init_metrics, get_meter
from auto.instrumentor import auto_instrument_libraries
from core.class_instrumentor import instrument_selected_classes, load_config as load_instrument_config
from utils.security import DataRedactor
from config.loader import load_config, find_and_load_config

logger = logging.getLogger(__name__)


def bootstrap(
    service_name: Optional[str] = None,
    version: Optional[str] = None,
    environment: Optional[str] = None,
    config_path: Optional[str] = None,
    enable_tracing: bool = True,
    enable_metrics: bool = True,
    enable_auto_instrumentation: bool = True,
    auto_instrument_libs: Optional[List[str]] = None,
    tracing_exporters: Optional[List[str]] = None,
    metrics_exporters: Optional[List[str]] = None,
    metrics_interval_ms: int = 30000,
    sensitive_keys: Optional[List[str]] = None,
    env_prefix: str = "OBSERVIX_",
    merge_env: bool = True,
    # New parameters for class instrumentation
    enable_class_instrumentation: bool = False,
    class_instrumentation_config: Optional[Union[str, Dict[str, Any]]] = None,
    base_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Bootstrap the entire Observix observability stack.
    
    This function initializes tracing, metrics, and auto-instrumentation
    based on the provided configuration or configuration file.
    
    Args:
        service_name: Name of the service
        version: Service version
        environment: Deployment environment (dev, staging, prod, etc.)
        config_path: Path to configuration file
        enable_tracing: Whether to enable tracing
        enable_metrics: Whether to enable metrics
        enable_auto_instrumentation: Whether to enable auto-instrumentation
        auto_instrument_libs: List of libraries to auto-instrument
        tracing_exporters: List of tracing exporters
        metrics_exporters: List of metrics exporters
        metrics_interval_ms: Metrics export interval in milliseconds
        sensitive_keys: List of sensitive keys to redact
        env_prefix: Prefix for environment variables
        merge_env: Whether to merge environment variables
        enable_class_instrumentation: Whether to enable selective class instrumentation
        class_instrumentation_config: Configuration for class instrumentation (path or dict)
        base_path: Base path for module discovery in class instrumentation
        
    Returns:
        dict: Dictionary with initialized components
        
    Example:
        # Basic usage
        from observix.bootstrap import bootstrap
        
        bootstrap(service_name="my-service")
        
        # Advanced usage with configuration
        bootstrap(
            service_name="my-service",
            version="1.2.3",
            environment="production",
            enable_tracing=True,
            enable_metrics=True,
            tracing_exporters=["console", "otlp"],
            metrics_exporters=["console", "otlp"],
            sensitive_keys=["password", "api_key"],
            enable_class_instrumentation=True,
            class_instrumentation_config="config.json"
        )
    """

    if config_path:
        config = load_config(config_path, env_prefix, merge_env)
    else:
        config = find_and_load_config(env_prefix=env_prefix, merge_env=merge_env)
    

    if service_name:
        config.setdefault("service", {})["name"] = service_name
    if version:
        config.setdefault("service", {})["version"] = version
    if environment:
        config.setdefault("service", {})["environment"] = environment
    
    if enable_tracing is not None:
        config.setdefault("tracing", {})["enabled"] = enable_tracing
    if tracing_exporters:
        config.setdefault("tracing", {})["exporters"] = tracing_exporters
    
    if enable_metrics is not None:
        config.setdefault("metrics", {})["enabled"] = enable_metrics
    if metrics_exporters:
        config.setdefault("metrics", {})["exporters"] = metrics_exporters
    if metrics_interval_ms:
        config.setdefault("metrics", {})["export_interval_millis"] = metrics_interval_ms
    
    if enable_auto_instrumentation is not None:
        config.setdefault("auto_instrumentation", {})["enabled"] = enable_auto_instrumentation
    if auto_instrument_libs:
        config.setdefault("auto_instrumentation", {})["libraries"] = auto_instrument_libs
    
    if sensitive_keys:
        config.setdefault("security", {})["sensitive_keys"] = sensitive_keys
    
    if enable_class_instrumentation is not None:
        config.setdefault("class_instrumentation", {})["enabled"] = enable_class_instrumentation
    

    service_config = config.get("service", {})
    service_name = service_config.get("name", "unnamed-service")
    service_version = service_config.get("version", "1.0.0")
    service_env = service_config.get("environment", "development")
    

    result = {
        "service": {
            "name": service_name,
            "version": service_version,
            "environment": service_env
        },
        "config": config
    }
    
    tracer = None
    if config.get("tracing", {}).get("enabled", True):
        tracing_config = config.get("tracing", {})
        exporters = tracing_config.get("exporters", ["console"])
        
        tracer = init_tracing(
            service_name=service_name,
            version=service_version,
            environment=service_env,
            exporters=exporters,
        )
        result["tracer"] = tracer
        logger.info(f"Initialized tracing for service: {service_name}")
    
    meter = None
    if config.get("metrics", {}).get("enabled", True):
        metrics_config = config.get("metrics", {})
        exporters = metrics_config.get("exporters", ["console"])
        interval = metrics_config.get("export_interval_millis", 30000)
        
        meter = init_metrics(
            service_name=service_name,
            version=service_version,
            environment=service_env,
            exporters=exporters,
            export_interval_millis=interval,
        )
        result["meter"] = meter
        logger.info(f"Initialized metrics for service: {service_name}")
    

    security_config = config.get("security", {})
    sensitive_keys = security_config.get("sensitive_keys")
    redaction_value = security_config.get("redaction_value", "***REDACTED***")
    enable_regex = security_config.get("enable_regex", True)
    
    if any([sensitive_keys, redaction_value != "***REDACTED***", enable_regex != True]):
        from utils.security import DataRedactor, default_redactor
        
        new_redactor = DataRedactor(
            sensitive_keys=sensitive_keys,
            redaction_value=redaction_value,
            enable_regex=enable_regex
        )
        
        import utils.security
        utils.security.default_redactor = new_redactor
        result["redactor"] = new_redactor
        logger.info("Updated security configuration")
    
    logging_config = config.get("logging", {})
    if logging_config.get("enabled", True):
        from logging_helpers.integrations import setup_logging
        
        log_level = logging_config.get("level", "INFO")
        log_format = logging_config.get("format", "%(asctime)s [%(levelname)s] %(name)s - %(message)s [trace_id=%(otelTraceID)s span_id=%(otelSpanID)s]")
        
        setup_logging(
            level=log_level,
            format_string=log_format,
        )
        logger.info("Set up logging with trace context")
    
    if config.get("auto_instrumentation", {}).get("enabled", True):
        auto_config = config.get("auto_instrumentation", {})
        libraries = auto_config.get("libraries")
        
        result["instrumentation_results"] = auto_instrument_libraries(libraries)
    
    if config.get("class_instrumentation", {}).get("enabled", True) or enable_class_instrumentation:
        if tracer and meter:
            instrument_config = class_instrumentation_config
            if not instrument_config:
                instrument_config = config.get("class_instrumentation", {}).get("config")
            
            if not instrument_config:
                instrument_config = {
                    "instrument_classes": config.get("instrument_classes", []),
                    "ignore_classes": config.get("ignore_classes", []),
                    "modules_to_instrument": config.get("modules_to_instrument", []),
                    "packages_to_instrument": config.get("packages_to_instrument", []),
                }
            
            if not base_path:
                base_path = config.get("class_instrumentation", {}).get("base_path")
            
            class_results = instrument_selected_classes(
                tracer=tracer,
                meter=meter,
                config=instrument_config,
                base_path=base_path
            )
            
            result["class_instrumentation_results"] = class_results
            logger.info(f"Selectively instrumented {len(class_results['instrumented'])} classes")
        else:
            logger.warning("Cannot instrument classes: tracer or meter not initialized")
    
    logger.info(f"Observix bootstrap complete for service: {service_name}")
    return result


def setup_all_tracing(
    config_path: Optional[str] = "config.json",
    service_name: Optional[str] = None,
    version: Optional[str] = None,
    environment: Optional[str] = None
) -> Dict[str, Any]:
    """
    Set up all tracing components based on a config file.
    
    This is a convenience function for setting up tracing with class instrumentation
    based on a configuration file.
    
    Args:
        config_path: Path to configuration file
        service_name: Service name (overrides config)
        version: Service version (overrides config)
        environment: Environment (overrides config)
        
    Returns:
        dict: Dictionary with initialized components
    """
    try:
        # Load the config file
        with open(config_path, "r") as f:
            config = json.load(f)
            
        # Extract telemetry settings
        telemetry = config.get("telemetry", {})
        service_name = service_name or telemetry.get("service_name")
        version = version or telemetry.get("version")
        environment = environment or telemetry.get("environment")
        
        metrics_config = telemetry.get("metrics", {})
        tracing_config = telemetry.get("tracing", {})
        
        # Bootstrap with the configuration
        return bootstrap(
            service_name=service_name,
            version=version,
            environment=environment,
            enable_tracing=True,
            enable_metrics=True,
            tracing_exporters=tracing_config.get("exporters"),
            metrics_exporters=metrics_config.get("exporters"),
            enable_class_instrumentation=True,
            class_instrumentation_config=config,
        )
        
    except Exception as e:
        logger.error(f"Failed to set up tracing: {e}")
        raise


def quickstart(service_name: str) -> Dict[str, Any]:
    """
    Quick setup for Observix with minimal configuration.
    
    This function initializes Observix with sensible defaults for
    getting started quickly.
    
    Args:
        service_name: Name of the service
        
    Returns:
        dict: Dictionary with initialized components
        
    Example:
        from observix.bootstrap import quickstart
        
        quickstart("my-service")
    """
    return bootstrap(
        service_name=service_name,
        enable_tracing=True,
        enable_metrics=True,
        enable_auto_instrumentation=True,
        tracing_exporters=["console"],
        metrics_exporters=["console"],
    )


def create_exporters_from_env() -> Dict[str, Any]:
    """
    Create exporters based on environment variables.
    
    This function checks for OTEL_EXPORTER_* environment variables
    and creates appropriate exporters.
    
    Returns:
        dict: Dictionary with created exporters
    """
    exporters = {
        "trace": [],
        "metrics": [],
    }
    
    otlp_trace_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
    if otlp_trace_endpoint:
        from core.tracer import create_otlp_exporter
        headers = {}

        for key, value in os.environ.items():
            if key.startswith("OTEL_EXPORTER_OTLP_TRACES_HEADERS_"):
                header_name = key[len("OTEL_EXPORTER_OTLP_TRACES_HEADERS_"):].lower()
                headers[header_name] = value
        
        exporter = create_otlp_exporter(endpoint=otlp_trace_endpoint, headers=headers)
        exporters["trace"].append(exporter)
    
    otlp_metrics_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")
    if otlp_metrics_endpoint:
        from core.metrics import create_otlp_metric_exporter
        headers = {}
        
        for key, value in os.environ.items():
            if key.startswith("OTEL_EXPORTER_OTLP_METRICS_HEADERS_"):
                header_name = key[len("OTEL_EXPORTER_OTLP_METRICS_HEADERS_"):].lower()
                headers[header_name] = value
        
        exporter = create_otlp_metric_exporter(endpoint=otlp_metrics_endpoint, headers=headers)
        exporters["metrics"].append(exporter)
    
    return exporters


if __name__ == "__main__":
    # If run as a script, bootstrap Observix using environment variables
    import argparse
    
    parser = argparse.ArgumentParser(description="Bootstrap Observix observability")
    parser.add_argument("--service", required=True, help="Service name")
    parser.add_argument("--version", default="1.0.0", help="Service version")
    parser.add_argument("--env", default="development", help="Deployment environment")
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--no-tracing", action="store_true", help="Disable tracing")
    parser.add_argument("--no-metrics", action="store_true", help="Disable metrics")
    parser.add_argument("--no-auto", action="store_true", help="Disable auto-instrumentation")
    parser.add_argument("--instrument-classes", action="store_true", help="Enable class instrumentation")
    parser.add_argument("--class-config", help="Path to class instrumentation config")
    
    args = parser.parse_args()
    
    bootstrap(
        service_name=args.service,
        version=args.version,
        environment=args.env,
        config_path=args.config,
        enable_tracing=not args.no_tracing,
        enable_metrics=not args.no_metrics,
        enable_auto_instrumentation=not args.no_auto,
        enable_class_instrumentation=args.instrument_classes,
        class_instrumentation_config=args.class_config,
    )