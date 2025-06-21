"""
Author: Vincent Sortoh
Created on: 2025-05-11
Modified: 2025-06-21

Description: Enhanced bootstrap.py with integrated log export functionality
"""

import json
import logging
import os
from typing import Dict, Any, Optional, List, Union

from core.tracer import init_tracing, init_tracing_and_logging
from core.metrics import init_metrics
from auto.instrumentor import auto_instrument_libraries
from core.class_instrumentor import instrument_selected_classes, load_config as load_instrument_config
from utils.security import DataRedactor
from config.loader import load_config, find_and_load_config
from core.log_exporter import setup_log_capture_with_export

logger = logging.getLogger(__name__)


def bootstrap(
    service_name: Optional[str] = None,
    version: Optional[str] = None,
    environment: Optional[str] = None,
    config_path: Optional[str] = None,
    enable_tracing: bool = True,
    enable_metrics: bool = True,
    enable_logging: bool = True,
    enable_log_export: bool = True,
    enable_auto_instrumentation: bool = True,
    auto_instrument_libs: Optional[List[str]] = None,
    tracing_exporters: Optional[List[str]] = None,
    logging_exporters: Optional[List[str]] = None,
    metrics_exporters: Optional[List[str]] = None,
    metrics_interval_ms: int = 30000,
    sensitive_keys: Optional[List[str]] = None,
    env_prefix: str = "OBSERVIX_",
    merge_env: bool = True,
    logging_config: Optional[Union[str, Dict[str, Any]]] = None,
    enable_class_instrumentation: bool = False,
    class_instrumentation_config: Optional[Union[str, Dict[str, Any]]] = None,
    base_path: Optional[str] = None,
    enable_loguru: bool = True,
    loguru_bridge_to_std: bool = True,
    attach_logs_to_spans: bool = True,
    capture_print: bool = True,
    log_level: str = "INFO"
) -> Dict[str, Any]:
    """
    Bootstrap the entire Observix observability stack with integrated log export.
    
    This function initializes tracing, metrics, logging with export capabilities,
    and auto-instrumentation based on the provided configuration or configuration file.
    
    Args:
        service_name: Name of the service
        version: Service version
        environment: Deployment environment (dev, staging, prod, etc.)
        config_path: Path to configuration file
        enable_tracing: Whether to enable tracing
        enable_metrics: Whether to enable metrics
        enable_logging: Whether to enable standard logging
        enable_log_export: Whether to enable log export to configured destinations
        enable_auto_instrumentation: Whether to enable auto-instrumentation
        auto_instrument_libs: List of libraries to auto-instrument
        tracing_exporters: List of tracing exporters
        logging_exporters: List of logging exporters
        metrics_exporters: List of metrics exporters
        metrics_interval_ms: Metrics export interval in milliseconds
        sensitive_keys: List of sensitive keys to redact
        env_prefix: Prefix for environment variables
        merge_env: Whether to merge environment variables
        enable_class_instrumentation: Whether to enable selective class instrumentation
        class_instrumentation_config: Configuration for class instrumentation (path or dict)
        base_path: Base path for module discovery in class instrumentation
        enable_loguru: Whether to enable loguru integration
        loguru_bridge_to_std: Whether to bridge loguru to standard logging for span capture
        attach_logs_to_spans: Whether to attach logs to spans as events
        capture_print: Whether to capture print statements
        log_level: Logging level
        
    Returns:
        dict: Dictionary with initialized components
        
    Example:
        # Basic usage with log export
        from observix.bootstrap import bootstrap
        
        bootstrap(
            service_name="my-service", 
            enable_log_export=True,
            logging_exporters=["console", "otlp"]
        )
        
        # Advanced usage with configuration
        bootstrap(
            service_name="my-service",
            version="1.2.3",
            environment="production",
            enable_tracing=True,
            enable_metrics=True,
            enable_loguru=True,
            enable_log_export=True,
            tracing_exporters=["console", "otlp"],
            logging_exporters=["console", "otlp"],
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
    
    # Handle logging and log export configuration
    if enable_logging is not None:
        config.setdefault("logging", {})["enabled"] = enable_logging
    if enable_log_export is not None:
        config.setdefault("logging", {})["export_enabled"] = enable_log_export
    if logging_exporters:
        config.setdefault("logging", {})["exporters"] = logging_exporters
    if attach_logs_to_spans is not None:
        config.setdefault("logging", {})["attach_to_spans"] = attach_logs_to_spans
    
    # Handle loguru configuration
    if enable_loguru is not None:
        config.setdefault("logging", {}).setdefault("loguru", {})["enabled"] = enable_loguru
    if loguru_bridge_to_std is not None:
        config.setdefault("logging", {}).setdefault("loguru", {})["bridge_to_std"] = loguru_bridge_to_std

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
    
    # Enhanced logging configuration with export support
    logging_config_dict = config.get("logging", {})
    if logging_config_dict.get("enabled", True):
        log_export_enabled = logging_config_dict.get("export_enabled", enable_log_export)
        if log_export_enabled:
            integrated_config = init_tracing_and_logging(
                service_name=service_name,
                version=service_version,
                environment=service_env,
                tracing_exporters=config.get("tracing", {}).get("exporters", tracing_exporters),
                logging_exporters=logging_config_dict.get("exporters", logging_exporters),
                exporter_endpoints=config.get("exporter_endpoints", {}),
                log_level=logging_config_dict.get("level", log_level),
                attach_logs_to_spans=logging_config_dict.get("attach_to_spans", attach_logs_to_spans),
                capture_print=logging_config_dict.get("capture_print", capture_print),
                configure_loggers=logging_config_dict.get("loggers"),
                enable_loguru=logging_config_dict.get("loguru", {}).get("enabled", enable_loguru),
                loguru_bridge_to_std=logging_config_dict.get("loguru", {}).get("bridge_to_std", loguru_bridge_to_std)
            )
            
            result.update({
                "tracer": integrated_config["tracer"],
                "log_provider": integrated_config["log_provider"],
                "log_handler": integrated_config["log_handler"],
                "configured_loggers": integrated_config["configured_loggers"],
                "loguru_enabled": integrated_config["loguru_enabled"],
                "span_attachment_enabled": integrated_config["span_attachment_enabled"],
                "log_exporters": integrated_config["log_exporters"],
                "tracing_exporters": integrated_config["tracing_exporters"]
            })
            
            logger.info(f"Initialized integrated tracing and logging with export for service: {service_name}")
        else:
            # Initialize tracing only
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
            
            # Set up standard logging without export
            from logging_helpers.integrations import setup_logging
            
            log_level_str = logging_config_dict.get("level", log_level)
            log_format = logging_config_dict.get("format", "%(asctime)s [%(levelname)s] %(name)s - %(message)s [trace_id=%(otelTraceID)s span_id=%(otelSpanID)s]")
            use_async_handler = logging_config_dict.get("use_async_handler", True)
            loggers = logging_config_dict.get("loggers", None)
            
            # Set up standard logging

            setup_logging(
                level=log_level_str,
                format_string=log_format,
                use_async_handler=use_async_handler,
                loggers=loggers
            )
                        
            # Handle loguru integration
            loguru_config = logging_config_dict.get("loguru", {})
            if loguru_config.get("enabled", enable_loguru):
                from logging_helpers.integrations import setup_loguru_with_trace_context, bridge_loguru_to_std_logging
                
                json_logs = logging_config_dict.get("json_format", False)
                bridge_to_std = loguru_config.get("bridge_to_std", loguru_bridge_to_std)
                
                if bridge_to_std:
                    # Bridge loguru to standard logging so spans can capture loguru logs
                    bridge_loguru_to_std_logging()
                    logger.info("Bridged loguru to standard logging for span capture")
                else:
                    # Configure loguru directly with trace context
                    setup_loguru_with_trace_context(json_logs=json_logs)
                    logger.info("Set up loguru with direct trace context")
                
                result["loguru_enabled"] = True
    else:
        # Initialize tracing only if logging is disabled
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
    
    # Initialize metrics
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
    
    # Security configuration
    security_config = config.get("security", {})
    sensitive_keys_config = security_config.get("sensitive_keys")
    redaction_value = security_config.get("redaction_value", "***REDACTED***")
    enable_regex = security_config.get("enable_regex", True)
    
    if any([sensitive_keys_config, redaction_value != "***REDACTED***", enable_regex != True]):
        from utils.security import DataRedactor, default_redactor
        
        new_redactor = DataRedactor(
            sensitive_keys=sensitive_keys_config,
            redaction_value=redaction_value,
            enable_regex=enable_regex
        )
        
        import utils.security
        utils.security.default_redactor = new_redactor
        result["redactor"] = new_redactor
        logger.info("Updated security configuration")
    
    # Auto-instrumentation
    if config.get("auto_instrumentation", {}).get("enabled", True):
        auto_config = config.get("auto_instrumentation", {})
        libraries = auto_config.get("libraries")
        
        
        result["instrumentation_results"] = auto_instrument_libraries(libraries)
    
    # Class instrumentation
    if config.get("class_instrumentation", {}).get("enabled", True) or enable_class_instrumentation:
        tracer = result.get("tracer")
        meter = result.get("meter")
        
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
    environment: Optional[str] = None,
    enable_loguru: bool = True,
    loguru_bridge_to_std: bool = True,
    enable_log_export: bool = True
) -> Dict[str, Any]:
    """
    Set up all tracing components based on a config file.
    
    This is a convenience function for setting up tracing with class instrumentation,
    loguru integration, and exitlog export based on a configuration file.
    
    Args:
        config_path: Path to configuration file
        service_name: Service name (overrides config)
        version: Service version (overrides config)
        environment: Environment (overrides config)
        enable_loguru: Whether to enable loguru integration
        loguru_bridge_to_std: Whether to bridge loguru to standard logging
        enable_log_export: Whether to enable log export
        
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
        logging_config = telemetry.get("logging", {})

        print(logging_config, 8899003)

        # Bootstrap with the configuration including loguru and log export
        return bootstrap(
            config_path=config_path,
            service_name=service_name,
            version=version,
            environment=environment,
            enable_tracing=True,
            enable_metrics=True,
            enable_logging=True,
            enable_log_export=enable_log_export,
            enable_loguru=enable_loguru,
            loguru_bridge_to_std=loguru_bridge_to_std,
            tracing_exporters=tracing_config.get("exporters"),
            logging_exporters=logging_config.get("exporters"),
            metrics_exporters=metrics_config.get("exporters"),
            enable_class_instrumentation=True,
            class_instrumentation_config=config,
        )
        
    except Exception as e:
        logger.error(f"Failed to set up tracing: {e}")
        raise


def quickstart(
    service_name: str, 
    enable_loguru: bool = True, 
    enable_log_export: bool = True,
    logging_exporters: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Quick setup for Observix with minimal configuration.
    
    This function initializes Observix with sensible defaults for
    getting started quickly, including loguru support and log export.
    
    Args:
        service_name: Name of the service
        enable_loguru: Whether to enable loguru integration
        enable_log_export: Whether to enable log export functionality
        logging_exporters: List of logging exporters to use
        
    Returns:
        dict: Dictionary with initialized components
        
    Example:
        from observix.bootstrap import quickstart
        
        quickstart("my-service", enable_loguru=True, enable_log_export=True)
    """
    if logging_exporters is None:
        logging_exporters = ["console"]
    
    return bootstrap(
        service_name=service_name,
        enable_tracing=True,
        enable_metrics=True,
        enable_logging=True,
        enable_log_export=enable_log_export,
        enable_auto_instrumentation=True,
        enable_loguru=enable_loguru,
        loguru_bridge_to_std=True,
        tracing_exporters=["console"],
        logging_exporters=logging_exporters,
        metrics_exporters=["console"],
    )


def bootstrap_with_log_export_only(
    service_name: str,
    version: str = "1.0.0",
    environment: str = "dev",
    logging_exporters: Optional[List[str]] = None,
    log_level: str = "INFO",
    attach_logs_to_spans: bool = False,
    capture_print: bool = True,
    enable_loguru: bool = True,
    loguru_bridge_to_std: bool = True
) -> Dict[str, Any]:
    """
    Bootstrap only log export functionality without tracing or metrics.
    
    This is useful when you only want to export logs to external systems
    without the full observability stack.
    
    Args:
        service_name: Name of the service
        version: Service version
        environment: Deployment environment
        logging_exporters: List of logging exporters
        log_level: Logging level
        attach_logs_to_spans: Whether to attach logs to spans (requires tracing)
        capture_print: Whether to capture print statements
        enable_loguru: Whether to enable loguru integration
        loguru_bridge_to_std: Whether to bridge loguru to standard logging
        
    Returns:
        dict: Dictionary with log export configuration
    """
    if logging_exporters is None:
        logging_exporters = ["console"]
    
    # Set up log capture and export
    log_config = setup_log_capture_with_export(
        service_name=service_name,
        version=version,
        environment=environment,
        exporters=logging_exporters,
        level=log_level,
        attach_to_spans=attach_logs_to_spans,
        capture_print=capture_print,
        enable_loguru=enable_loguru,
        loguru_bridge_to_std=loguru_bridge_to_std
    )
    
    result = {
        "service": {
            "name": service_name,
            "version": version,
            "environment": environment
        },
        "log_provider": log_config["log_provider"],
        "log_handler": log_config["handler"],
        "configured_loggers": log_config["configured_loggers"],
        "loguru_enabled": log_config["loguru_enabled"],
        "span_attachment_enabled": log_config["span_attachment_enabled"],
        "log_exporters": log_config["exporters"]
    }
    
    logger.info(f"Log export only bootstrap complete for service: {service_name}")
    return result