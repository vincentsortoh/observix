"""
Author: Vincent Sortoh
Created on: 2025-06-27

Integrated instrumentation orchestrator for Observix.

This module provides a unified interface for instrumenting both classes and functions
based on enhanced configuration.
"""

import logging
from typing import Dict, Any, Union, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


def load_enhanced_config(config_file: str = "config.json") -> dict:
    """
    Load enhanced configuration that supports both class and function instrumentation.
    
    Args:
        config_file: Path to configuration file
        
    Returns:
        Enhanced configuration dictionary
    """
    import json
    
    with open(config_file, "r") as f:
        config = json.load(f)
    
    # Ensure backward compatibility with old config format
    config = normalize_config(config)
    
    return config


def normalize_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize configuration to ensure backward compatibility and set defaults.
    
    Args:
        config: Raw configuration dictionary
        
    Returns:
        Normalized configuration dictionary
    """
    normalized = config.copy()
    
    # Handle class instrumentation settings
    if "class_instrumentation" not in normalized:
        normalized["class_instrumentation"] = {
            "enabled": True,
            "auto_instrument_classes": True,
            "capture_args": True,
            "capture_result": True
        }
        
        # Move legacy class settings
        if "instrument_classes" in normalized:
            normalized["class_instrumentation"]["instrument_classes"] = normalized["instrument_classes"]
        if "ignore_classes" in normalized:
            normalized["class_instrumentation"]["ignore_classes"] = normalized["ignore_classes"]
    
    # Handle function instrumentation settings
    if "function_instrumentation" not in normalized:
        normalized["function_instrumentation"] = {
            "enabled": True,
            "auto_instrument_functions": False,  # Conservative default
            "capture_args": True,
            "capture_result": True,
            "include_private_functions": False
        }
    
    # Handle instrumentation options
    if "instrumentation_options" not in normalized:
        normalized["instrumentation_options"] = {
            "link_spans": False,
            "with_caller": False,
            "redact_sensitive_data": True
        }
    
    return normalized


def instrument_application(
    tracer=None,
    meter=None,
    config: Union[Dict[str, Any], str] = "config.json",
    base_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Comprehensive instrumentation of both classes and functions based on configuration.
    
    Args:
        tracer: OpenTelemetry tracer
        meter: OpenTelemetry meter
        config: Either a config dictionary or path to a config file
        base_path: Optional base path for module discovery
        
    Returns:
        Dictionary with comprehensive instrumentation results
    """
    # Load and normalize configuration
    if isinstance(config, str):
        config = load_enhanced_config(config)
    else:
        config = normalize_config(config)
    
    results = {
        "classes": {"instrumented": [], "ignored": [], "errors": []},
        "functions": {"instrumented": [], "ignored": [], "errors": []},
        "summary": {},
        "config_used": config
    }
    
    class_config = config.get("class_instrumentation", {})
    function_config = config.get("function_instrumentation", {})
    
    # Instrument classes if enabled
    if class_config.get("enabled", True):
        logger.info("Starting class instrumentation...")
        
        try:
            from class_instrumentor import instrument_selected_classes
            
            # Prepare class-specific config for backward compatibility
            class_specific_config = config.copy()
            class_specific_config.update({
                "instrument_classes": class_config.get("instrument_classes", []),
                "ignore_classes": class_config.get("ignore_classes", [])
            })
            
            class_results = instrument_selected_classes(
                tracer=tracer,
                meter=meter,
                config=class_specific_config,
                base_path=base_path
            )
            
            results["classes"] = class_results
            logger.info(f"Class instrumentation completed: {len(class_results['instrumented'])} classes instrumented")
            
        except Exception as e:
            logger.error(f"Class instrumentation failed: {e}")
            results["classes"]["errors"].append({"error": str(e), "type": "initialization"})
    
    # Instrument functions if enabled
    if function_config.get("enabled", True):
        logger.info("Starting function instrumentation...")
        
        try:
            from function_instrumentor import instrument_selected_functions
            
            # Prepare function-specific config
            function_specific_config = config.copy()
            function_specific_config.update(function_config)
            
            function_results = instrument_selected_functions(
                tracer=tracer,
                meter=meter,
                config=function_specific_config,
                base_path=base_path,
                capture_args=function_config.get("capture_args", True),
                capture_result=function_config.get("capture_result", True)
            )
            
            results["functions"] = function_results
            logger.info(f"Function instrumentation completed: {len(function_results['instrumented'])} functions instrumented")
            
        except Exception as e:
            logger.error(f"Function instrumentation failed: {e}")
            results["functions"]["errors"].append({"error": str(e), "type": "initialization"})
    
    # Generate summary
    results["summary"] = {
        "total_classes_instrumented": len(results["classes"]["instrumented"]),
        "total_functions_instrumented": len(results["functions"]["instrumented"]),
        "total_classes_ignored": len(results["classes"]["ignored"]),
        "total_functions_ignored": len(results["functions"]["ignored"]),
        "total_class_errors": len(results["classes"]["errors"]),
        "total_function_errors": len(results["functions"]["errors"]),
        "class_instrumentation_enabled": class_config.get("enabled", True),
        "function_instrumentation_enabled": function_config.get("enabled", True)
    }
    
    logger.info(f"Instrumentation summary: {results['summary']}")
    
    return results


def setup_observix(
    service_name: str,
    config_file: str = "config.json",
    version: str = "1.0.0",
    environment: str = "development",
    base_path: Optional[str] = None,
    initialize_telemetry: bool = True
) -> Dict[str, Any]:
    """
    Complete Observix setup with tracing, metrics, logging, and instrumentation.
    
    Args:
        service_name: Name of the service
        config_file: Path to configuration file
        version: Service version
        environment: Deployment environment
        base_path: Optional base path for module discovery
        initialize_telemetry: Whether to initialize telemetry systems
        
    Returns:
        Dictionary with setup results and initialized components
    """
    logger.info(f"Setting up Observix for service: {service_name}")
    
    # Load configuration
    config = load_enhanced_config(config_file)
    
    tracer = None
    meter = None
    telemetry_setup = {}
    
    if initialize_telemetry:
        try:
            # Initialize tracing and logging
            from core.tracer import init_tracing_and_logging
            from core.metrics import init_metrics
            
            tracing_config = config.get("tracing", {})
            metrics_config = config.get("metrics", {})
            logging_config = config.get("logging", {})
            
            # Set up tracing and logging
            if tracing_config.get("enabled", True) or logging_config.get("enabled", True):
                telemetry_setup = init_tracing_and_logging(
                    service_name=service_name,
                    version=version,
                    environment=environment,
                    tracing_exporters=tracing_config.get("exporters", ["console"]),
                    logging_exporters=logging_config.get("exporters", ["console"]),
                    exporter_endpoints=tracing_config.get("exporter_endpoints", {}),
                    log_level=logging_config.get("level", "INFO"),
                    capture_print=logging_config.get("capture_print", True),
                    enable_loguru=logging_config.get("enable_loguru", True),
                    attach_logs_to_spans=logging_config.get("attach_logs_to_spans", True)
                )
                tracer = telemetry_setup.get("tracer")
            
            # Set up metrics
            if metrics_config.get("enabled", True):
                meter = init_metrics(
                    service_name=service_name,
                    version=version,
                    environment=environment,
                    exporters=metrics_config.get("exporters", ["console"]),
                    export_interval_millis=metrics_config.get("export_interval_millis", 5000),
                    exporter_endpoints=metrics_config.get("exporter_endpoints", {})
                )
            
            logger.info("Telemetry initialization completed")
            
        except Exception as e:
            logger.error(f"Telemetry initialization failed: {e}")
            telemetry_setup["error"] = str(e)
    
    # Perform instrumentation
    instrumentation_results = instrument_application(
        tracer=tracer,
        meter=meter,
        config=config,
        base_path=base_path
    )
    
    setup_results = {
        "service_name": service_name,
        "version": version,
        "environment": environment,
        "telemetry": telemetry_setup,
        "instrumentation": instrumentation_results,
        "tracer": tracer,
        "meter": meter,
        "config": config
    }
    
    logger.info("Observix setup completed successfully")
    
    return setup_results


def quick_setup(
    service_name: str,
    modules: list = None,
    auto_instrument_classes: bool = True,
    auto_instrument_functions: bool = False,
    exporters: list = None
) -> Dict[str, Any]:
    """
    Quick setup for simple use cases without a configuration file.
    
    Args:
        service_name: Name of the service
        modules: List of modules to instrument
        auto_instrument_classes: Whether to auto-instrument all classes
        auto_instrument_functions: Whether to auto-instrument all functions
        exporters: List of exporters to use
        
    Returns:
        Setup results
    """
    # Create minimal configuration
    config = {
        "modules_to_instrument": modules or [],
        "class_instrumentation": {
            "enabled": True,
            "auto_instrument_classes": auto_instrument_classes,
            "capture_args": True,
            "capture_result": True
        },
        "function_instrumentation": {
            "enabled": True,
            "auto_instrument_functions": auto_instrument_functions,
            "capture_args": True,
            "capture_result": True
        },
        "tracing": {
            "enabled": True,
            "exporters": exporters or ["console"]
        },
        "metrics": {
            "enabled": True,
            "exporters": exporters or ["console"]
        },
        "logging": {
            "enabled": True,
            "level": "INFO",
            "capture_print": True
        }
    }
    
    return setup_observix(
        service_name=service_name,
        config_file=None,
        initialize_telemetry=True
    )


# Convenience function for backward compatibility
def instrument_selected_classes_and_functions(
    tracer=None,
    meter=None,
    config: Union[Dict[str, Any], str] = "config.json",
    base_path: Optional[str] = None
):
    """
    Backward compatible function that instruments both classes and functions.
    
    This is an alias for instrument_application for backward compatibility.
    """
    return instrument_application(tracer, meter, config, base_path)
