"""
Author: Vincent Sortoh
Created on: 2025-05-10
Enhanced tracer module for Observix with integrated log export support.

This module provides functions for initializing and accessing OpenTelemetry tracers
and log exporters together.
"""

import logging
from typing import Dict, Optional, List
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor, BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource

# Import the new log exporter module
from core.log_exporter import init_log_export, setup_log_capture_with_export, get_log_provider

try:
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    OTLP_AVAILABLE = True
except ImportError:
    OTLP_AVAILABLE = False

try:
    from opentelemetry.exporter.jaeger.thrift import JaegerExporter
    JAEGER_AVAILABLE = True
except ImportError:
    JAEGER_AVAILABLE = False

try:
    from opentelemetry.exporter.zipkin.json import ZipkinExporter
    ZIPKIN_AVAILABLE = True
except ImportError:
    ZIPKIN_AVAILABLE = False

logger = logging.getLogger(__name__)

_tracer = None
_initialized = False

def get_tracer():
    """
    Get the current tracer instance.
    
    Returns:
        Tracer: The current OpenTelemetry tracer instance.
    """
    global _tracer
    if _tracer is None:
        raise RuntimeError("Tracer has not been initialized. Call init_tracing() first.")
    return _tracer

def init_tracing(
    service_name: str,
    version: str = "1.0.0",
    environment: str = "dev",
    exporters=None,
    force_reinit: bool = False,
    exporter_endpoints: Dict[str, str] = None,
    additional_attributes: Dict[str, str] = None
):
    """
    Initialize OpenTelemetry tracing.
    
    Args:
        service_name (str): Name of the service (required).
        version (str): Service version.
        environment (str): Deployment environment.
        exporters (list): List of exporters. Default is [ConsoleSpanExporter()].
        force_reinit (bool): Force reinitialization if already initialized.
        exporter_endpoints (dict): Endpoints for various exporters.
        additional_attributes (dict): Additional resource attributes.
    
    Returns:
        Tracer: The initialized OpenTelemetry tracer.
    """
    global _tracer, _initialized
    
    if _initialized and not force_reinit:
        logging.info("Tracing already initialized. Returning existing tracer.")
        return _tracer
    
    # Create resource attributes
    resource_attrs = {
        "service.name": service_name,
        "service.version": version,
        "deployment.environment": environment,
    }
    
    if additional_attributes:
        resource_attrs.update(additional_attributes)
    
    resource = Resource.create(resource_attrs)
    
    provider = TracerProvider(resource=resource)
    trace.set_tracer_provider(provider)
    
    if exporters is None:
        exporters = ["console"]
    
    if exporter_endpoints is None:
        exporter_endpoints = {}
    
    for exporter_name in exporters:
        if exporter_name.lower() == "console":
            provider.add_span_processor(
                BatchSpanProcessor(ConsoleSpanExporter())
            )
            logger.info("Added console span exporter")
            
        elif exporter_name.lower() == "otlp" and OTLP_AVAILABLE:
            endpoint = exporter_endpoints.get("otlp", "http://localhost:4317")
            provider.add_span_processor(
                BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint))
            )
            logger.info(f"Added OTLP span exporter with endpoint {endpoint}")
            
        elif exporter_name.lower() == "jaeger" and JAEGER_AVAILABLE:
            endpoint = exporter_endpoints.get("jaeger", "http://localhost:14268/api/traces")
            provider.add_span_processor(
                BatchSpanProcessor(JaegerExporter(collector_endpoint=endpoint))
            )
            logger.info(f"Added Jaeger span exporter with endpoint {endpoint}")
            
        elif exporter_name.lower() == "zipkin" and ZIPKIN_AVAILABLE:
            endpoint = exporter_endpoints.get("zipkin", "http://localhost:9411/api/v2/spans")
            provider.add_span_processor(
                BatchSpanProcessor(ZipkinExporter(endpoint=endpoint))
            )
            logger.info(f"Added Zipkin span exporter with endpoint {endpoint}")
            
        else:
            if exporter_name not in ["console", "otlp", "jaeger", "zipkin"]:
                logger.warning(f"Unknown exporter: {exporter_name}")
            else:
                logger.warning(f"Exporter {exporter_name} is not available. Install the appropriate package.")
    
    _tracer = trace.get_tracer(__name__)
    _initialized = True
    
    logging.info(f"Tracing initialized for service: {service_name}")
    return _tracer

def init_tracing_and_logging(
    service_name: str,
    version: str = "1.0.0",
    environment: str = "dev",
    tracing_exporters: Optional[List[str]] = None,
    logging_exporters: Optional[List[str]] = None,
    exporter_endpoints: Optional[Dict[str, str]] = None,
    force_reinit: bool = False,
    log_level: str = "INFO",
    attach_logs_to_spans: bool = True,
    capture_print: bool = True,
    configure_loggers: Optional[List[str]] = None,
    enable_loguru: bool = True,
    loguru_bridge_to_std: bool = True,
    additional_attributes: Optional[Dict[str, str]] = None
) -> Dict[str, any]:
    """
    Initialize both OpenTelemetry tracing and logging together.
    
    Args:
        service_name: Name of the service
        version: Service version
        environment: Deployment environment
        tracing_exporters: List of tracing exporters
        logging_exporters: List of logging exporters
        exporter_endpoints: Endpoints for various exporters
        force_reinit: Force reinitialization if already initialized
        log_level: Logging level
        attach_logs_to_spans: Whether to attach logs to spans as events
        capture_print: Whether to capture print statements
        configure_loggers: List of logger names to configure
        enable_loguru: Whether to enable loguru integration
        loguru_bridge_to_std: Whether to bridge loguru to standard logging
        additional_attributes: Additional resource attributes
    
    Returns:
        dict: Dictionary containing tracer, log_provider, and configuration results
    """
    tracer = init_tracing(
        service_name=service_name,
        version=version,
        environment=environment,
        exporters=tracing_exporters,
        force_reinit=force_reinit,
        exporter_endpoints=exporter_endpoints,
        additional_attributes=additional_attributes
    )
    
    log_config = setup_log_capture_with_export(
        service_name=service_name,
        version=version,
        environment=environment,
        exporters=logging_exporters,
        exporter_endpoints=exporter_endpoints,
        level=log_level,
        attach_to_spans=attach_logs_to_spans,
        capture_print=capture_print,
        loggers=configure_loggers,
        enable_loguru=enable_loguru,
        loguru_bridge_to_std=loguru_bridge_to_std
    )
    
    result = {
        "tracer": tracer,
        "log_provider": log_config["log_provider"],
        "log_handler": log_config["handler"],
        "configured_loggers": log_config["configured_loggers"],
        "loguru_enabled": log_config["loguru_enabled"],
        "span_attachment_enabled": log_config["span_attachment_enabled"],
        "log_exporters": log_config["exporters"],
        "tracing_exporters": tracing_exporters or ["console"]
    }
    
    logger.info(f"Initialized tracing and logging for service: {service_name}")
    return result

def create_otlp_exporter(endpoint=None, headers=None):
    """
    Create an OTLP exporter for tracing.
    
    Args:
        endpoint (str): The OTLP endpoint URL.
        headers (dict): Headers to include with OTLP requests.
    
    Returns:
        OTLPSpanExporter: An OTLP exporter instance.
    """
    kwargs = {}
    if endpoint:
        kwargs["endpoint"] = endpoint
    if headers:
        kwargs["headers"] = headers
    
    return OTLPSpanExporter(**kwargs)