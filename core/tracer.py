"""
Author: Vincent Sortoh
Created on: 2025-05-10
Tracer module for Observix.

This module provides functions for initializing and accessing OpenTelemetry tracers.
"""

import logging
from typing import Dict
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor, BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource


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
    
    Returns:
        Tracer: The initialized OpenTelemetry tracer.
    """
    global _tracer, _initialized
    
    if _initialized and not force_reinit:
        logging.info("Tracing already initialized. Returning existing tracer.")
        return _tracer
    
    resource = Resource.create({
        "service.name": service_name,
        "service.version": version,
        "deployment.environment": environment,
    })
    
    provider = TracerProvider(resource=resource)
    trace.set_tracer_provider(provider)
    
    if exporters is None:
        exporters = [ConsoleSpanExporter()]
    
    for exporter_name in exporters:
        # print(exporter_name, 89900)
        # span_processor = SimpleSpanProcessor(exporter_name)
        # provider.add_span_processor(span_processor)

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