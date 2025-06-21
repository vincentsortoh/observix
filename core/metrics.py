"""
Author: Vincent Sortoh
Created on: 2025-rt-10

Metrics module for Observix.
This module provides functions for initializing and accessing OpenTelemetry metrics.
"""

import logging
from typing import Dict
from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.metrics.export import ConsoleMetricExporter, PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource

try:
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
    OTLP_AVAILABLE = True
except ImportError:
    OTLP_AVAILABLE = False


try:
    from opentelemetry.exporter.prometheus import PrometheusMetricExporter
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

_meter = None

def get_meter():
    """
    Get the current meter instance.
    
    Returns:
        Meter: The current OpenTelemetry meter instance.
    """
    global _meter
    if _meter is None:
        raise RuntimeError("Metrics have not been initialized. Call init_metrics() first.")
    return _meter

def init_metrics(
    service_name: str,
    version: str = "1.0.0",
    environment: str = "dev",
    exporters: list = None,
    export_interval_millis: int = 1000,
    force_reinit: bool = False,
    exporter_endpoints: Dict[str, str] = None,
    additional_attributes: Dict[str, str] = None,

):
    """
    Initialize OpenTelemetry metrics pipeline.
    
    Args:
        service_name (str): Your service name.
        version (str): Service version.
        environment (str): Deployment environment.
        exporters (list): List of exporters. Options: "console", "otlp".
        export_interval_millis (int): Export interval in milliseconds.
        force_reinit (bool): Force reinitialization if already initialized.
    
    Returns:
        Meter: The initialized OpenTelemetry meter.
    """
    global _meter
    
    if _meter is not None and not force_reinit:
        logging.info("Metrics already initialized. Returning existing meter.")
        return _meter
    
    exporters = exporters or ["console"]
    
    resource = Resource.create({
        "service.name": service_name,
        "service.version": version,
        "deployment.environment": environment,
    })
    
    metric_readers = []
    for exporter_name in exporters:
        if exporter_name == "console":
            reader = PeriodicExportingMetricReader(
                exporter=ConsoleMetricExporter(),
                export_interval_millis=export_interval_millis,
            )
            metric_readers.append(reader)
        elif exporter_name == "otlp":
            reader = PeriodicExportingMetricReader(
                exporter=OTLPMetricExporter(),
                export_interval_millis=export_interval_millis,
            )
            metric_readers.append(reader)
        elif exporter_name.lower() == "otlp" and OTLP_AVAILABLE:
            endpoint = exporter_endpoints.get("otlp", "http://localhost:4317")
            otlp_reader = PeriodicExportingMetricReader(
                OTLPMetricExporter(endpoint=endpoint),
                export_interval_millis=export_interval_millis
            )
            metric_readers.append(otlp_reader)
            logging.info(f"Added OTLP metric exporter with endpoint {endpoint}")
            
        elif exporter_name.lower() == "prometheus" and PROMETHEUS_AVAILABLE:
            # Prometheus typically uses pull-based collection, so no interval is needed
            prometheus_port = int(exporter_endpoints.get("prometheus", "9464"))
            prometheus_exporter = PrometheusMetricExporter(port=prometheus_port)
            metric_readers.append(prometheus_exporter)
            logging.info(f"Added Prometheus metric exporter on port {prometheus_port}")
            
        else:
            if exporter_name not in ["console", "otlp", "prometheus"]:
                logging.warning(f"Unknown exporter: {exporter_name}")
            else:
                logging.warning(f"Exporter {exporter_name} is not available. Install the appropriate package.")
    
    
    provider = MeterProvider(
        resource=resource,
        metric_readers=metric_readers
    )
    metrics.set_meter_provider(provider)
    
    _meter = metrics.get_meter_provider().get_meter(__name__)
    
    logging.info(f"Metrics initialized for service: {service_name}")
    
    return _meter

def create_otlp_metric_exporter(endpoint=None, headers=None):
    """
    Create an OTLP exporter for metrics.
    
    Args:
        endpoint (str): The OTLP endpoint URL.
        headers (dict): Headers to include with OTLP requests.
    
    Returns:
        OTLPMetricExporter: An OTLP exporter instance.
    """
    kwargs = {}
    if endpoint:
        kwargs["endpoint"] = endpoint
    if headers:
        kwargs["headers"] = headers
    
    return OTLPMetricExporter(**kwargs)