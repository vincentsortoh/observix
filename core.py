"""
Core OpenTelemetry instrumentation functionality for Observix.

This module provides the core functionality for OpenTelemetry instrumentation,
including tracing, metrics, and utilities for redacting sensitive data.
"""

import sys
import time
import json
import importlib
import importlib.util
import subprocess
import asyncio
import logging
from functools import wraps
from typing import Any, Dict, Set, List, Optional, Callable, Union

from opentelemetry.trace import Link, StatusCode
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry import trace, metrics, context
from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.metrics.export import ConsoleMetricExporter
from opentelemetry.sdk.resources import Resource

from .auto_libraries import INSTRUMENTATION_MAP

# Global variables
_initialized = False
_initialized_meter = None

# Constants
SENSITIVE_KEYS = {"password", "passwd", "token", "secret", "api_key", "authorization", "ssn"}


def is_module_available(name: str) -> bool:
    """Check if a module is available in the current Python environment."""
    return importlib.util.find_spec(name) is not None


def install_if_missing(pip_pkg: str) -> None:
    """Install a package if it's not already installed."""
    subprocess.check_call([sys.executable, "-m", "pip", "install", pip_pkg])


def try_instrument(lib: str) -> None:
    """Attempt to instrument a library with OpenTelemetry."""
    module_path, pip_pkg, class_name = INSTRUMENTATION_MAP[lib]
    if not is_module_available(module_path):
        install_if_missing(pip_pkg)

    try:
        mod = importlib.import_module(module_path)
        instrumentor_class = getattr(mod, class_name)
        instrumentor_class().instrument()
        logging.info(f"[otel] Instrumented: {lib}")
    except Exception as e:
        logging.warning(f"[otel] Failed to instrument {lib}: {e}")


def auto_instrument_libraries() -> None:
    """Automatically instrument libraries that are installed in the environment."""
    for lib in INSTRUMENTATION_MAP:
        if is_module_available(lib):
            try_instrument(lib)
        else:
            logging.info(f"[otel] Skipping {lib} — not installed in environment")


def redact_sensitive_data(key: str, value: Any) -> str:
    """Redact the value if the key is considered sensitive."""
    if any(sensitive in key.lower() for sensitive in SENSITIVE_KEYS):
        return "***"
    return str(value)


def redact_json(data: Any, sensitive_keys: Set[str] = SENSITIVE_KEYS) -> Any:
    """
    Recursively redact sensitive keys from a nested JSON-like structure.
    
    Args:
        data: The data structure to redact
        sensitive_keys: Set of keys to consider sensitive
        
    Returns:
        Redacted data structure
    """
    if isinstance(data, dict):
        return {
            k: (
                "REDACTED"
                if k.lower() in sensitive_keys
                else redact_json(v, sensitive_keys)
            )
            for k, v in data.items()
        }
    elif isinstance(data, list):
        return [redact_json(item, sensitive_keys) for item in data]
    else:
        return data


def init_metrics(
    service_name: str,
    version: str = "1.0.0",
    environment: str = "dev",
    exporters: Optional[List[str]] = None,
    export_interval_millis: int = 1000
) -> Any:
    """
    Initialize OpenTelemetry metrics pipeline with singleton pattern.
    
    Args:
        service_name: Your service name
        version: Service version
        environment: Deployment environment
        exporters: List of exporters. Options: "console", "otlp"
        export_interval_millis: Export interval in milliseconds
        
    Returns:
        OpenTelemetry meter instance
    """
    global _initialized_meter
    
    if _initialized_meter:
        logging.info("Metrics already initialized. Returning the existing meter.")
        return _initialized_meter
    
    exporters = exporters or ["console"]

    resource = Resource.create({
        "service.name": service_name,
        "service.version": version,
        "deployment.environment": environment,
    })

    # Setup metric readers based on configured exporters
    metric_readers = []
    for exp in exporters:
        if exp == "console":
            reader = PeriodicExportingMetricReader(
                exporter=ConsoleMetricExporter(),
                export_interval_millis=export_interval_millis,
            )
            metric_readers.append(reader)
        elif exp == "otlp":
            reader = PeriodicExportingMetricReader(
                exporter=OTLPMetricExporter(),
                export_interval_millis=export_interval_millis,
            )
            metric_readers.append(reader)
        else:
            logging.warning(f"Unsupported exporter: {exp}")

    provider = MeterProvider(
        resource=resource,
        metric_readers=metric_readers
    )
    metrics.set_meter_provider(provider)

    meter = metrics.get_meter_provider().get_meter(__name__)
    _initialized_meter = meter

    logging.info("Metrics initialized successfully.")
    return meter


def init_tracing(
    service_name: str, 
    version: str = "1.0.0", 
    environment: str = "dev", 
    exporters: Optional[List] = None
) -> Any:
    """
    Initialize OpenTelemetry tracing only if not already initialized.
    
    Args:
        service_name: Name of the service
        version: App version
        environment: Deployment environment
        exporters: List of span exporters
        
    Returns:
        OpenTelemetry tracer instance
    """
    # Check if a TracerProvider is already set
    if isinstance(trace.get_tracer_provider(), TracerProvider):
        return trace.get_tracer(__name__)

    # Create resource with service information
    resource = Resource.create({
        "service.name": service_name,
        "service.version": version,
        "deployment.environment": environment,
    })

    # Set up tracer provider
    provider = TracerProvider(resource=resource)
    trace.set_tracer_provider(provider)

    # Configure exporters
    if exporters is None:
        exporters = [ConsoleSpanExporter()]

    # Add exporters to the provider
    for exporter in exporters:
        span_processor = SimpleSpanProcessor(exporter)
        trace.get_tracer_provider().add_span_processor(span_processor)

    # Get and return a tracer
    return trace.get_tracer(__name__)


def instrument_class(
    tracer=None, 
    meter=None, 
    ignore_methods=None, 
    link_span=False
):
    """
    Decorator to instrument a class with OpenTelemetry tracing and metrics.
    
    Args:
        tracer: OpenTelemetry tracer instance (required)
        meter: OpenTelemetry meter instance (required)
        ignore_methods: List of method names to ignore for instrumentation
        link_span: Whether to link spans with parent spans
        
    Returns:
        Decorated class with instrumentation
    """
    if tracer is None:
        raise ValueError("A tracer instance must be provided")
    
    if meter is None:
        raise ValueError("A meter instance must be provided")
    
    ignore_methods = set(ignore_methods or [])

    def decorator(cls):
        for attr_name in dir(cls):
            # Skip magic methods and ignored methods
            if attr_name.startswith("__") or attr_name in ignore_methods:
                continue

            attr = getattr(cls, attr_name)
            is_static = isinstance(attr, staticmethod)
            is_class = isinstance(attr, classmethod)
            func = attr.__func__ if (is_static or is_class) else attr

            # Skip non-callable attributes and methods marked with @no_trace
            if not callable(func) or getattr(func, "_no_trace", False):
                continue

            # Get span attributes if any were defined
            span_attrs = getattr(func, "_otel_span_attrs", {})

            # Handle async methods
            if asyncio.iscoroutinefunction(func):
                @wraps(func)
                async def async_wrapper(*args, __func=func, __span_attrs=span_attrs, **kwargs):
                    # Create links to parent spans if requested
                    links = []
                    if link_span:
                        current_span = trace.get_current_span()
                        if current_span.is_active():
                            links.append(Link(current_span.get_span_context()))

                    method_name = __func.__qualname__
                    ctx = context.get_current()

                    # Start a new span for this method
                    with tracer.start_as_current_span(method_name, context=ctx, links=links) as span:
                        start_time = time.time_ns()

                        # Record trace and span IDs
                        trace_id_hex = f"0x{span.context.trace_id:x}"
                        span_id_hex = f"0x{span.context.span_id:x}"

                        span.set_attribute("trace_id", trace_id_hex)
                        span.set_attribute("span_id", span_id_hex)

                        # Record custom span attributes with sensitive data redaction
                        for key, val in __span_attrs.items():
                            try:
                                actual_val = val(*args, **kwargs) if callable(val) else val
                            except Exception:
                                actual_val = "<error>"
                            sanitized_val = redact_sensitive_data(key, actual_val)
                            span.set_attribute(key, sanitized_val)

                        # Record method arguments, skipping self/cls
                        span.set_attribute("args", str(args[1:]))
                        span.set_attribute("kwargs", str(kwargs))

                        try:
                            # Execute the original method
                            result = await __func(*args, **kwargs)
                            
                            # Record the result after redacting sensitive data
                            results_redacted = redact_json(result)
                            span.set_attribute("result", str(results_redacted))
                            
                            return result
                        except Exception as e:
                            # Record exceptions
                            span.record_exception(e)
                            span.set_status(StatusCode.ERROR)
                            raise
                        finally:
                            # Calculate and record method execution duration
                            duration_ms = (time.time_ns() - start_time) / 1e6
                            
                            # Record method call counter
                            method_call_counter = meter.create_counter(
                                "operation_counter", 
                                description="Count of operations performed", 
                                unit="1",
                            )
                            method_call_counter.add(
                                1,
                                attributes={
                                    "method": method_name,
                                    "trace_id": trace_id_hex,
                                    "span_id": span_id_hex
                                },
                                context=context.get_current()
                            )

                            # Record method latency histogram
                            method_latency_histogram = meter.create_histogram(
                                "method_latency",
                                description="Histogram of method execution latency",
                                unit="ms"
                            )
                            method_latency_histogram.record(
                                duration_ms,
                                attributes={
                                    "method": method_name,
                                    "trace_id": trace_id_hex,
                                    "span_id": span_id_hex
                                },
                                context=context.get_current()
                            )

                wrapped = async_wrapper
            # Handle synchronous methods
            else:
                @wraps(func)
                def sync_wrapper(*args, __func=func, __span_attrs=span_attrs, **kwargs):
                    # Create links to parent spans if requested
                    links = []
                    if link_span:
                        current_span = trace.get_current_span()
                        if current_span.is_active():
                            links.append(Link(current_span.get_span_context()))

                    method_name = __func.__qualname__
                    ctx = context.get_current()

                    # Start a new span for this method
                    with tracer.start_as_current_span(method_name, context=ctx, links=links) as span:
                        start_time = time.time_ns()

                        # Record trace and span IDs
                        trace_id_hex = f"0x{span.context.trace_id:x}"
                        span_id_hex = f"0x{span.context.span_id:x}"

                        span.set_attribute("trace_id", trace_id_hex)
                        span.set_attribute("span_id", span_id_hex)

                        # Record custom span attributes with sensitive data redaction
                        for key, val in __span_attrs.items():
                            try:
                                actual_val = val(*args, **kwargs) if callable(val) else val
                            except Exception:
                                actual_val = "<error>"
                            sanitized_val = redact_sensitive_data(key, actual_val)
                            span.set_attribute(key, sanitized_val)

                        # Record method arguments, skipping self/cls
                        span.set_attribute("args", str(args[1:]))
                        span.set_attribute("kwargs", str(kwargs))

                        try:
                            # Execute the original method
                            result = __func(*args, **kwargs)
                            
                            # Record the result after redacting sensitive data
                            results_redacted = redact_json(result, SENSITIVE_KEYS)
                            span.set_attribute("result", str(results_redacted))
                            
                            return result
                        except Exception as e:
                            # Record exceptions
                            span.record_exception(e)
                            span.set_status(StatusCode.ERROR)
                            raise
                        finally:
                            # Calculate and record method execution duration
                            duration_ms = (time.time_ns() - start_time) / 1e6
                            
                            # Record method call counter
                            method_call_counter = meter.create_counter(
                                "operation_counter", 
                                description="Count of operations performed", 
                                unit="1",
                            )
                            method_call_counter.add(
                                1,
                                attributes={
                                    "method": method_name,
                                    "trace_id": trace_id_hex,
                                    "span_id": span_id_hex
                                },
                                context=context.get_current()
                            )

                            # Record method latency histogram
                            method_latency_histogram = meter.create_histogram(
                                "method_latency",
                                description="Histogram of method execution latency",
                                unit="ms"
                            )
                            method_latency_histogram.record(
                                duration_ms,
                                attributes={
                                    "method": method_name,
                                    "trace_id": trace_id_hex,
                                    "span_id": span_id_hex
                                },
                                context=context.get_current()
                            )

                wrapped = sync_wrapper

            # Replace the original method with the instrumented version
            if is_static:
                setattr(cls, attr_name, staticmethod(wrapped))
            elif is_class:
                setattr(cls, attr_name, classmethod(wrapped))
            else:
                setattr(cls, attr_name, wrapped)

        return cls

    return decorator