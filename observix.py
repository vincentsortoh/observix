"""
Author: 
Created on: 2025-04-13
Description: Describe your script here
"""

import sys
import time
import importlib
import importlib.util
import subprocess
import asyncio
from functools import wraps
from opentelemetry.trace import Link, StatusCode
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry import trace, metrics, context
from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.metrics import get_meter_provider

from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.metrics.export import ConsoleMetricExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry import metrics

import logging

import otel_auto_libraries as otel_instrumentation


def is_module_available(name):
    return importlib.util.find_spec(name) is not None

def install_if_missing(pip_pkg):
    subprocess.check_call([sys.executable, "-m", "pip", "install", pip_pkg])

def try_instrument(lib):
    module_path, pip_pkg, class_name = otel_instrumentation.INSTRUMENTATION_MAP[lib]
    if not is_module_available(module_path):
        install_if_missing(pip_pkg)

    try:
        mod = importlib.import_module(module_path)
        instrumentor_class = getattr(mod, class_name)
        instrumentor_class().instrument()
        print(f"[otel] Instrumented: {lib}")
    except Exception as e:
        print(f"[otel] Failed to instrument {lib}: {e}")

def auto_instrument_libraries():
    for lib in otel_instrumentation.INSTRUMENTATION_MAP:
        if is_module_available(lib):
            try_instrument(lib)
        else:
            print(f"[otel] Skipping {lib} — not installed in environment")


_initialized_meter = None

def init_metrics(
    service_name: str,
    version: str = "1.0.0",
    environment: str = "dev",
    exporters: list = None,
    export_interval_millis: int = 1000
):
    """
    Initialize OpenTelemetry metrics pipeline. Prevents multiple re-initializations
    and returns the same meter if already initialized.

    Args:
        service_name (str): Your service name.
        version (str): Service version.
        environment (str): Deployment environment.
        exporters (list): List of exporters. Options: "console", "otlp".
        export_interval_millis (int): Export interval in milliseconds.
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

    # Exporter registry
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
    
    def get_trace_and_span_id():
        current_span = trace.get_current_span()
        if current_span.is_active():
            trace_id_hex = f"0x{current_span.get_context().trace_id:x}"
            span_id_hex = f"0x{current_span.get_context().span_id:x}"
            return trace_id_hex, span_id_hex
        return None, None

    return meter


def init_tracing(service_name: str, version: str = "1.0.0", environment: str = "dev", exporters=None):
    """
    Initializes OpenTelemetry tracing, but only if no provider is set yet.

    Args:
        service_name (str): Name of the service (required).
        version (str): App version.
        environment (str): Deployment environment.
    """

    if isinstance(trace.get_tracer_provider(), TracerProvider):
        return

    resource = Resource.create({
        "service.name": service_name,
        "service.version": version,
        "deployment.environment": environment,
    })


    provider = TracerProvider(resource=resource)
    trace.set_tracer_provider(provider)

    if exporters is None:
        exporters = [ConsoleSpanExporter()]


    for exporter in exporters:
        span_processor = SimpleSpanProcessor(exporter)
        trace.get_tracer_provider().add_span_processor(span_processor)


    return trace.get_tracer(__name__)


_initialized = False  

def init_tracing_with_guard(service_name: str, version: str = "1.0.0", environment: str = "dev", exporters=None):
    """
    Initializes OpenTelemetry tracing only if no provider has been initialized using a global guard.
    
    Args:
        service_name (str): Name of the service.
        version (str): App version.
        environment (str): Deployment environment.
    """
    global _initialized
    if _initialized:
        return

    resource = Resource.create({
        "service.name": service_name,
        "service.version": version,
        "deployment.environment": environment,
    })

    provider = TracerProvider(resource=resource)
    trace.set_tracer_provider(provider)

    if exporters is None:
        exporters = [ConsoleSpanExporter()]

    for exporter in exporters:
        span_processor = SimpleSpanProcessor(exporter)
        trace.get_tracer_provider().add_span_processor(span_processor)


    _initialized = True

    return trace.get_tracer(__name__)


def instrument_class(tracer=None, meter=None, ignore_methods=None, link_span=False):
    """
    Decorator to instrument a class with OpenTelemetry tracing and metrics.
    
    Args:
        tracer: OpenTelemetry tracer instance (required)
        meter: OpenTelemetry meter instance (required)
        ignore_methods: List of method names to ignore for instrumentation
        link_span: Whether to link spans with parent spans
    """

    if tracer is None:
        raise ValueError("A tracer instance must be provided")
    
    if meter is None:
        raise ValueError("A meter instance must be provided")
    
    ignore_methods = set(ignore_methods or [])

    def decorator(cls):
        for attr_name in dir(cls):
            if attr_name.startswith("__") or attr_name in ignore_methods:
                continue

            attr = getattr(cls, attr_name)
            is_static = isinstance(attr, staticmethod)
            is_class = isinstance(attr, classmethod)
            func = attr.__func__ if (is_static or is_class) else attr

            if not callable(func) or getattr(func, "_no_trace", False):
                continue

            span_attrs = getattr(func, "_otel_span_attrs", {})

            if asyncio.iscoroutinefunction(func):
                @wraps(func)
                async def async_wrapper(*args, __func=func, __span_attrs=span_attrs, **kwargs):
                    links = []
                    if link_span:
                        current_span = trace.get_current_span()
                        if current_span.is_active():
                            links.append(Link(current_span.get_span_context()))

                    method_name = __func.__qualname__
                    ctx = context.get_current()

                    with tracer.start_as_current_span(method_name, context=ctx, links=links) as span:
                        start_time = time.time_ns()

                        trace_id_hex = f"0x{span.context.trace_id:x}"
                        span_id_hex = f"0x{span.context.span_id:x}"

                        span.set_attribute("trace_id", trace_id_hex)
                        span.set_attribute("span_id", span_id_hex)

                        for key, val in __span_attrs.items():
                            try:
                                actual_val = val(*args, **kwargs) if callable(val) else val
                            except Exception:
                                actual_val = "<error>"
                            span.set_attribute(key, str(actual_val))

                        span.set_attribute("args", str(args[1:]))
                        span.set_attribute("kwargs", str(kwargs))

                        try:
                            result = await __func(*args, **kwargs)
                            span.set_attribute("result", str(result))
                            return result
                        except Exception as e:
                            span.record_exception(e)
                            span.set_status(StatusCode.ERROR)
                            raise
                        finally:
                            duration_ms = (time.time_ns() - start_time) / 1e6

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

            else:
                @wraps(func)
                def sync_wrapper(*args, __func=func, __span_attrs=span_attrs, **kwargs):
                    links = []
                    if link_span:
                        current_span = trace.get_current_span()
                        if current_span.is_active():
                            links.append(Link(current_span.get_span_context()))

                    method_name = __func.__qualname__
                    ctx = context.get_current()

                    with tracer.start_as_current_span(method_name, context=ctx, links=links) as span:
                        start_time = time.time_ns()

                        # Convert trace_id and span_id to hexadecimal
                        trace_id_hex = f"0x{span.context.trace_id:x}"
                        span_id_hex = f"0x{span.context.span_id:x}"

                        span.set_attribute("trace_id", trace_id_hex)
                        span.set_attribute("span_id", span_id_hex)

                        for key, val in __span_attrs.items():
                            try:
                                actual_val = val(*args, **kwargs) if callable(val) else val
                            except Exception:
                                actual_val = "<error>"
                            span.set_attribute(key, str(actual_val))

                        span.set_attribute("args", str(args[1:]))  # Skip self/cls
                        span.set_attribute("kwargs", str(kwargs))

                        try:
                            result = __func(*args, **kwargs)
                            span.set_attribute("result", str(result))
                            return result
                        except Exception as e:
                            span.record_exception(e)
                            span.set_status(StatusCode.ERROR)
                            raise
                        finally:
                            duration_ms = (time.time_ns() - start_time) / 1e6
                            
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

            if is_static:
                setattr(cls, attr_name, staticmethod(wrapped))
            elif is_class:
                setattr(cls, attr_name, classmethod(wrapped))
            else:
                setattr(cls, attr_name, wrapped)

        return cls

    return decorator


