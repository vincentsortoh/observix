"""
Author: 
Created on: 2025-05-31
Log exporter module for Observix.

This module provides functionality for exporting logs to various destinations while
maintaining the ability to attach logs to OpenTelemetry spans as events.
"""

import logging
import weakref
from typing import Dict, List, Optional, Any, Union
from opentelemetry import trace
from opentelemetry.trace import get_current_span
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import ConsoleLogExporter, SimpleLogRecordProcessor, BatchLogRecordProcessor
from opentelemetry.sdk.resources import Resource

try:
    from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter
    OTLP_LOGS_AVAILABLE = True
except ImportError:
    OTLP_LOGS_AVAILABLE = False

try:
    from opentelemetry.exporter.jaeger.thrift import JaegerExporter
    JAEGER_LOGS_AVAILABLE = True
except ImportError:
    JAEGER_LOGS_AVAILABLE = False

logger = logging.getLogger(__name__)

_log_provider = None
_initialized = False


class SpanAttachingLogHandler(logging.Handler):
    """
    A logging handler that attaches logs to the current span AND exports them.
    
    This handler combines the functionality of SpanLoggingHandler with log exporting.
    """
    
    def __init__(self, level=logging.NOTSET, attach_to_spans=True):
        super().__init__(level)
        self._span_log_cache = weakref.WeakKeyDictionary()
        self.attach_to_spans = attach_to_spans
        self.otel_handler = None
        
    def set_otel_handler(self, otel_handler):
        """Set the OpenTelemetry logging handler for log export."""
        self.otel_handler = otel_handler
    
    def emit(self, record):
        try:
            if self.attach_to_spans:
                self._attach_to_span(record)
            
            if self.otel_handler:
                self.otel_handler.emit(record)
                
        except Exception:
            self.handleError(record)
    
    def _attach_to_span(self, record):
        """Attach log record to current span as an event."""
        span = get_current_span()
        if span is not None and span.is_recording():
            span_context = span.get_span_context()
            message = record.getMessage()

            logged_messages = self._span_log_cache.setdefault(span, set())

            if message in logged_messages:
                return

            trace_context = {
                "trace_id": f"0x{span_context.trace_id:032x}",
                "span_id": f"0x{span_context.span_id:016x}",
            }

            span.add_event(
                message,
                attributes={
                    "log.level": record.levelname,
                    "log.logger": record.name,
                    **trace_context
                }
            )

            logged_messages.add(message)


def init_log_export(
    service_name: str,
    version: str = "1.0.0",
    environment: str = "dev",
    exporters: Optional[List[str]] = None,
    exporter_endpoints: Optional[Dict[str, str]] = None,
    force_reinit: bool = False,
    attach_to_spans: bool = True
) -> LoggerProvider:
    """
    Initialize OpenTelemetry log export.
    
    Args:
        service_name (str): Name of the service
        version (str): Service version
        environment (str): Deployment environment
        exporters (list): List of log exporters ("console", "otlp", etc.)
        exporter_endpoints (dict): Endpoints for various exporters
        force_reinit (bool): Force reinitialization if already initialized
        attach_to_spans (bool): Whether to also attach logs to spans
    
    Returns:
        LoggerProvider: The initialized OpenTelemetry log provider
    """
    global _log_provider, _initialized
    
    if _initialized and not force_reinit:
        logger.info("Log export already initialized. Returning existing provider.")
        return _log_provider
    
    resource = Resource.create({
        "service.name": service_name,
        "service.version": version,
        "deployment.environment": environment,
    })
    
    _log_provider = LoggerProvider(resource=resource)
    
    if exporters is None:
        exporters = ["console"]
    
    if exporter_endpoints is None:
        exporter_endpoints = {}
    
    for exporter_name in exporters:
        if exporter_name.lower() == "console":
            processor = BatchLogRecordProcessor(ConsoleLogExporter())
            _log_provider.add_log_record_processor(processor)
            logger.info("Added console log exporter")
            
        elif exporter_name.lower() == "otlp" and OTLP_LOGS_AVAILABLE:
            endpoint = exporter_endpoints.get("otlp", "http://localhost:4317")
            exporter = OTLPLogExporter(endpoint=endpoint)
            processor = BatchLogRecordProcessor(exporter)
            _log_provider.add_log_record_processor(processor)
            logger.info(f"Added OTLP log exporter with endpoint {endpoint}")
            
        else:
            if exporter_name not in ["console", "otlp"]:
                logger.warning(f"Unknown log exporter: {exporter_name}")
            else:
                logger.warning(f"Log exporter {exporter_name} is not available. Install the appropriate package.")
    
    _initialized = True
    logger.info(f"Log export initialized for service: {service_name}")
    
    return _log_provider


def get_log_provider() -> Optional[LoggerProvider]:
    """
    Get the current log provider instance.
    
    Returns:
        LoggerProvider: The current OpenTelemetry log provider instance, or None if not initialized.
    """
    return _log_provider


def setup_log_capture_with_export(
    service_name: str,
    version: str = "1.0.0",
    environment: str = "dev",
    exporters: Optional[List[str]] = None,
    exporter_endpoints: Optional[Dict[str, str]] = None,
    level: str = "INFO",
    attach_to_spans: bool = True,
    capture_print: bool = True,
    loggers: Optional[List[str]] = None,
    enable_loguru: bool = True,
    loguru_bridge_to_std: bool = True
) -> Dict[str, Any]:
    """
    Set up comprehensive log capture with both span attachment and export.
    
    Args:
        service_name: Name of the service
        version: Service version
        environment: Deployment environment
        exporters: List of log exporters
        exporter_endpoints: Endpoints for exporters
        level: Logging level
        attach_to_spans: Whether to attach logs to spans
        capture_print: Whether to capture print statements
        loggers: List of logger names to configure
        enable_loguru: Whether to enable loguru integration
        loguru_bridge_to_std: Whether to bridge loguru to standard logging
    
    Returns:
        dict: Configuration results and handlers
    """
    from logging_helpers.formatters import TraceContextFormatter
    from logging_helpers.integrations import redirect_stdout_stderr_to_logger, bridge_loguru_to_std_logging, setup_loguru_with_trace_context
    
    log_provider = init_log_export(
        service_name=service_name,
        version=version,
        environment=environment,
        exporters=exporters,
        exporter_endpoints=exporter_endpoints,
        attach_to_spans=attach_to_spans
    )
    
    otel_logging_handler = LoggingHandler(logger_provider=log_provider)
    
    span_export_handler = SpanAttachingLogHandler(
        level=getattr(logging, level.upper(), logging.INFO),
        attach_to_spans=attach_to_spans
    )
    span_export_handler.set_otel_handler(otel_logging_handler)
    span_export_handler.setFormatter(TraceContextFormatter())
    
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)
    
    root_logger.addHandler(span_export_handler)
    
    configured_loggers = {"": root_logger}
    
    if loggers:
        for logger_name in loggers:
            logger_instance = logging.getLogger(logger_name)
            logger_instance.setLevel(getattr(logging, level.upper(), logging.INFO))
            
            for existing_handler in list(logger_instance.handlers):
                logger_instance.removeHandler(existing_handler)
            
            logger_instance.addHandler(span_export_handler)
            logger_instance.propagate = False
            
            configured_loggers[logger_name] = logger_instance
    
    from logging_helpers.handlers import inject_trace_context
    inject_trace_context()
    
    if capture_print:
        redirect_stdout_stderr_to_logger(span_export_handler)
    
    loguru_enabled = False
    if enable_loguru:
        if loguru_bridge_to_std:
            bridge_loguru_to_std_logging()
            loguru_enabled = True
            logger.info("Bridged loguru to standard logging for span capture and export")
        else:
            setup_loguru_with_trace_context(json_logs=False)
            loguru_enabled = True
            logger.info("Set up loguru with direct trace context (export not available)")
    
    return {
        "log_provider": log_provider,
        "handler": span_export_handler,
        "otel_handler": otel_logging_handler,
        "configured_loggers": configured_loggers,
        "loguru_enabled": loguru_enabled,
        "span_attachment_enabled": attach_to_spans,
        "exporters": exporters or ["console"]
    }


def create_otlp_log_exporter(endpoint: Optional[str] = None, headers: Optional[Dict[str, str]] = None):
    """
    Create an OTLP log exporter.
    
    Args:
        endpoint: The OTLP endpoint URL
        headers: Headers to include with OTLP requests
    
    Returns:
        OTLPLogExporter: An OTLP log exporter instance, or None if not available
    """
    if not OTLP_LOGS_AVAILABLE:
        logger.warning("OTLP log exporter is not available. Install opentelemetry-exporter-otlp")
        return None
    
    kwargs = {}
    if endpoint:
        kwargs["endpoint"] = endpoint
    if headers:
        kwargs["headers"] = headers
    
    return OTLPLogExporter(**kwargs)


def get_log_capturing_handler(
    attach_to_spans: bool = True,
    export_logs: bool = True,
    level: Union[str, int] = logging.INFO
) -> SpanAttachingLogHandler:
    """
    Get a pre-configured log handler that can both attach to spans and export logs.
    
    Args:
        attach_to_spans: Whether to attach logs to spans
        export_logs: Whether to export logs
        level: Logging level
    
    Returns:
        SpanAttachingLogHandler: Configured handler
    """
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)
    
    handler = SpanAttachingLogHandler(level=level, attach_to_spans=attach_to_spans)
    
    if export_logs and _log_provider:
        otel_handler = LoggingHandler(logger_provider=_log_provider)
        handler.set_otel_handler(otel_handler)
    
    from logging_helpers.formatters import TraceContextFormatter
    handler.setFormatter(TraceContextFormatter())
    
    return handler