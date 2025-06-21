"""
Author: Vincent Sortoh
Created on: 2025-05-31
Log exporter module for Observix.

This module provides functionality for exporting logs to various destinations while
maintaining the ability to attach logs to OpenTelemetry spans as events.
"""

import logging
import sys
import weakref
import threading
from typing import Dict, List, Optional, Any, Union
from opentelemetry import trace
from opentelemetry.trace import get_current_span
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import (
    ConsoleLogExporter,
    SimpleLogRecordProcessor,
    BatchLogRecordProcessor,
)
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

    def __init__(self, level=logging.NOTSET, attach_to_spans=True, export_logs=True):
        super().__init__(level)
        self._span_log_cache = weakref.WeakKeyDictionary()
        self._processed_records = set()  # Cache to prevent duplicate processing
        self._record_lock = threading.RLock()  # Thread safety for deduplication
        self.attach_to_spans = attach_to_spans
        self.export_logs = export_logs
        self.otel_handler = None

    def set_otel_handler(self, otel_handler):
        """Set the OpenTelemetry logging handler for log export."""
        self.otel_handler = otel_handler

    def emit(self, record):
        try:
            # Create a unique identifier for this record based on content and location
            # Include timestamp to handle rapid identical messages
            record_id = f"{record.getMessage()}:{record.pathname}:{record.lineno}:{record.created:.6f}"
            
            with self._record_lock:
                if record_id in self._processed_records:
                    return  # Skip already processed records
                    
                self._processed_records.add(record_id)
                
                # Clean up processed records cache periodically to prevent memory leaks
                if len(self._processed_records) > 1000:
                    # Keep only the most recent 500 records
                    recent_records = list(self._processed_records)[-500:]
                    self._processed_records = set(recent_records)

            if self.attach_to_spans:
                self._attach_to_span(record)

            if self.export_logs and self.otel_handler:
                self.otel_handler.emit(record)

        except Exception:
            self.handleError(record)

    def _attach_to_span(self, record):
        """Attach log record to current span as an event."""
        span = get_current_span()
        if span is not None and span.is_recording():
            span_context = span.get_span_context()
            message = record.getMessage()

            # Use the same caching mechanism as the original handler
            logged_messages = self._span_log_cache.setdefault(span, set())
            
            # Create a unique key for this message including location and timestamp info
            message_key = f"{message}:{record.pathname}:{record.lineno}:{record.created:.3f}"

            if message_key in logged_messages:
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
                    **trace_context,
                },
            )

            logged_messages.add(message_key)



class OTELExportingStreamToLogger:
    """
    A file-like object that captures writes to a logger while preserving original stream behavior
    AND ensuring OTEL log export.
    """
    def __init__(self, logger, level=logging.INFO, original_stream=None, echo_to_original=True, 
                 span_export_handler=None):
        self.logger = logger
        self.level = level
        self.original_stream = original_stream or sys.__stdout__
        self.echo_to_original = echo_to_original
        self._buffer = ""
        self._processed_messages = set()
        self._lock = threading.Lock()
        self.span_export_handler = span_export_handler
        
    def write(self, message):
        # ALWAYS preserve original behavior first
        if self.original_stream and self.echo_to_original:
            self.original_stream.write(message)
            self.original_stream.flush()  # Ensure immediate output
        
        # Then capture for logging/tracing
        # Handle partial writes (common with print statements)
        self._buffer += message
        
        # Process complete lines
        while '\n' in self._buffer:
            line, self._buffer = self._buffer.split('\n', 1)
            if line.strip():  # Only log non-empty lines
                self._process_message(line.strip())
    
    def _process_message(self, message):
        """Process a message for logging, avoiding duplicates."""
        with self._lock:
            # Create a unique key for this message
            thread_id = threading.get_ident()
            message_key = f"{message}:{thread_id}"
            
            if message_key in self._processed_messages:
                return
            
            self._processed_messages.add(message_key)
            
            # Clean up cache periodically
            if len(self._processed_messages) > 500:
                recent_messages = list(self._processed_messages)[-250:]
                self._processed_messages = set(recent_messages)
            
            # Create a log record and emit through the SpanAttachingLogHandler
            # This will handle both span attachment AND OTEL export
            if self.span_export_handler:
                record = self.logger.makeRecord(
                    name=self.logger.name,
                    level=self.level,
                    fn="<print>",
                    lno=0,
                    msg=message,
                    args=(),
                    exc_info=None,
                    func="<print>"
                )
                # Use the SpanAttachingLogHandler directly to ensure both span attachment and export
                self.span_export_handler.emit(record)
            else:
                # Fallback to regular logging if no span handler available
                self.logger.log(self.level, message)
            
    def flush(self):
        # Flush any remaining buffer content
        if self._buffer.strip():
            self._process_message(self._buffer.strip())
            self._buffer = ""
            
        # Always flush original stream
        if self.original_stream:
            self.original_stream.flush()
            
    def __getattr__(self, name):
        """Delegate other attributes to original stream"""
        return getattr(self.original_stream, name)


def redirect_stdout_stderr_to_logger_with_otel_export(level=logging.INFO):
    """
    Enhanced version that ensures print statements are exported to OTEL logs.
    """
    
    stdout_logger = logging.getLogger("stdout")
    stderr_logger = logging.getLogger("stderr")
    
    # Get or create the SpanAttachingLogHandler from the root logger
    root_logger = logging.getLogger()
    span_export_handler = None
    
    for handler in root_logger.handlers:
        if hasattr(handler, 'attach_to_spans') and hasattr(handler, 'export_logs'):
            span_export_handler = handler
            break
    
    # If no SpanAttachingLogHandler exists, create one
    if span_export_handler is None:
        from log_exporter import SpanAttachingLogHandler, get_log_provider
        span_export_handler = SpanAttachingLogHandler(
            level=level,
            attach_to_spans=True,
            export_logs=True
        )
        
        # Set up OTEL handler if log provider exists
        log_provider = get_log_provider()
        if log_provider:
            from opentelemetry.sdk._logs import LoggingHandler
            otel_handler = LoggingHandler(logger_provider=log_provider)
            span_export_handler.set_otel_handler(otel_handler)
            
        from logging_helpers.formatters import TraceContextFormatter
        span_export_handler.setFormatter(TraceContextFormatter())
    
    # Add the handler to stdout/stderr loggers (this ensures they get exported)
    stdout_logger.addHandler(span_export_handler)
    stderr_logger.addHandler(span_export_handler)
    
    stdout_logger.setLevel(level)
    stderr_logger.setLevel(logging.ERROR)

    # Store original streams
    original_stdout = sys.stdout
    original_stderr = sys.stderr

    # Use the enhanced StreamToLogger that routes through SpanAttachingLogHandler
    sys.stdout = OTELExportingStreamToLogger(
        stdout_logger, 
        level, 
        original_stdout,
        echo_to_original=True,
        span_export_handler=span_export_handler
    )
    sys.stderr = OTELExportingStreamToLogger(
        stderr_logger, 
        logging.ERROR, 
        original_stderr,
        echo_to_original=True,
        span_export_handler=span_export_handler
    )


def init_log_export(
    service_name: str,
    version: str = "1.0.0",
    environment: str = "dev",
    exporters: Optional[List[str]] = None,
    exporter_endpoints: Optional[Dict[str, str]] = None,
    force_reinit: bool = False,
    attach_to_spans: bool = True,
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

    resource = Resource.create(
        {
            "service.name": service_name,
            "service.version": version,
            "deployment.environment": environment,
        }
    )

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
                logger.warning(
                    f"Log exporter {exporter_name} is not available. Install the appropriate package."
                )

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
    loguru_bridge_to_std: bool = True,
    echo_print_to_console: bool = True,  # Changed default to True
    add_console_handler: bool = True,  # New parameter to control console output
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
        echo_print_to_console: Whether to echo captured print statements to console
        add_console_handler: Whether to add a console handler for standard logging

    Returns:
        dict: Configuration results and handlers
    """
    from logging_helpers.formatters import TraceContextFormatter
    from logging_helpers.integrations import (
        redirect_stdout_stderr_to_logger,
        bridge_loguru_to_std_logging,
        setup_loguru_with_trace_context,
    )

    log_provider = init_log_export(
        service_name=service_name,
        version=version,
        environment=environment,
        exporters=exporters,
        exporter_endpoints=exporter_endpoints,
        attach_to_spans=attach_to_spans,
    )

    # Create the combined handler (only for span attachment and log export)
    span_export_handler = SpanAttachingLogHandler(
        level=getattr(logging, level.upper(), logging.INFO),
        attach_to_spans=attach_to_spans,
        export_logs=True,  # Enable log export
    )
    
    # Set up the OTLP handler
    otel_logging_handler = LoggingHandler(logger_provider=log_provider)
    span_export_handler.set_otel_handler(otel_logging_handler)
    span_export_handler.setFormatter(TraceContextFormatter())

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Check if console handler already exists
    has_console_handler = any(
        isinstance(handler, logging.StreamHandler) and 
        hasattr(handler, 'stream') and 
        handler.stream.name in ['<stdout>', '<stderr>']
        for handler in root_logger.handlers
    )

    # Remove existing handlers to prevent duplicates, but preserve console if needed
    existing_console_handlers = []
    if has_console_handler:
        existing_console_handlers = [
            h for h in root_logger.handlers 
            if isinstance(h, logging.StreamHandler) and 
            hasattr(h, 'stream') and 
            h.stream.name in ['<stdout>', '<stderr>']
        ]

    # Clear all handlers
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    # Add our span attachment and export handler
    root_logger.addHandler(span_export_handler)

    # Add console handler if needed and requested
    if add_console_handler and not existing_console_handlers:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(TraceContextFormatter())
        console_handler.setLevel(getattr(logging, level.upper(), logging.INFO))
        root_logger.addHandler(console_handler)
    elif existing_console_handlers:
        # Re-add existing console handlers
        for handler in existing_console_handlers:
            root_logger.addHandler(handler)

    configured_loggers = {"": root_logger}

    # Configure additional loggers
    if loggers:
        # this logger comes from the configuration. the problem is that users would to configured
        # sample:
        #     "loggers": [
        #     "user_service",
        #     "order_service", 
        #     "services",
        #     "api_client",
        #     "requests",
        #     "urllib3",
        #     "sqlalchemy.engine",
        #     "my_app.database",
        #     "my_app.auth"
        # ]
         
        # i need to auto add loggers for classes
        
        for logger_name in loggers:
            logger_instance = logging.getLogger(logger_name)
            logger_instance.setLevel(getattr(logging, level.upper(), logging.INFO))

            # Clear handlers for this logger
            for existing_handler in list(logger_instance.handlers):
                logger_instance.removeHandler(existing_handler)

            logger_instance.addHandler(span_export_handler)
            
            if add_console_handler:
                console_handler = logging.StreamHandler()
                console_handler.setFormatter(TraceContextFormatter())
                console_handler.setLevel(getattr(logging, level.upper(), logging.INFO))
                logger_instance.addHandler(console_handler)

            logger_instance.propagate = False

            configured_loggers[logger_name] = logger_instance

    # Inject trace context into log records
    from logging_helpers.handlers import inject_trace_context
    inject_trace_context()

    # Set up print capture with control over echoing
    if capture_print:
        redirect_stdout_stderr_to_logger_with_otel_export(
            level=getattr(logging, level.upper(), logging.INFO)
        )

    # Handle loguru integration
    loguru_enabled = False
    if enable_loguru:
        if loguru_bridge_to_std:
            bridge_loguru_to_std_logging()
            loguru_enabled = True
            logger.info(
                "Bridged loguru to standard logging for span capture and export"
            )
        else:
            setup_loguru_with_trace_context(json_logs=False)
            loguru_enabled = True
            logger.info(
                "Set up loguru with direct trace context (export not available)"
            )

    return {
        "log_provider": log_provider,
        "handler": span_export_handler,
        "otel_handler": otel_logging_handler,
        "configured_loggers": configured_loggers,
        "loguru_enabled": loguru_enabled,
        "span_attachment_enabled": attach_to_spans,
        "exporters": exporters or ["console"],
        "console_handler_added": add_console_handler,
    }


def create_otlp_log_exporter(
    endpoint: Optional[str] = None, headers: Optional[Dict[str, str]] = None
):
    """
    Create an OTLP log exporter.

    Args:
        endpoint: The OTLP endpoint URL
        headers: Headers to include with OTLP requests

    Returns:
        OTLPLogExporter: An OTLP log exporter instance, or None if not available
    """
    if not OTLP_LOGS_AVAILABLE:
        logger.warning(
            "OTLP log exporter is not available. Install opentelemetry-exporter-otlp"
        )
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
    level: Union[str, int] = logging.INFO,
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

    handler = SpanAttachingLogHandler(
        level=level, 
        attach_to_spans=attach_to_spans,
        export_logs=export_logs
    )

    if export_logs and _log_provider:
        otel_handler = LoggingHandler(logger_provider=_log_provider)
        handler.set_otel_handler(otel_handler)

    from logging_helpers.formatters import TraceContextFormatter
    handler.setFormatter(TraceContextFormatter())

    return handler