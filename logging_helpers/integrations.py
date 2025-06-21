"""
Author: Vincent Sortoh
Created on: 2025-05-09

Fixed integrations with third-party logging libraries.
This version preserves original logging/print behavior while capturing for tracing.
"""

import sys
import json
import logging
import threading
import weakref
from opentelemetry.trace import get_current_span
from core.log_exporter import SpanAttachingLogHandler
from logging_helpers.handlers import NonInterferingSpanHandler, NonInterferingStreamToLogger


class InterceptHandler(logging.Handler):
    """
    Handler to intercept and bridge between logging frameworks.
    
    This handler can be used to forward logs from one system (like loguru)
    to another (like standard logging).
    """
    def emit(self, record):
        # Forward to standard logging but avoid infinite loops
        if not getattr(record, '_intercepted', False):
            record._intercepted = True
            logging.getLogger(record.name).handle(record)


class PreservingStreamToLogger:
    """
    A file-like object that captures writes to a logger while preserving original stream behavior.
    
    This ensures that print statements still appear in console/file as expected while also
    being captured for tracing and export. Fixed to prevent duplicates.
    """
    def __init__(self, logger, level=logging.INFO, original_stream=None, echo_to_original=True):
        self.logger = logger
        self.level = level
        self.original_stream = original_stream or sys.__stdout__
        self.echo_to_original = echo_to_original
        self._buffer = ""
        self._processed_messages = set()
        self._lock = threading.Lock()
        
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
            
            # Only send to trace handlers to avoid duplicate console output
            for handler in self.logger.handlers:
                if isinstance(handler, NonInterferingSpanHandler):
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
                    handler.handle(record)
            
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


# Alias for backward compatibility
TeeStreamToLogger = PreservingStreamToLogger


class PreservingSpanLoggingHandler(NonInterferingSpanHandler):
    """
    A logging handler that captures logs for spans without interfering with existing handlers.
    
    This handler only captures for tracing - it doesn't emit to console or files.
    Now inherits from NonInterferingSpanHandler for consistent behavior.
    """
    pass


def setup_logging(level="DEBUG", format_string=None, json_format=False, 
                 capture_print=True, add_trace_context=True, 
                 root_logger_name="", loggers=None, use_async_handler=False,
                 preserve_exi=True,  
                 sting_handlers=True, ensure_console_output=True):
    """
    Set up logging with OpenTelemetry trace context integration.
    
    This version ALWAYS preserves existing handlers while adding trace capture.
    
    Args:
        preserve_existing_handlers: Always True in this fixed version
        ensure_console_output: Ensure console output is preserved
    """
    
    from logging_helpers.formatters import TraceContextFormatter, JsonTraceContextFormatter
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Configure root logger
    root_logger = logging.getLogger(root_logger_name)
    root_logger.setLevel(numeric_level)
    
    # Store existing handlers - we NEVER remove them
    existing_handlers = list(root_logger.handlers)
    
    # Add trace capture handler (this doesn't emit to console/files)
    if add_trace_context:
        # Check if we already have a trace handler
        has_trace_handler = any(isinstance(h, NonInterferingSpanHandler) for h in existing_handlers)
        if not has_trace_handler:
            trace_handler = NonInterferingSpanHandler()
            trace_handler.setLevel(numeric_level)
            root_logger.addHandler(trace_handler)
    
    # Check if we need a console handler
    has_console_handler = any(
        isinstance(h, logging.StreamHandler) and 
        getattr(h, 'stream', None) in (sys.stdout, sys.stderr)
        for h in existing_handlers
    )
    
    if ensure_console_output and not has_console_handler:
        if json_format:
            formatter = JsonTraceContextFormatter()
        else:
            if format_string is None:
                format_string = "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
                if add_trace_context:
                    format_string += " [trace_id=%(trace_id)s span_id=%(span_id)s]"
            
            formatter = TraceContextFormatter(fmt=format_string)
        
        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(numeric_level)
        root_logger.addHandler(console_handler)
    
    configured_loggers = {root_logger_name: root_logger}
    
    # Configure additional loggers
    if loggers:
        for logger_name in loggers:
            logger_instance = logging.getLogger(logger_name)
            logger_instance.setLevel(numeric_level)
            
            # Store existing handlers for this logger too
            existing_logger_handlers = list(logger_instance.handlers)
            
            # Add trace capture handler
            if add_trace_context:
                has_trace_handler = any(isinstance(h, NonInterferingSpanHandler) for h in existing_logger_handlers)
                if not has_trace_handler:
                    trace_handler = NonInterferingSpanHandler()
                    trace_handler.setLevel(numeric_level)
                    logger_instance.addHandler(trace_handler)
            
            # Check if we need console handler for this logger
            has_console = any(
                isinstance(h, logging.StreamHandler) and 
                getattr(h, 'stream', None) in (sys.stdout, sys.stderr)
                for h in existing_logger_handlers
            )
            
            if ensure_console_output and not has_console and not has_console_handler:
                # Use the same console handler as root logger
                if 'console_handler' in locals():
                    logger_instance.addHandler(console_handler)
            
            # Keep propagation enabled so parent handlers still work
            logger_instance.propagate = True
            configured_loggers[logger_name] = logger_instance

    if add_trace_context:
        from logging_helpers.handlers import inject_trace_context
        inject_trace_context(json_logs=json_format)

    if capture_print:
        redirect_stdout_stderr_to_logger_preserving(numeric_level)
    
    return configured_loggers


def bridge_loguru_to_std_logging(preserve_loguru_handlers=True):
    """
    Bridge loguru logs to standard logging while preserving existing behavior.
    
    Args:
        preserve_loguru_handlers: Always True - we preserve all existing loguru handlers
    """
    try:
        from loguru import logger
        
        # We NEVER remove existing loguru handlers in this fixed version
        # Just add the bridge handler
        logger.add(InterceptHandler(), level="DEBUG")
        
    except ImportError:
        print("[observix] WARNING: loguru is enabled in config but not installed.")


def setup_loguru_with_trace_context(json_logs=False, preserve_existing=True):
    """
    Configure loguru to include trace context information in logs.
    
    This version preserves ALL existing loguru handlers.
    """
    try:
        from loguru import logger as loguru_logger
        
        def formatter(record):
            span = get_current_span()
            ctx = span.get_span_context() if span else None
            trace_id = format(ctx.trace_id, "032x") if ctx and ctx.trace_id else "N/A"
            span_id = format(ctx.span_id, "016x") if ctx and ctx.span_id else "N/A"

            if json_logs:
                return json.dumps({
                    "timestamp": f"{record['time']:%Y-%m-%d %H:%M:%S}",
                    "level": record['level'].name,
                    "message": record['message'],
                    "trace_id": trace_id,
                    "span_id": span_id
                }) + "\n"

            return (
                f"[{record['time']:%Y-%m-%d %H:%M:%S}] "
                f"[trace_id={trace_id} span_id={span_id}] "
                f"{record['level'].name} - {record['message']}\n"
            )

        # NEVER remove existing handlers - just add trace context handler
        # This handler captures for tracing without interfering with existing output
        loguru_logger.add(
            lambda msg: _capture_loguru_for_tracing(msg), 
            format=formatter,
            level="DEBUG"
        )

    except ImportError:
        print("[observix] WARNING: loguru is enabled in config but not installed.")


def _capture_loguru_for_tracing(message):
    """
    Internal function to capture loguru messages for tracing without outputting them.
    """
    # This function doesn't print - it just exists to capture the formatted message
    # The actual tracing happens through the bridge to standard logging
    pass


def redirect_stdout_stderr_to_logger_preserving(level=logging.INFO):
    """
    Redirect stdout and stderr to loggers while PERFECTLY preserving original behavior.
    """
    
    stdout_logger = logging.getLogger("stdout")
    stderr_logger = logging.getLogger("stderr")
    
    # Add only trace capture handlers (no console output from these)
    stdout_trace_handler = NonInterferingSpanHandler()
    stderr_trace_handler = NonInterferingSpanHandler()
    
    stdout_logger.addHandler(stdout_trace_handler)
    
    stderr_logger.addHandler(stderr_trace_handler)
    
    stdout_logger.setLevel(level)
    stderr_logger.setLevel(logging.ERROR)

    # Store original streams
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    # Use NonInterferingStreamToLogger to preserve original behavior while capturing
    sys.stdout = NonInterferingStreamToLogger(
        stdout_logger, 
        level, 
        original_stdout
    )
    sys.stderr = NonInterferingStreamToLogger(
        stderr_logger, 
        logging.ERROR, 
        original_stderr
    )


def redirect_stdout_stderr_to_logger(handler=None, echo_to_console=True):
    """
    Legacy function - redirects to the new preserving version.
    """
    redirect_stdout_stderr_to_logger_preserving(level=logging.INFO)


def restore_original_streams():
    """
    Restore original stdout/stderr streams.
    Useful for cleanup or testing scenarios.
    """
    sys.stdout = sys.__stdout__
    sys.stderr = sys.__stderr__