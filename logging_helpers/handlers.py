"""
Author: Vincent Sortoh
Created on: 2025-05-09
Logging handlers with OpenTelemetry trace context integration.

This module provides custom logging handlers that capture logs and attach them
to the current active span as events with trace context.
"""

import sys
import logging
import asyncio
import weakref
import atexit
from opentelemetry.trace import get_current_span


class StreamToLogger:
    """
    A file-like object that redirects writes to a logger instance.
    
    Useful for capturing stdout/stderr and sending to the logging system.
    """
    def __init__(self, logger, level=logging.INFO, stream=sys.__stdout__):
        self.logger = logger
        self.level = level
        self.stream = stream

    def write(self, message):
        message = message.strip()
        if message:
            self.logger.log(self.level, message)
            self.stream.write(message + "\n")  # Echo to original stream

    def flush(self):
        self.stream.flush()


class SpanLoggingHandler(logging.Handler):
    """
    A logging handler that captures log records and adds them as events to the current span.
    
    This handler also maintains a weak reference cache to avoid duplicate log messages
    within the same span.
    """
    def __init__(self, level=logging.NOTSET):
        super().__init__(level)
        self._span_log_cache = weakref.WeakKeyDictionary()

    def emit(self, record):
        try:
            span = get_current_span()
            if span is not None and span.is_recording():
                span_context = span.get_span_context()
                message = record.getMessage()

                # Create cache set if this span hasn't been seen yet
                logged_messages = self._span_log_cache.setdefault(span, set())

                # Skip duplicate messages
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
                        **trace_context
                    }
                )

                logged_messages.add(message)

        except Exception:
            self.handleError(record)


class AsyncSpanLoggingHandler(logging.Handler):
    """
    An asynchronous version of SpanLoggingHandler that processes logs in a background task.
    
    This handler is useful for high-throughput logging scenarios where synchronous 
    processing might cause performance issues.
    """
    def __init__(self, level=logging.NOTSET):
        super().__init__(level)
        self._span_log_cache = weakref.WeakKeyDictionary()
        self._queue = asyncio.Queue()  
        self._loop = asyncio.get_event_loop()
        self._worker_task = self._loop.create_task(self._process_logs())
        
        # Register cleanup at exit
        atexit.register(lambda: asyncio.run_coroutine_threadsafe(self.close(), self._loop))

    async def _process_logs(self):
        while True:
            record = await self._queue.get()
            if record is None:
                break 
            await self._log(record)

    async def _log(self, record):
        try:
            span = get_current_span()
            if span is not None and span.is_recording():
                span_context = span.get_span_context()
                message = record.getMessage()

                # Create cache set if this span hasn't been seen yet
                logged_messages = self._span_log_cache.setdefault(span, set())

                # Skip duplicate messages
                if message in logged_messages:
                    return

                trace_context = {
                    "trace_id": f"0x{span_context.trace_id:032x}",
                    "span_id": f"0x{span_context.span_id:016x}",
                }

                # Add the log message as an event
                span.add_event(
                    message,
                    attributes={
                        "log.level": record.levelname,
                        **trace_context
                    }
                )

                logged_messages.add(message)

        except Exception:
            self.handleError(record)

    def emit(self, record):
        """ Emit the log record by queuing it for async processing. """
        try:
            # Enqueue the log record asynchronously
            self._loop.create_task(self._queue.put(record))
        except Exception:
            self.handleError(record)

    async def close(self):
        """ Gracefully stop the worker and process any remaining logs. """
        # Signal the worker to stop processing logs
        await self._queue.put(None)  # None signals the worker to stop
        await self._worker_task  


# Store original log record factory
_original_factory = logging.getLogRecordFactory()

def inject_trace_context(json_logs=False):
    """
    Injects trace context into stdlib logging.
    
    This function modifies the logging record factory to include trace_id and span_id
    fields in every log record, enabling correlation with OpenTelemetry traces.
    
    Args:
        json_logs (bool): If True, configures logging to use JSON format with trace context.
    """
    from logging_helpers.formatters import TraceContextFormatter, JsonTraceContextFormatter
    
    def trace_context_factory(*args, **kwargs):
        record = _original_factory(*args, **kwargs)
        span = get_current_span()
        ctx = span.get_span_context() if span else None
        record.trace_id = format(ctx.trace_id, "032x") if ctx and ctx.trace_id else "N/A"
        record.span_id = format(ctx.span_id, "016x") if ctx and ctx.span_id else "N/A"
        return record

    logging.setLogRecordFactory(trace_context_factory)

    # Add default handler if none exists
    if not logging.getLogger().handlers:
        handler = logging.StreamHandler()
        
        if json_logs:
            handler.setFormatter(JsonTraceContextFormatter())
        else:
            handler.setFormatter(TraceContextFormatter())

        logging.getLogger().addHandler(handler)
        logging.getLogger().setLevel(logging.INFO)


def setup_standard_logging_capture(enable_stdout_redirect=True):
    """
    Sets up logging to automatically send log messages as span events.
    
    Args:
        enable_stdout_redirect (bool): If True, redirects stdout/stderr to loggers.
        
    Returns:
        SpanLoggingHandler: The configured handler instance.
    """
    from logging_helpers.formatters import TraceContextFormatter
    from logging_helpers.integrations import redirect_stdout_stderr_to_logger
    
    logger = logging.getLogger()

    # Create and configure the custom SpanLoggingHandler
    handler = SpanLoggingHandler()
    
    handler.setFormatter(TraceContextFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    
    if enable_stdout_redirect:
        redirect_stdout_stderr_to_logger(handler)

    return handler


def capture_log_as_span_event(level, message, trace_context=None):
    """
    Capture logs as span events.
    
    Args:
        level (str): The log level (e.g., "INFO", "ERROR")
        message (str): The log message text
        trace_context (dict, optional): Additional trace context information
    """
    span = get_current_span()
    if span is None:
        return

    # Log the message as a span event with log level
    attributes = {"log.level": level}
    if trace_context:
        attributes.update(trace_context)
        
    span.add_event(message, attributes=attributes)