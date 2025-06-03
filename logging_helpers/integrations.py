"""
Author: Vincent Sortoh
Created on: 2025-05-09

Integrations with third-party logging libraries.

This module provides integration with popular logging libraries like loguru,
enabling them to include OpenTelemetry trace context.
"""

import sys
import json
import logging
from opentelemetry.trace import get_current_span
from logging_helpers.handlers import SpanLoggingHandler, AsyncSpanLoggingHandler, setup_standard_logging_capture
from logging_helpers.formatters import TraceContextFormatter, JsonTraceContextFormatter


class InterceptHandler(logging.Handler):
    """
    Handler to intercept and bridge between logging frameworks.
    
    This handler can be used to forward logs from one system (like loguru)
    to another (like standard logging).
    """
    def emit(self, record):
        logging.getLogger(record.name).handle(record)



def setup_logging(level="DEBUG", format_string=None, json_format=False, 
                 capture_print=True, add_trace_context=True, 
                 root_logger_name="", loggers=None, use_async_handler=True):
    """
    Set up logging with OpenTelemetry trace context integration.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Configure root logger
    root_logger = logging.getLogger(root_logger_name)
    root_logger.setLevel(numeric_level)
    
    # Remove existing handlers
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)
    
    # Create formatter
    if json_format:
        formatter = JsonTraceContextFormatter()
    else:
        if format_string is None:
            format_string = "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
            if add_trace_context:
                format_string += " [trace_id=%(trace_id)s span_id=%(span_id)s]"
        
        formatter = TraceContextFormatter(fmt=format_string)
    
    # Create handler
    if add_trace_context:
        if use_async_handler:
            handler = AsyncSpanLoggingHandler()
        else:
            handler = SpanLoggingHandler()
    else:
        handler = logging.StreamHandler()
    
    handler.setFormatter(formatter)
    handler.setLevel(numeric_level)
    root_logger.addHandler(handler)
    
    configured_loggers = {root_logger_name: root_logger}
    
    # Configure additional loggers
    if loggers:
        for logger_name in loggers:
            logger = logging.getLogger(logger_name)
            logger.setLevel(numeric_level)
            
            for existing_handler in list(logger.handlers):
                logger.removeHandler(existing_handler)
            
            logger.addHandler(handler)
            
            logger.propagate = False
            
            configured_loggers[logger_name] = logger

    if add_trace_context:
        from logging_helpers.handlers import inject_trace_context
        inject_trace_context(json_logs=json_format)
    
    if capture_print:
        redirect_stdout_stderr_to_logger(handler)
    
    return configured_loggers



def bridge_loguru_to_std_logging():
    """
    Bridge loguru logs to standard logging.
    
    This function removes loguru's default handlers and redirects all loguru
    logs through standard logging, which can then benefit from the trace context.
    """
    try:
        from loguru import logger
        
        logger.remove()

        logger.add(InterceptHandler(), level="DEBUG")
        
    except ImportError:
        print("[observix] WARNING: loguru is enabled in config but not installed.")


def setup_loguru_with_trace_context(json_logs=False):
    """
    Configure loguru to include trace context information in logs.
    
    Args:
        json_logs (bool): If True, configure loguru to output JSON-formatted logs.
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

        loguru_logger.remove()
        loguru_logger.add(lambda msg: print(msg, end=""), format=formatter)

    except ImportError:
        print("[observix] WARNING: loguru is enabled in config but not installed.")


def redirect_stdout_stderr_to_logger(handler=None):
    """
    Redirect stdout and stderr to loggers with trace context.
    
    Args:
        handler (logging.Handler, optional): Handler to attach to the stdout/stderr loggers.
    """
    from logging_helpers.handlers import StreamToLogger
    
    stdout_logger = logging.getLogger("stdout")
    stderr_logger = logging.getLogger("stderr")
    
    if handler:
        stdout_logger.addHandler(handler)
        stderr_logger.addHandler(handler)

    stdout_logger.setLevel(logging.INFO)
    stderr_logger.setLevel(logging.ERROR)

    sys.stdout = StreamToLogger(stdout_logger, logging.INFO, sys.__stdout__)
    sys.stderr = StreamToLogger(stderr_logger, logging.ERROR, sys.__stderr__)