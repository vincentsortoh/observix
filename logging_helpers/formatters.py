"""
Author: Vincent Sortoh
Created on: 2025-05-09
Log formatters with trace context integration.

This module provides formatters that include OpenTelemetry trace context
information in log messages, in both text and JSON formats.
"""

import json
import logging


class TraceContextFormatter(logging.Formatter):
    """
    A log formatter that includes trace and span IDs in log messages.
    
    Format: [timestamp] [trace_id=<trace_id> span_id=<span_id>] LEVEL - message
    """
    def __init__(self, fmt=None, datefmt=None, style='%'):
        if fmt is None:
            fmt = "[%(asctime)s] [trace_id=%(trace_id)s span_id=%(span_id)s] %(levelname)s - %(message)s"
        super().__init__(fmt=fmt, datefmt=datefmt, style=style)


class JsonTraceContextFormatter(logging.Formatter):
    """
    A log formatter that outputs JSON-formatted logs with trace context.
    
    This formatter is useful for structured logging systems and log aggregators
    that can parse JSON.
    """
    def format(self, record):
        log_data = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "message": record.getMessage(),
            "trace_id": getattr(record, "trace_id", "N/A"),
            "span_id": getattr(record, "span_id", "N/A")
        }
        
        for key, value in record.__dict__.items():
            if key not in log_data and not key.startswith("_") and isinstance(value, (str, int, float, bool, type(None))):
                log_data[key] = value
                
        return json.dumps(log_data)