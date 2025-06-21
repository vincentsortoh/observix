"""
Author: Vincent Sortoh
Created on: 2025-05-09
Fixed logging handlers with OpenTelemetry trace context integration.

This version focuses on capturing logs for tracing without interfering with
existing logging behavior and prevents duplicate events.
"""

import inspect
import sys
import logging
import asyncio
import weakref
import atexit
import threading
from opentelemetry.trace import get_current_span


class NonInterferingStreamToLogger:
    """
    A file-like object that redirects writes to a logger while preserving original stream behavior.
    
    Ensures original behavior is NEVER affected and prevents duplicates.
    """
    def __init__(self, logger, level=logging.INFO, original_stream=sys.__stdout__):
        self.logger = logger
        self.level = level
        self.original_stream = original_stream
        self._buffer = ""
        self._processed_messages = set()
        self._lock = threading.Lock()

    def write(self, message):
        # ALWAYS write to original stream first - this is the user's expected behavior
        if self.original_stream:
            self.original_stream.write(message)
            self.original_stream.flush()
        
        # Then capture for tracing (but don't interfere with original output)
        self._buffer += message
        
        # Process complete messages for logging
        while '\n' in self._buffer:
            line, self._buffer = self._buffer.split('\n', 1)
            if line.strip():  
                self._process_message(line.strip())

    def _process_message(self, message):
        """Process a message for logging, avoiding duplicates."""
        with self._lock:
            # Create a unique key for this message
            message_key = f"{message}:{id(threading.current_thread())}"
            
            if message_key in self._processed_messages:
                return
            
            self._processed_messages.add(message_key)
            
            # Clean up cache periodically
            if len(self._processed_messages) > 500:
                # Keep only recent half
                recent_messages = list(self._processed_messages)[-250:]
                self._processed_messages = set(recent_messages)
            
            # Find the original caller for better trace context
            frame = inspect.currentframe()
            try:
                caller_frame = frame.f_back.f_back  # Skip this method and write()
                
                # Skip internal frames to find actual source
                while caller_frame:
                    filename = caller_frame.f_code.co_filename
                    function_name = caller_frame.f_code.co_name
                    
                    if (not filename.endswith(('handlers.py', 'integrations.py', 'logging/__init__.py')) and 
                        not function_name.startswith('_')):
                        break
                    caller_frame = caller_frame.f_back
                
                if caller_frame:
                    record = self.logger.makeRecord(
                        name=self.logger.name,
                        level=self.level,
                        fn=caller_frame.f_code.co_filename,
                        lno=caller_frame.f_lineno,
                        msg=message,
                        args=(),
                        exc_info=None,
                        func=caller_frame.f_code.co_name
                    )
                    # Only send to trace handlers, not console handlers
                    for handler in self.logger.handlers:
                        if isinstance(handler, (NonInterferingSpanHandler, PreservingSpanLoggingHandler)):
                            handler.handle(record)
                else:
                    # Fallback - only to trace handlers
                    for handler in self.logger.handlers:
                        if isinstance(handler, (NonInterferingSpanHandler, PreservingSpanLoggingHandler)):
                            handler.emit(logging.LogRecord(
                                name=self.logger.name,
                                level=self.level,
                                pathname="<print>",
                                lineno=0,
                                msg=message,
                                args=(),
                                exc_info=None
                            ))
                        
            finally:
                del frame

    def flush(self):
        # Process any remaining buffer
        if self._buffer.strip():
            self._process_message(self._buffer.strip())
            self._buffer = ""
        
        # Always flush original stream
        if self.original_stream:
            self.original_stream.flush()


class NonInterferingSpanHandler(logging.Handler):
    """
    A logging handler that ONLY captures for spans - never outputs to console/files.
    
    This handler is designed to work alongside existing handlers without interfering.
    Prevents duplicate span events.
    """
    def __init__(self, level=logging.NOTSET):
        super().__init__(level)
        self._span_log_cache = weakref.WeakKeyDictionary()
        self._global_message_cache = set()
        self._last_cleanup = 0
        self._lock = threading.RLock()

    def emit(self, record):
        try:
            with self._lock:
                span = get_current_span()
                if span is not None and span.is_recording():
                    span_context = span.get_span_context()
                    message = record.getMessage()
                    
                    # Create unique identifier including thread info to prevent cross-contamination
                    thread_id = threading.get_ident()
                    message_key = f"{message}:{getattr(record, 'pathname', 'unknown')}:{getattr(record, 'lineno', 0)}:{thread_id}"
                    
                    # Get or create message cache for this span
                    span_id = id(span)
                    logged_messages = self._span_log_cache.setdefault(span, set())

                    # Skip duplicates - check both span-specific and global caches
                    if message_key in logged_messages or message_key in self._global_message_cache:
                        return

                    # Add to span as event
                    trace_context = {
                        "trace_id": f"0x{span_context.trace_id:032x}",
                        "span_id": f"0x{span_context.span_id:016x}",
                    }

                    span.add_event(
                        message,
                        attributes={
                            "log.level": record.levelname,
                            "log.logger": getattr(record, 'name', 'unknown'),
                            "log.pathname": getattr(record, 'pathname', 'unknown'),
                            "log.lineno": getattr(record, 'lineno', 0),
                            "log.function": getattr(record, 'funcName', 'unknown'),
                            **trace_context
                        }
                    )

                    # Cache the message
                    logged_messages.add(message_key)
                    self._global_message_cache.add(message_key)
                    
                    # Periodic cleanup
                    import time
                    current_time = time.time()
                    if current_time - self._last_cleanup > 60:  # Cleanup every minute
                        self._cleanup_caches()
                        self._last_cleanup = current_time

        except Exception:
            # Don't call handleError as it might interfere with existing logging
            pass

    def _cleanup_caches(self):
        """Clean up caches to prevent memory leaks."""
        if len(self._global_message_cache) > 1000:
            # Keep only recent messages
            recent_messages = list(self._global_message_cache)[-500:]
            self._global_message_cache = set(recent_messages)


# Alias for backward compatibility
PreservingSpanLoggingHandler = NonInterferingSpanHandler


class SpanLoggingHandler(NonInterferingSpanHandler):
    """
    Original SpanLoggingHandler - now inherits from NonInterferingSpanHandler
    for better behavior preservation.
    """
    pass


class AsyncSpanLoggingHandler(logging.Handler):
    """
    Non-interfering async version that only captures for spans.
    """
    def __init__(self, level=logging.NOTSET):
        super().__init__(level)
        self._span_log_cache = weakref.WeakValueDictionary()
        self._message_cache = set()
        self._queue = None
        self._loop = None
        self._worker_task = None
        self._closing = False
        self._lock = threading.RLock()
        self._setup_async()
        
    def _setup_async(self):
        """Set up async components."""
        try:
            self._loop = asyncio.get_event_loop()
        except RuntimeError:
            # No event loop running
            self._loop = None
            return
            
        if self._loop and self._loop.is_running():
            self._queue = asyncio.Queue()
            self._worker_task = self._loop.create_task(self._process_logs())
            
            def cleanup():
                if self._loop and self._loop.is_running():
                    future = asyncio.run_coroutine_threadsafe(self._shutdown(), self._loop)
                    try:
                        future.result(timeout=2.0)
                    except Exception:
                        pass
            
            atexit.register(cleanup)

    async def _process_logs(self):
        """Process logs asynchronously."""
        while True:
            try:
                record = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                if record is None:
                    break
                await self._log(record)
                self._queue.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception:
                break

    async def _log(self, record):
        """Log record to span (async version)."""
        try:
            with self._lock:
                span = get_current_span()
                if span is not None and span.is_recording():
                    span_context = span.get_span_context()
                    message = record.getMessage()
                    
                    thread_id = threading.get_ident()
                    message_key = f"{message}:{getattr(record, 'pathname', 'unknown')}:{getattr(record, 'lineno', 0)}:{thread_id}"
                    
                    if message_key in self._message_cache:
                        return

                    trace_context = {
                        "trace_id": f"0x{span_context.trace_id:032x}",
                        "span_id": f"0x{span_context.span_id:016x}",
                    }

                    span.add_event(
                        message,
                        attributes={
                            "log.level": record.levelname,
                            "log.logger": getattr(record, 'name', 'unknown'),
                            **trace_context
                        }
                    )

                    self._message_cache.add(message_key)
                    
                    if len(self._message_cache) > 1000:
                        recent_messages = list(self._message_cache)[-500:]
                        self._message_cache = set(recent_messages)

        except Exception:
            pass

    def emit(self, record):
        """Emit record for async processing."""
        if self._closing or not self._queue or not self._loop:
            # Fallback to sync processing
            self._sync_emit(record)
            return
            
        try:
            if self._loop.is_running():
                asyncio.run_coroutine_threadsafe(self._queue.put(record), self._loop)
            else:
                self._sync_emit(record)
        except Exception:
            self._sync_emit(record)
    
    def _sync_emit(self, record):
        """Synchronous fallback."""
        try:
            with self._lock:
                span = get_current_span()
                if span is not None and span.is_recording():
                    span_context = span.get_span_context()
                    message = record.getMessage()
                    
                    thread_id = threading.get_ident()
                    message_key = f"{message}:{getattr(record, 'pathname', 'unknown')}:{getattr(record, 'lineno', 0)}:{thread_id}"
                    
                    if message_key in self._message_cache:
                        return
                    
                    trace_context = {
                        "trace_id": f"0x{span_context.trace_id:032x}",
                        "span_id": f"0x{span_context.span_id:016x}",
                    }
                    
                    span.add_event(
                        message,
                        attributes={
                            "log.level": record.levelname,
                            "log.logger": getattr(record, 'name', 'unknown'),
                            **trace_context
                        }
                    )
                    
                    self._message_cache.add(message_key)
        except Exception:
            pass

    async def _shutdown(self):
        """Shutdown async components."""
        if self._closing:
            return
            
        self._closing = True
        
        if self._queue:
            await self._queue.put(None)
            await self._queue.join()
        
        if self._worker_task:
            await self._worker_task

    def close(self):
        """Close handler."""
        if self._closing:
            return
            
        self._closing = True
        
        if self._loop and self._loop.is_running() and self._queue:
            asyncio.run_coroutine_threadsafe(self._queue.put(None), self._loop)
        
        super().close()


# Store original log record factory
_original_factory = logging.getLogRecordFactory()

def inject_trace_context(json_logs=False):
    """
    Injects trace context into stdlib logging without affecting existing behavior.
    """
    def trace_context_factory(*args, **kwargs):
        record = _original_factory(*args, **kwargs)
        span = get_current_span()
        ctx = span.get_span_context() if span else None
        record.trace_id = format(ctx.trace_id, "032x") if ctx and ctx.trace_id else "N/A"
        record.span_id = format(ctx.span_id, "016x") if ctx and ctx.span_id else "N/A"
        return record

    logging.setLogRecordFactory(trace_context_factory)


def setup_standard_logging_capture(enable_stdout_redirect=True):
    """
    Sets up non-interfering logging capture for traces.
    """
    logger = logging.getLogger()

    # Only add our handler if it's not already there
    has_span_handler = any(isinstance(h, NonInterferingSpanHandler) for h in logger.handlers)
    
    if not has_span_handler:
        handler = NonInterferingSpanHandler()
        logger.addHandler(handler)
    
    # Ensure minimum level for capture
    if logger.level > logging.INFO:
        logger.setLevel(logging.INFO)
    
    if True: #enable_stdout_redirect:
        print("JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ")
        from logging_helpers.integrations import redirect_stdout_stderr_to_logger_preserving
        redirect_stdout_stderr_to_logger_preserving()

    return handler


def capture_log_as_span_event(level, message, trace_context=None):
    """
    Capture logs as span events.
    """
    span = get_current_span()
    if span is None:
        return

    attributes = {"log.level": level}
    if trace_context:
        attributes.update(trace_context)
        
    span.add_event(message, attributes=attributes)