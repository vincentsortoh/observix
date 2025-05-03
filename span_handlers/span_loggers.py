import json
import logging
import asyncio
import sys
import weakref
import atexit
from loguru import logger
from opentelemetry.trace import get_current_span


class StreamToLogger:
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


class InterceptHandler(logging.Handler):
    def emit(self, record):
        # Forward Loguru records to standard logging
        logging.getLogger(record.name).handle(record)


def bridge_loguru_to_std_logging():
    # Remove Loguru's default handler
    logger.remove()

    # Redirect everything to standard logging
    logger.add(InterceptHandler(), level="DEBUG")


class AsyncSpanLoggingHandler(logging.Handler):
    def __init__(self, level=logging.NOTSET):
        super().__init__(level)
        self._span_log_cache = weakref.WeakKeyDictionary()
        self._queue = asyncio.Queue()  
        self._loop = asyncio.get_event_loop()
        self._worker_task = self._loop.create_task(self._process_logs())

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

        except Exception as e:
            self.handleError(record)

    def emit(self, record):
        """ Emit the log record by queuing it for async processing. """
        try:
            # Enqueue the log record asynchronously
            self._loop.create_task(self._queue.put(record))
        except Exception as e:
            self.handleError(record)


    async def close(self):
        """ Gracefully stop the worker and process any remaining logs. """
        # Signal the worker to stop processing logs
        await self._queue.put(None)  # None signals the worker to stop
        await self._worker_task  

        print("AsyncSpanLoggingHandler has been closed.")


class SpanLoggingHandler(logging.Handler):
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


# Store original log record factory
_original_factory = logging.getLogRecordFactory()

def inject_trace_context(json_logs=False):
    """
    Injects trace context into stdlib logging. Supports optional JSON format.
    """
    def trace_context_factory(*args, **kwargs):
        record = _original_factory(*args, **kwargs)
        span = get_current_span()
        ctx = span.get_span_context() if span else None
        record.trace_id = format(ctx.trace_id, "032x") if ctx and ctx.trace_id else "N/A"
        record.span_id = format(ctx.span_id, "016x") if ctx and ctx.span_id else "N/A"
        return record

    logging.setLogRecordFactory(trace_context_factory)

    if not logging.getLogger().handlers:
        handler = logging.StreamHandler()
        if json_logs:
            class JsonFormatter(logging.Formatter):
                def format(self, record):
                    return json.dumps({
                        "timestamp": self.formatTime(record),
                        "level": record.levelname,
                        "message": record.getMessage(),
                        "trace_id": record.trace_id,
                        "span_id": record.span_id
                    })

            handler.setFormatter(JsonFormatter())
        else:
            handler.setFormatter(logging.Formatter(
                "[%(asctime)s] [trace_id=%(trace_id)s span_id=%(span_id)s] %(levelname)s - %(message)s"
            ))

        logging.getLogger().addHandler(handler)
        logging.getLogger().setLevel(logging.INFO)

def setup_loguru_with_trace_context(json_logs=False):
    # setup_loguru_with_trace_context() to support JSON:
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
        print("[microtrace] WARNING: loguru is enabled in config but not installed.")


def capture_log_as_span_event(level, message, trace_context=None):
    """Capture logs as span events."""
    span = get_current_span()
    if span is None:
        return

    # Log the message as a span event with log level
    span.add_event(message, attributes={"log.level": level, "trace_context": trace_context})


def setup_standard_logging_capture(enable_stdout_redirect=True):
    """
    Sets up logging to automatically send log messages as span events.
    """
    # Set up logging
    logger = logging.getLogger()
    # Create and configure the custom SpanLoggingHandler
    #handler = SpanLoggingHandler() #SpanLoggingHandler()

    handler = SpanLoggingHandler()

    # Optional: Add a formatter to the handler
    formatter = logging.Formatter(
        "[%(asctime)s] [trace_id=%(trace_id)s span_id=%(span_id)s] %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)

    # Add the handler to the logger
    logger.addHandler(handler)

    # Optionally, set the log level for the logger (default to INFO)
    logger.setLevel(logging.INFO)  # Adjust this as needed

    # redirect_stdout_stderr_to_logger()

    #redirect_stdout_stderr_to_logger()

    # Optional: capture print() and stdout/stderr
    if enable_stdout_redirect:
        stdout_logger = logging.getLogger("stdout")
        stderr_logger = logging.getLogger("stderr")

        # Attach span handler to stdout/stderr loggers too
        stdout_logger.addHandler(handler)
        stderr_logger.addHandler(handler)

        stdout_logger.setLevel(logging.INFO)
        stderr_logger.setLevel(logging.ERROR)

        # Redirect actual sys.stdout and sys.stderr
        sys.stdout = StreamToLogger(stdout_logger, logging.INFO, sys.__stdout__)
        sys.stderr = StreamToLogger(stderr_logger, logging.ERROR, sys.__stderr__)

    handler.close()

    return handler