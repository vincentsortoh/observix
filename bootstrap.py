import sys
import weakref
import atexit

from otel_auto_libraries import auto_instrument_libraries
from observix_setup import load_config, instrument_selected_classes
from span_handlers.span_loggers import inject_trace_context
from span_handlers.span_loggers import setup_standard_logging_capture
from span_handlers.span_loggers import setup_loguru_with_trace_context
from span_handlers.span_loggers import bridge_loguru_to_std_logging


def setup_all_tracing(config_file="config.json", base_path="my_package"):

    config = load_config(config_file)

    print("Setting up auto-instrumentation for libraries...")
    auto_instrument_libraries()

    print("Setting up instrumentation for internal classes...")
    instrument_selected_classes(config, base_path)


    if config["logging"].get("enable_stdlib", True):
        inject_trace_context()
        handler = setup_standard_logging_capture()
        handler.close()

    if config["logging"].get("enable_loguru", False):
        setup_loguru_with_trace_context()
        bridge_loguru_to_std_logging()