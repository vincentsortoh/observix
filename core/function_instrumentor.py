"""
Author: 
Created on: 2025-06-27

Enhanced function instrumentation module for Observix.

This module extends the existing class instrumentation to support function-level
instrumentation with both automatic discovery and selective targeting.
"""

import os
import importlib
import json
import inspect
import fnmatch
from typing import List, Set, Dict, Any, Optional, Union, Callable
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Track processed functions to avoid duplicate instrumentation
processed_functions: Set[str] = set()

class FunctionInstrumentor:
    """
    Handles the instrumentation of individual functions.
    """
    
    def __init__(
        self,
        tracer=None,
        meter=None,
        redactor=None,
        capture_args: bool = True,
        capture_result: bool = True,
        with_caller: bool = False
    ):
        """
        Initialize a function instrumentor.
        
        Args:
            tracer: OpenTelemetry tracer instance
            meter: OpenTelemetry meter instance
            redactor: Data redactor for sensitive information
            capture_args: Whether to capture function arguments
            capture_result: Whether to capture function return values
            with_caller: Whether to include caller information
        """
        # Defer tracer/meter initialization to avoid circular imports
        self._tracer = tracer
        self._meter = meter
        self.redactor = redactor
        self.capture_args = capture_args
        self.capture_result = capture_result
        self.with_caller = with_caller
    
    @property
    def tracer(self):
        """Get tracer, initializing if needed."""
        if self._tracer is None:
            try:
                from core.tracer import get_tracer
                self._tracer = get_tracer()
            except Exception as e:
                logger.warning(f"Could not get tracer: {e}")
                return None
        return self._tracer
    
    @property
    def meter(self):
        """Get meter, initializing if needed."""
        if self._meter is None:
            try:
                from core.metrics import get_meter
                self._meter = get_meter()
            except Exception as e:
                logger.warning(f"Could not get meter: {e}")
                return None
        return self._meter
    
    def should_instrument_function(self, func: Callable, func_name: str) -> bool:
        """
        Determine if a function should be instrumented.
        
        Args:
            func: The function to check
            func_name: Name of the function
            
        Returns:
            bool: True if the function should be instrumented
        """
        # Skip if already marked to not trace
        if getattr(func, "_no_trace", False):
            return False
        
        # Skip dunder methods
        if func_name.startswith("__") and func_name.endswith("__"):
            return False
        
        # Skip private functions (starting with _) by default
        # Users can override this by explicitly listing them
        if func_name.startswith("_"):
            return False
        
        # Skip if not actually callable
        if not callable(func):
            return False
        
        # Skip classes (these should be handled by class instrumentor)
        if inspect.isclass(func):
            return False
        
        # Skip built-in functions
        if inspect.isbuiltin(func):
            return False
        
        # Skip if it's a method (bound or unbound)
        if inspect.ismethod(func):
            return False
        
        return True
    
    def instrument_function(self, func: Callable, function_name: str) -> Callable:
        """
        Instrument a function with tracing and metrics.
        
        Args:
            func: The function to instrument
            function_name: Full name for tracing (module.function_name)
            
        Returns:
            Instrumented function
        """
        # Import MethodInstrumentor to reuse existing logic
        from core.instrumentation import MethodInstrumentor
        
        # Create a method instrumentor with function-specific settings
        method_instrumentor = MethodInstrumentor(
            tracer=self.tracer,
            meter=self.meter,
            redactor=self.redactor,
            capture_args=self.capture_args,
            capture_result=self.capture_result,
            with_caller=self.with_caller
        )
        
        # Get span attributes if defined on the function
        span_attrs = getattr(func, "_otel_span_attrs", {})
        
        # Instrument using the existing method instrumentation logic
        instrumented_func = method_instrumentor.instrument_method(func, span_attrs)
        
        # Mark as instrumented to avoid re-instrumentation
        instrumented_func._observix_instrumented = True
        instrumented_func._original_function = func
        
        return instrumented_func


def get_functions_to_instrument(config: Dict[str, Any], base_path: Optional[str] = None) -> Set[str]:
    """
    Determine all functions that should be instrumented based on configuration.
    
    Args:
        config: Configuration dictionary
        base_path: Optional base path to search for modules
        
    Returns:
        Set of function names to instrument (format: module.function_name)
    """
    functions_to_instrument = set(config.get("instrument_functions", []))
    
    # Add functions from patterns
    function_patterns = config.get("function_patterns", [])
    if function_patterns:
        # We'll resolve patterns when we scan modules
        pass
    
    # If no specific functions listed and auto_instrument_functions is True,
    # we'll discover functions during module scanning
    
    return functions_to_instrument


def match_function_patterns(func_name: str, patterns: List[str]) -> bool:
    """
    Check if a function name matches any of the given patterns.
    
    Args:
        func_name: Name of the function
        patterns: List of glob patterns
        
    Returns:
        bool: True if function name matches any pattern
    """
    return any(fnmatch.fnmatch(func_name, pattern) for pattern in patterns)


def discover_functions_in_module(module, config: Dict[str, Any]) -> List[tuple]:
    """
    Discover functions in a module that should be instrumented.
    
    Args:
        module: The imported module
        config: Configuration dictionary
        
    Returns:
        List of (function_name, function_object) tuples
    """
    functions = []
    
    # Get configuration
    instrument_functions = set(config.get("instrument_functions", []))
    ignore_functions = set(config.get("ignore_functions", []))
    function_patterns = config.get("function_patterns", [])
    auto_instrument_functions = config.get("auto_instrument_functions", False)
    
    module_name = getattr(module, "__name__", "unknown")
    
    for attr_name in dir(module):
        if attr_name.startswith("__"):
            continue
            
        try:
            attr = getattr(module, attr_name)
        except Exception:
            # Skip attributes that can't be accessed
            continue
        
        # Check if it's a function (not a class, not a module, etc.)
        if not (inspect.isfunction(attr) or (callable(attr) and not inspect.isclass(attr))):
            continue
        
        full_function_name = f"{module_name}.{attr_name}"
        
        # Skip if in ignore list
        if full_function_name in ignore_functions or attr_name in ignore_functions:
            continue
        
        # Skip if already processed
        if full_function_name in processed_functions:
            continue
        
        # Check if we should instrument this function
        should_instrument = False
        
        # 1. Explicitly listed functions
        if full_function_name in instrument_functions or attr_name in instrument_functions:
            should_instrument = True
        
        # 2. Pattern matching
        elif function_patterns and match_function_patterns(attr_name, function_patterns):
            should_instrument = True
        
        # 3. Auto-instrument all functions in module
        elif auto_instrument_functions:
            # Use the instrumentor's logic to determine if we should instrument
            instrumentor = FunctionInstrumentor()
            should_instrument = instrumentor.should_instrument_function(attr, attr_name)
        
        if should_instrument:
            functions.append((attr_name, attr, full_function_name))
    
    return functions


def instrument_selected_functions(
    tracer=None,
    meter=None,
    config: Union[Dict[str, Any], str],
    base_path: Optional[str] = None,
    capture_args: bool = True,
    capture_result: bool = True
):
    """
    Selectively instrument functions based on configuration.
    
    Args:
        tracer: OpenTelemetry tracer
        meter: OpenTelemetry meter
        config: Either a config dictionary or path to a config file
        base_path: Optional base path for module discovery
        capture_args: Whether to capture function arguments
        capture_result: Whether to capture function return values
        
    Returns:
        Dictionary with instrumentation results
    """
    if isinstance(config, str):
        from class_instrumentor import load_config
        config = load_config(config)
    
    # Import the existing module discovery logic
    from class_instrumentor import get_modules_to_instrument
    
    module_names = get_modules_to_instrument(config, base_path)
    
    # Create function instrumentor
    function_instrumentor = FunctionInstrumentor(
        tracer=tracer,
        meter=meter,
        capture_args=capture_args,
        capture_result=capture_result
    )
    
    results = {
        "instrumented": [],
        "ignored": [],
        "errors": [],
        "modules_processed": []
    }
    
    for module_name in module_names:
        try:
            module = importlib.import_module(module_name)
            results["modules_processed"].append(module_name)
            
            # Discover functions to instrument
            functions_to_process = discover_functions_in_module(module, config)
            
            for func_name, func_obj, full_func_name in functions_to_process:
                try:
                    # Check if already instrumented
                    if getattr(func_obj, "_observix_instrumented", False):
                        results["ignored"].append(full_func_name)
                        continue
                    
                    # Instrument the function
                    instrumented_func = function_instrumentor.instrument_function(
                        func_obj, full_func_name
                    )
                    
                    # Replace the function in the module
                    setattr(module, func_name, instrumented_func)
                    
                    # Track as processed
                    processed_functions.add(full_func_name)
                    results["instrumented"].append(full_func_name)
                    
                    logger.info(f"Instrumented function: {full_func_name}")
                    
                except Exception as e:
                    error_info = {"function": full_func_name, "error": str(e)}
                    results["errors"].append(error_info)
                    logger.error(f"Failed to instrument function {full_func_name}: {e}")
            
        except ModuleNotFoundError:
            logger.warning(f"Module not found: {module_name}")
        except Exception as e:
            error_info = {"module": module_name, "error": str(e)}
            results["errors"].append(error_info)
            logger.error(f"Error while processing module {module_name}: {e}")
    
    return results


def instrument_function_decorator(
    capture_args: bool = True,
    capture_result: bool = True,
    span_attrs: Optional[Dict[str, Any]] = None,
    tracer=None,
    meter=None
):
    """
    Decorator for manual function instrumentation.
    
    Usage:
        @instrument_function_decorator(capture_args=True)
        def my_function(arg1, arg2):
            return result
    
    Args:
        capture_args: Whether to capture function arguments
        capture_result: Whether to capture function return values
        span_attrs: Additional span attributes
        tracer: OpenTelemetry tracer (optional)
        meter: OpenTelemetry meter (optional)
        
    Returns:
        Decorated function
    """
    def decorator(func):
        # Store span attributes for later use
        if span_attrs:
            func._otel_span_attrs = span_attrs
        
        # Get the module and function name for proper naming
        module_name = getattr(func, "__module__", "unknown")
        function_name = f"{module_name}.{func.__name__}"
        
        # Create instrumentor
        instrumentor = FunctionInstrumentor(
            tracer=tracer,
            meter=meter,
            capture_args=capture_args,
            capture_result=capture_result
        )
        
        # Instrument the function
        instrumented = instrumentor.instrument_function(func, function_name)
        
        # Track as processed
        processed_functions.add(function_name)
        
        return instrumented
    
    return decorator


# Convenience alias for the decorator
instrument_function = instrument_function_decorator