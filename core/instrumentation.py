"""
Author: 
Created on: 2025-05-09

Instrumentation module for Observix.

This module provides functionality for instrumenting Python classes and methods.
"""

import time
import asyncio
import functools
import inspect
import json
from functools import wraps
from typing import Set, Dict, Any, Callable, Optional, Type, List, TypeVar, Union

from opentelemetry import trace, context
from opentelemetry.trace import Link, StatusCode, Span

from core.tracer import get_tracer
from core.metrics import get_meter
from utils.security import redact_json, redact_sensitive_data, DataRedactor


TraceAttributesType = Dict[str, Any]

T = TypeVar('T')


def should_instrument(func: Callable) -> bool:
    """
    Determine if a function should be instrumented.
    
    A function should not be instrumented if:
    - It has the _no_trace attribute set to True
    - It is a built-in function (like __init__, __str__, etc)
    - It is a property, staticmethod or classmethod
    
    Args:
        func (Callable): The function to check
        
    Returns:
        bool: True if the function should be instrumented, False otherwise
    """

    if getattr(func, "_no_trace", False):
        return False
    
    if func.__name__.startswith("__") and func.__name__.endswith("__"):
        return False
    
    if isinstance(func, (property, staticmethod, classmethod)):
        return False
    
    return True


class MethodInstrumentor:
    """
    Handles the instrumentation of individual methods.
    """
    
    def __init__(
        self,
        tracer=None,
        meter=None,
        link_span: bool = False,
        redactor: Optional[DataRedactor] = None,
        capture_args: bool = True,
        capture_result: bool = True,
        with_caller: bool = False
    ):
        """
        Initialize a method instrumentor.
        
        Args:
            tracer: OpenTelemetry tracer instance
            meter: OpenTelemetry meter instance
            link_span: Whether to link spans with parent spans
            redactor: Data redactor for sensitive information
            capture_args: Whether to capture method arguments
            capture_result: Whether to capture method return values
            with_caller: Whether to include caller information
        """
        self.tracer = tracer or get_tracer()
        self.meter = meter or get_meter()
        self.link_span = link_span
        self.redactor = redactor or DataRedactor()
        self.capture_args = capture_args
        self.capture_result = capture_result
        self.with_caller = with_caller
    
    def _get_links(self) -> List[Link]:
        """Get links to parent spans if enabled."""
        links = []
        if self.link_span:
            current_span = trace.get_current_span()
            if current_span.is_active():
                links.append(Link(current_span.get_span_context()))
        return links
    
    def _extract_caller_info(self) -> Dict[str, str]:
        """Extract information about the caller."""
        if not self.with_caller:
            return {}
            
        frame = inspect.currentframe()
        try:
            for _ in range(3):  # Skip this function, wrapper, and instrumented function
                if frame is None:
                    break
                frame = frame.f_back
                
            if frame is None:
                return {}
                
            info = inspect.getframeinfo(frame)
            return {
                "caller.file": info.filename,
                "caller.line": str(info.lineno),
                "caller.function": info.function
            }
        finally:
            del frame
    
    def _setup_span(
        self, 
        span: Span, 
        method_name: str,
        args: tuple,
        kwargs: dict,
        span_attrs: Dict[str, Any]
    ) -> None:
        """Set up span with attributes."""
        # Set trace and span IDs
        trace_id_hex = f"0x{span.context.trace_id:x}"
        span_id_hex = f"0x{span.context.span_id:x}"
        
        span.set_attribute("trace_id", trace_id_hex)
        span.set_attribute("span_id", span_id_hex)
        span.set_attribute("method", method_name)
        
        # Add caller info if enabled
        caller_info = self._extract_caller_info()
        for k, v in caller_info.items():
            span.set_attribute(k, v)
        
        # Set user-defined attributes
        for key, val in span_attrs.items():
            try:
                # Handle callable attributes
                actual_val = val(*args, **kwargs) if callable(val) else val
            except Exception:
                actual_val = "<error>"
                
            sanitized_val = redact_sensitive_data(key, actual_val)
            span.set_attribute(key, sanitized_val)
        
        if self.capture_args and args:
            # Skip self/cls for instance/class methods
            skip = 1 if len(args) > 0 and not isinstance(args[0], (int, float, str, bool, type(None))) else 0
            args_to_log = args[skip:]
            if args_to_log:
                args_redacted = redact_json(args_to_log)
                span.set_attribute("args", str(args_redacted))
        
        if self.capture_args and kwargs:
            kwargs_redacted = redact_json(kwargs)
            span.set_attribute("kwargs", str(kwargs_redacted))
    
    def _record_metrics(
        self, 
        start_time: int,
        method_name: str, 
        trace_id: str, 
        span_id: str,
        success: bool
    ) -> None:
        """Record metrics for the method execution."""
        duration_ms = (time.time_ns() - start_time) / 1e6
        ctx = context.get_current()
        
        # Counter for method calls
        method_call_counter = self.meter.create_counter(
            "operation_counter", 
            description="Count of operations performed", 
            unit="1",
        )
        method_call_counter.add(
            1,
            attributes={
                "method": method_name,
                "trace_id": trace_id,
                "span_id": span_id,
                "success": success
            },
            context=ctx
        )
        
        # Histogram for method latency
        method_latency_histogram = self.meter.create_histogram(
            "method_latency",
            description="Histogram of method execution latency",
            unit="ms"
        )
        method_latency_histogram.record(
            duration_ms,
            attributes={
                "method": method_name,
                "trace_id": trace_id,
                "span_id": span_id,
                "success": success
            },
            context=ctx
        )
    
    def instrument_sync_method(self, func: Callable, span_attrs: Dict[str, Any]) -> Callable:
        """Instrument a synchronous method."""
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            method_name = func.__qualname__
            links = self._get_links()
            ctx = context.get_current()
            
            with self.tracer.start_as_current_span(method_name, context=ctx, links=links) as span:
                start_time = time.time_ns()
                trace_id_hex = f"0x{span.context.trace_id:x}"
                span_id_hex = f"0x{span.context.span_id:x}"
                
                self._setup_span(span, method_name, args, kwargs, span_attrs)
                
                success = False
                try:
                    result = func(*args, **kwargs)
                    
                    if self.capture_result:
                        sanitized_result = redact_json(result)
                        span.set_attribute("result", str(sanitized_result))
                    
                    success = True
                    return result
                except Exception as e:
                    span.record_exception(e)
                    span.set_status(StatusCode.ERROR)
                    span.set_attribute("error", str(e))
                    raise
                finally:
                    self._record_metrics(
                        start_time, 
                        method_name, 
                        trace_id_hex, 
                        span_id_hex,
                        success
                    )
        
        return sync_wrapper
    
    def instrument_async_method(self, func: Callable, span_attrs: Dict[str, Any]) -> Callable:
        """Instrument an asynchronous method."""
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            method_name = func.__qualname__
            links = self._get_links()
            ctx = context.get_current()
            
            with self.tracer.start_as_current_span(method_name, context=ctx, links=links) as span:
                start_time = time.time_ns()
                trace_id_hex = f"0x{span.context.trace_id:x}"
                span_id_hex = f"0x{span.context.span_id:x}"
                
                self._setup_span(span, method_name, args, kwargs, span_attrs)
                
                success = False
                try:
                    result = await func(*args, **kwargs)
                    
                    if self.capture_result:
                        sanitized_result = redact_json(result)
                        span.set_attribute("result", str(sanitized_result))
                    
                    success = True
                    return result
                except Exception as e:
                    span.record_exception(e)
                    span.set_status(StatusCode.ERROR)
                    span.set_attribute("error", str(e))
                    raise
                finally:
                    self._record_metrics(
                        start_time, 
                        method_name, 
                        trace_id_hex, 
                        span_id_hex,
                        success
                    )
        
        return async_wrapper
    
    def instrument_method(self, func: Callable, span_attrs: Dict[str, Any]) -> Callable:
        """Instrument a method, handling both sync and async."""
        if asyncio.iscoroutinefunction(func):
            return self.instrument_async_method(func, span_attrs)
        else:
            return self.instrument_sync_method(func, span_attrs)


def instrument_class(
    tracer=None, 
    meter=None, 
    ignore_methods: Optional[List[str]] = None,
    link_span: bool = False,
    capture_args: bool = True,
    capture_result: bool = True
):
    """
    Decorator to instrument a class with OpenTelemetry tracing and metrics.
    
    Args:
        tracer: OpenTelemetry tracer instance
        meter: OpenTelemetry meter instance
        ignore_methods: List of method names to ignore for instrumentation
        link_span: Whether to link spans with parent spans
        capture_args: Whether to capture method arguments
        capture_result: Whether to capture method return values
    
    Returns:
        A decorator that instruments a class.
    """
    # Get tracer/meter now if provided, otherwise defer until decoration time
    tracer = tracer
    meter = meter
    ignore_methods = set(ignore_methods or [])
    
    def decorator(cls):
        nonlocal tracer, meter
        tracer = tracer or get_tracer()
        meter = meter or get_meter()
        
        instrumentor = MethodInstrumentor(
            tracer=tracer,
            meter=meter,
            link_span=link_span,
            capture_args=capture_args,
            capture_result=capture_result
        )
        
        for attr_name in dir(cls):
            if attr_name.startswith("__") or attr_name in ignore_methods:
                continue
            
            attr = getattr(cls, attr_name)
            is_static = isinstance(attr, staticmethod)
            is_class = isinstance(attr, classmethod)
            func = attr.__func__ if (is_static or is_class) else attr
            
            if not callable(func) or getattr(func, "_no_trace", False):
                continue
            
            # Get user-defined span attributes
            span_attrs = getattr(func, "_otel_span_attrs", {})
            
            wrapped = instrumentor.instrument_method(func, span_attrs)
            
            if is_static:
                setattr(cls, attr_name, staticmethod(wrapped))
            elif is_class:
                setattr(cls, attr_name, classmethod(wrapped))
            else:
                setattr(cls, attr_name, wrapped)
        
        return cls
    
    return decorator