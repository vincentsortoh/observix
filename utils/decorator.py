"""
Decorators for trace instrumentation control.

This module provides decorators that can be used to control the 
instrumentation behavior for specific functions or methods.
"""


def add_to_span(**span_attrs):
    """
    Decorator to attach OpenTelemetry span attributes to a function.

    This decorator sets a `_otel_span_attrs` attribute on the decorated function,
    which can be used by tracing logic to enrich spans with custom attributes.

    Args:
        **span_attrs: Arbitrary keyword arguments representing span attribute names and values.

    Returns:
        Callable: A decorator that attaches the given span attributes to a function.
        
    Example:
        @add_to_span(operation_type="database", database_name="users")
        def query_database(user_id):
            # Function implementation
            pass
    """
    def decorator(func):
        setattr(func, "_otel_span_attrs", span_attrs)
        return func
    return decorator


def no_trace(func):
    """
    Decorator to mark a function as excluded from tracing.

    When applied, this decorator sets a `_no_trace` attribute on the function
    to indicate that it should not be included in tracing or instrumentation logic.

    Args:
        func (Callable): The function to be marked as not traceable.

    Returns:
        Callable: The same function with a `_no_trace` attribute set to True.
        
    Example:
        @no_trace
        def sensitive_function():
            # This function will not be traced
            pass
    """
    func._no_trace = True
    return func