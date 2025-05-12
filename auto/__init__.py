"""
Observix Auto Instrumentation Package

This package provides automatic instrumentation for popular Python libraries
and modules using OpenTelemetry instrumentation packages.
"""

from auto.instrumentor import auto_instrument_libraries, auto_instrument

__all__ = ['auto_instrument_libraries', 'auto_instrument']