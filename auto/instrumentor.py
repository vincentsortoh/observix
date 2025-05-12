"""
Author: Vincent Sortoh
Created on: 2025-05-10
Auto instrumentation logic for third-party libraries.

This module provides functions to automatically detect and instrument
supported libraries with OpenTelemetry instrumentation packages.
"""

import importlib
import sys
import logging
import pkg_resources
from typing import List, Optional

from auto.libraries import SUPPORTED_LIBRARIES, DEFAULT_AUTO_INSTRUMENT

logger = logging.getLogger(__name__)


def is_library_installed(library_name: str) -> bool:
    """
    Check if a library is installed in the current environment.
    
    Args:
        library_name (str): Name of the library to check
        
    Returns:
        bool: True if the library is installed, False otherwise
    """
    try:
        importlib.import_module(library_name)
        return True
    except ImportError:
        return False


def is_instrumentation_installed(instrumentation_package: str) -> bool:
    """
    Check if an instrumentation package is installed.
    
    Args:
        instrumentation_package (str): Name of the instrumentation package
        
    Returns:
        bool: True if the instrumentation package is installed, False otherwise
    """
    try:
        pkg_resources.get_distribution(instrumentation_package)
        return True
    except pkg_resources.DistributionNotFound:
        return False


def auto_instrument(library_name: str) -> bool:
    """
    Automatically instrument a specific library if it's installed.
    
    Args:
        library_name (str): Name of the library to instrument
        
    Returns:
        bool: True if instrumentation was successful, False otherwise
    """
    if library_name not in SUPPORTED_LIBRARIES:
        logger.warning(f"Library '{library_name}' is not supported for auto-instrumentation")
        return False
        
    if not is_library_installed(library_name):
        logger.debug(f"Library '{library_name}' is not installed, skipping instrumentation")
        return False
        
    instrumentation_package = SUPPORTED_LIBRARIES[library_name]
    
    if not is_instrumentation_installed(instrumentation_package):
        logger.warning(
            f"Instrumentation package '{instrumentation_package}' for '{library_name}' "
            f"is not installed. Run 'pip install {instrumentation_package}' to install it."
        )
        return False
        
    try:
        module = importlib.import_module(instrumentation_package.replace("-", "."))
        
        if hasattr(module, "instrument"):
            module.instrument()
        elif hasattr(module, "instrumentor"):
            instrumentor = getattr(module, "instrumentor")()
            instrumentor.instrument()
        else:
            logger.warning(f"Could not find instrumentation entry point for {library_name}")
            return False
            
        logger.info(f"Successfully instrumented {library_name}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to instrument {library_name}: {str(e)}")
        return False


def auto_instrument_libraries(libraries: Optional[List[str]] = None) -> dict:
    """
    Automatically instrument multiple libraries.
    
    Args:
        libraries (List[str], optional): List of libraries to instrument.
            If None, will instrument libraries in DEFAULT_AUTO_INSTRUMENT list.
            
    Returns:
        dict: Map of library names to instrumentation status (True/False)
    """
    if libraries is None:
        libraries = DEFAULT_AUTO_INSTRUMENT
        
    results = {}
    for lib in libraries:
        results[lib] = auto_instrument(lib)
        
    successful = [lib for lib, status in results.items() if status]
    failed = [lib for lib, status in results.items() if not status]
    
    if successful:
        logger.info(f"Successfully instrumented libraries: {', '.join(successful)}")
    if failed:
        logger.warning(f"Failed to instrument libraries: {', '.join(failed)}")
        
    return results