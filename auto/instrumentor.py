"""
Author: 
Created on: 2025-05-10
Auto instrumentation logic for third-party libraries.

This module provides functions to automatically detect and instrument
supported libraries with OpenTelemetry instrumentation packages.
"""

import importlib
import sys
import logging
import pkg_resources
from typing import List, Optional, Dict, Any

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


def get_instrumentor_module_path(instrumentation_package: str) -> str:
    """
    Convert instrumentation package name to Python module path.
    
    Args:
        instrumentation_package (str): Name of the instrumentation package
        
    Returns:
        str: Python module path
    """
    return instrumentation_package.replace("-", ".")


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
        
    library_config = SUPPORTED_LIBRARIES[library_name]
    instrumentation_package = library_config["module"]
    instrumentor_class_name = library_config["class"]
    
    if not is_instrumentation_installed(instrumentation_package):
        logger.warning(
            f"Instrumentation package '{instrumentation_package}' for '{library_name}' "
            f"is not installed. Run 'pip install {instrumentation_package}' to install it."
        )
        return False
        
    try:

        module_path = get_instrumentor_module_path(instrumentation_package)
        module = importlib.import_module(module_path)
        
        if not hasattr(module, instrumentor_class_name):
            logger.error(
                f"Instrumentor class '{instrumentor_class_name}' not found in module '{module_path}'"
            )
            return False
            
        instrumentor_class = getattr(module, instrumentor_class_name)
        
        instrumentor = instrumentor_class()
        instrumentor.instrument()
        
        logger.info(f"Successfully instrumented {library_name} using {instrumentor_class_name}")
        return True
        
    except ImportError as e:
        logger.error(f"Failed to import instrumentation module for {library_name}: {str(e)}")
        return False
    except AttributeError as e:
        logger.error(f"Failed to find instrumentor class for {library_name}: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Failed to instrument {library_name}: {str(e)}")
        return False


def auto_instrument_libraries(libraries: Optional[List[str]] = None) -> Dict[str, bool]:
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


def get_supported_libraries() -> Dict[str, Dict[str, str]]:
    """
    Get the dictionary of supported libraries and their instrumentation info.
    
    Returns:
        dict: Dictionary mapping library names to their instrumentation config
    """
    return SUPPORTED_LIBRARIES.copy()


def get_instrumentation_status(libraries: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
    """
    Get the installation and instrumentation status for libraries.
    
    Args:
        libraries (List[str], optional): List of libraries to check.
            If None, will check all supported libraries.
            
    Returns:
        dict: Status information for each library
    """
    if libraries is None:
        libraries = list(SUPPORTED_LIBRARIES.keys())
    
    status = {}
    for lib in libraries:
        if lib not in SUPPORTED_LIBRARIES:
            status[lib] = {
                "supported": False,
                "library_installed": False,
                "instrumentation_installed": False,
                "error": f"Library '{lib}' is not supported"
            }
            continue
            
        library_config = SUPPORTED_LIBRARIES[lib]
        lib_installed = is_library_installed(lib)
        instr_installed = is_instrumentation_installed(library_config["module"])
        
        status[lib] = {
            "supported": True,
            "library_installed": lib_installed,
            "instrumentation_installed": instr_installed,
            "instrumentation_package": library_config["module"],
            "instrumentor_class": library_config["class"],
            "ready_to_instrument": lib_installed and instr_installed
        }
    
    return status