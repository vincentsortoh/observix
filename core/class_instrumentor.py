"""
Author: 
Created on: 2025-05-11

Class instrumentation module for Observix.

This module provides functionality to selectively instrument Python classes
based on configuration, either automatically or manually.
"""

import os
import importlib
import json
from typing import List, Set, Dict, Any, Optional, Union
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

processed_classes: Set[str] = set()

def load_config(config_file: str = "config.json") -> dict:
    with open(config_file, "r") as f:
        return json.load(f)

def module_names_from_package(pkg: str) -> List[str]:
    """Convert a package like 'my_package.module' into all module paths under it."""
    try:
        module = importlib.import_module(pkg)
        if hasattr(module, "__path__"):
            path = Path(module.__path__[0])
        else:
            return [pkg]
    except ImportError:
        path = Path(pkg.replace(".", "/"))
        if not path.exists():
            logger.warning(f"Package path not found: {pkg}")
            return []
    
    return [
        f"{pkg}.{p.stem}"
        for p in path.glob("*.py")
        if not p.stem.startswith("__")
    ]

def get_modules_to_instrument(config: Dict[str, Any], base_path: Optional[str] = None) -> Set[str]:
    """
    Determine all modules that should be instrumented based on configuration.
    
    Args:
        config: Configuration dictionary
        base_path: Optional base path to search for modules
        
    Returns:
        Set of module names to instrument
    """
    modules_to_instrument = set(config.get("modules_to_instrument", []))
    packages_to_instrument = config.get("packages_to_instrument", [])

    for pkg in packages_to_instrument:
        modules_to_instrument.update(module_names_from_package(pkg))


    if not modules_to_instrument and base_path:
        for module_path in Path(base_path).rglob("*.py"):
            if module_path.name.startswith("__"):
                continue
            rel_path = module_path.relative_to(base_path).with_suffix('')
            parts = rel_path.parts
            module_name = ".".join([base_path.replace('/', '.')] + list(parts))
            modules_to_instrument.add(module_name)
    
    return modules_to_instrument

def instrument_selected_classes(
    tracer, 
    meter, 
    config: Union[Dict[str, Any], str],
    base_path: Optional[str] = None,
    instrument_decorator=None
):
    """
    Selectively instrument classes based on configuration.
    
    Args:
        tracer: OpenTelemetry tracer
        meter: OpenTelemetry meter
        config: Either a config dictionary or path to a config file
        base_path: Optional base path for module discovery
        instrument_decorator: Function to use for instrumentation (defaults to observix.instrument_class)
        
    Returns:
        Dictionary with instrumentation results
    """
    # Import observix here to avoid circular imports
    if instrument_decorator is None:
        from core.instrumentation import instrument_class
        
        instrument_decorator = lambda cls: instrument_class(tracer, meter)(cls)
    
    if isinstance(config, str):
        config = load_config(config)
    
    instrument_classes = set(config.get("instrument_classes", []))
    ignore_classes = set(config.get("ignore_classes", []))
    
    module_names = get_modules_to_instrument(config, base_path)
    
    results = {
        "instrumented": [],
        "ignored": [],
        "errors": []
    }
    
    for module_name in module_names:
        try:
            module = importlib.import_module(module_name)
            for attr_name in dir(module):
                if attr_name.startswith("__"):
                    continue

                attr = getattr(module, attr_name)
                if not isinstance(attr, type):
                    continue

                full_class_name = f"{module_name}.{attr.__name__}"

                if full_class_name in ignore_classes or full_class_name in processed_classes:
                    results["ignored"].append(full_class_name)
                    continue

                if not instrument_classes or full_class_name in instrument_classes:
                    try:
                        instrument_decorator(attr)
                        processed_classes.add(full_class_name)
                        results["instrumented"].append(full_class_name)
                        logger.info(f"Instrumented: {full_class_name}")
                    except Exception as e:
                        error_info = {"class": full_class_name, "error": str(e)}
                        results["errors"].append(error_info)
                        logger.error(f"Failed to instrument {full_class_name}: {e}")

        except ModuleNotFoundError:
            logger.warning(f"Module not found: {module_name}")
        except Exception as e:
            error_info = {"module": module_name, "error": str(e)}
            results["errors"].append(error_info)
            logger.error(f"Error while instrumenting {module_name}: {e}")
    
    return results