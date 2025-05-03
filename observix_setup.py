# otel_setup.py
"""
Author: Vincent Sortoh
Created on: 2025-05-03
Description: 
    This script handles selective OpenTelemetry instrumentation of Python classes 
    based on a configurable JSON file. It dynamically loads modules, identifies 
    classes to instrument, and applies the `observix.instrument_class()` decorator.

Configuration:
    config.json fields:
    - instrument_classes: List of fully qualified class names to instrument
    - ignore_classes: List of fully qualified class names to skip
    - modules_to_instrument: Specific module paths to load
    - packages_to_instrument: Packages to recursively search for modules
"""

import os
import importlib
import json
from typing import List
from pathlib import Path
import observix 

processed_classes = set()

def load_config(config_file: str = "config.json") -> dict:
    with open(config_file, "r") as f:
        return json.load(f)

def module_names_from_package(pkg: str) -> list:
    """Convert a package like 'my_package.module' into all module paths under it."""
    path = Path(pkg.replace(".", "/"))
    if not path.exists():
        return []
    return [
        f"{pkg}.{p.with_suffix('').name}"
        for p in path.glob("*.py")
        if not p.name.startswith("__")
    ]

def instrument_selected_classes(config: dict, base_path: str = "my_package"):
    
    instrument_classes = set(config.get("instrument_classes", []))
    ignore_classes = set(config.get("ignore_classes", []))
    modules_to_instrument = config.get("modules_to_instrument", [])
    packages_to_instrument = config.get("packages_to_instrument", [])

    module_names = set()

    if modules_to_instrument:
        module_names.update(modules_to_instrument)

    if packages_to_instrument:
        for pkg in packages_to_instrument:
            module_names.update(module_names_from_package(pkg))

    if not module_names:
        for module_path in Path(base_path).rglob("*.py"):
            if module_path.name.startswith("__"):
                continue
            rel_path = module_path.relative_to(base_path).with_suffix('')
            parts = rel_path.parts
            module_name = ".".join([base_path.replace('/', '.')] + list(parts))
            module_names.add(module_name)

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
                    continue

                if not instrument_classes or full_class_name in instrument_classes:
                    observix.instrument_class()(attr)
                    processed_classes.add(full_class_name)
                    print(f"Instrumented: {full_class_name}")

        except ModuleNotFoundError:
            print(f"Module not found: {module_name}")
        except Exception as e:
            print(f"Error while instrumenting {module_name}: {e}")

