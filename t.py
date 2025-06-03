# Enhanced sample script demonstrating integrated usage of Observix
# This shows the new enhanced bootstrap with log export functionality

import os
import asyncio
import json
from loguru import logger
from enhanced_bootstrap import bootstrap, setup_all_tracing, quickstart, bootstrap_with_log_export_only

print("=== Testing Enhanced Bootstrap Functionality ===")

# Option 1: Use enhanced setup_all_tracing with integrated log export
print("\n1. Using enhanced setup_all_tracing...")
result = setup_all_tracing(
    config_path="config.json",
    enable_loguru=True,
    loguru_bridge_to_std=True,
    enable_log_export=True
)

print(f"Service: {result['service']['name']} v{result['service']['version']}")
print(f"Environment: {result['service']['environment']}")
print(f"Loguru enabled: {result.get('loguru_enabled', False)}")
print(f"Log export enabled: {result.get('log_exporters', [])}")
print(f"Tracing exporters: {result.get('tracing_exporters', [])}")

# Option 2: Enhanced bootstrap with all new features
print("\n2. Using enhanced bootstrap with full configuration...")
"""
result = bootstrap(
    service_name="enhanced-user-service",
    version="3.0.0",
    environment="development",
    enable_tracing=True,
    enable_metrics=True,
    enable_logging=True,
    enable_log_export=True,
    enable_loguru=True,
    loguru_bridge_to_std=True,
    tracing_exporters=["console"],
    logging_exporters=["console", "otlp"],
    metrics_exporters=["console"],
    enable_class_instrumentation=True,
    class_instrumentation_config="config.json",
    attach_logs_to_spans=True,
    capture_print=True,
    log_level="INFO",
    sensitive_keys=["password", "api_key", "secret"]
)
"""

# Option 3: Quick start for rapid development
print("\n3. Using quickstart for rapid development...")
"""
quickstart_result = quickstart(
    service_name="quick-service",
    enable_loguru=True,
    enable_log_export=True,
    logging_exporters=["console"]
)
print(f"Quickstart service: {quickstart_result['service']['name']}")
"""

# Option 4: Log export only (useful for existing applications)
print("\n4. Using log export only...")
"""
log_only_result = bootstrap_with_log_export_only(
    service_name="log-only-service",
    version="1.0.0",
    environment="production",
    logging_exporters=["console", "otlp"],
    log_level="INFO",
    attach_logs_to_spans=False,  # No tracing in this mode
    capture_print=True,
    enable_loguru=True,
    loguru_bridge_to_std=True
)
print(f"Log-only service: {log_only_result['service']['name']}")
"""

print("\n=== Testing Instrumented Classes ===")

# Import and use the UserService class - it's already instrumented via config
import user_service
uservice = user_service.UserService()

# Test synchronous method with enhanced logging
print("\nTesting synchronous method...")
user_data = {"user": "enhanced-user-vincent", "password": "secure123", "api_key": "secret-key"}
create_result = uservice.create_user(user_data)
# logger.info(f"Create user result: {create_result}")

# # Test asynchronous method with enhanced logging
# print("\nTesting asynchronous method...")
# async def test_async_enhanced():
#     try:
#         user = await uservice.fetch_user("enhanced-async-testing")
#         logger.info(f"Fetched user: {user}")
#         print(f"Async result: {user}")
#     except Exception as e:
#         logger.error(f"Async test failed: {e}")

# # Run the async test
# asyncio.run(test_async_enhanced())

# # Test internal logging
# print("\nTesting internal logging...")
# uservice.log_internal()

# # Test print capture (if enabled)
# print("\nTesting print capture...")
# print("This print statement should be captured if capture_print=True")

# # Test loguru integration
# print("\nTesting loguru integration...")
# logger.info("This is a loguru info message")
# logger.warning("This is a loguru warning message")
# logger.error("This is a loguru error message")

# # Test sensitive data redaction
# print("\nTesting sensitive data handling...")
# sensitive_data = {
#     "username": "testuser",
#     "password": "should-be-redacted",
#     "api_key": "also-should-be-redacted",
#     "public_info": "this-is-fine"
# }
# logger.info(f"Processing data: {sensitive_data}")

# # Display comprehensive results
# print("\n=== Bootstrap Results Summary ===")
# print(f"Service Name: {result['service']['name']}")
# print(f"Service Version: {result['service']['version']}")
# print(f"Environment: {result['service']['environment']}")

# if 'tracer' in result:
#     print("✓ Tracing initialized")
# if 'meter' in result:
#     print("✓ Metrics initialized")
# if 'log_provider' in result:
#     print("✓ Log export initialized")
# if 'loguru_enabled' in result:
#     print(f"✓ Loguru integration: {result['loguru_enabled']}")
# if 'span_attachment_enabled' in result:
#     print(f"✓ Span attachment: {result['span_attachment_enabled']}")

# # Display active instrumentations
# print("\n=== Instrumentation Results ===")
# if "class_instrumentation_results" in result:
#     instrumented_classes = result['class_instrumentation_results']['instrumented']
#     print(f"✓ Instrumented {len(instrumented_classes)} classes:")
#     for cls in instrumented_classes:
#         print(f"  - {cls}")
    
#     if result['class_instrumentation_results']['errors']:
#         print(f"⚠ Instrumentation errors:")
#         for error in result['class_instrumentation_results']['errors']:
#             print(f"  - {error}")

# if "instrumentation_results" in result:
#     auto_results = result['instrumentation_results']
#     print(f"✓ Auto-instrumentation results:")
#     print(f"  - Success: {len(auto_results.get('success', []))}")
#     print(f"  - Failed: {len(auto_results.get('failed', []))}")
    
#     if auto_results.get('failed'):
#         print("  Failed libraries:")
#         for lib, error in auto_results['failed'].items():
#             print(f"    - {lib}: {error}")

# # Test configuration access
# print("\n=== Configuration Access ===")
# config = result.get('config', {})
# print(f"Loaded configuration keys: {list(config.keys())}")

# # Security configuration
# if 'redactor' in result:
#     print("✓ Custom security redactor configured")

# # Export information
# if 'log_exporters' in result:
#     print(f"✓ Log exporters: {result['log_exporters']}")
# if 'tracing_exporters' in result:
#     print(f"✓ Tracing exporters: {result['tracing_exporters']}")

# print("\n=== Enhanced Bootstrap Test Complete ===")