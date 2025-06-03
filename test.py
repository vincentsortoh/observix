# Sample script demonstrating integrated usage of Observix with automatic loguru capture
# This shows both manual instrumentation and auto instrumentation via configuration

import os
import asyncio
import json
from loguru import logger
from bootstrap import bootstrap, setup_all_tracing

# Option 1: Use setup_all_tracing with automatic loguru integration
# This is the simplest approach that handles everything including loguru
result = setup_all_tracing(
    config_path="config.json",
    enable_loguru=True,
    loguru_bridge_to_std=True  # This ensures loguru logs are captured in spans
)

# Option 2: Manually bootstrap with loguru integration
"""
result = bootstrap(
    service_name="user-service",
    version="2.3.1",
    environment="dev",
    enable_tracing=True,
    enable_metrics=True,
    enable_loguru=True,
    loguru_bridge_to_std=True,  # Key parameter for span capture
    tracing_exporters=["console"],
    metrics_exporters=["console"],
    enable_class_instrumentation=True,
    class_instrumentation_config="config.json"
)
"""

print("Bootstrap result:")
print(f"- Service: {result['service']}")
print(f"- Tracer initialized: {'tracer' in result}")
print(f"- Meter initialized: {'meter' in result}")
print(f"- Loguru enabled: {result.get('loguru_enabled', False)}")

# Import and use the UserService class - it's already instrumented
import user_service
uservice = user_service.UserService()

# Test loguru logging - these should now be captured in spans
logger.info("Starting user service tests")
logger.debug("This is a debug message from loguru")

# Test synchronous method with loguru logging
user_data = {"user": "user-vincent", "password": "123444"}
logger.info(f"Creating user with data: {user_data}")
result = uservice.create_user(user_data)
logger.success(f"Create user result: {result}")

# Test asynchronous method with loguru logging
async def test_async():
    logger.info("Starting async user fetch test")
    user = await uservice.fetch_user("async-testing")
    logger.info(f"Fetched user: {user}")
    logger.warning("This is a warning from async context")

# Run the async test
logger.info("Running async test")
asyncio.run(test_async())


# Test logging inside instrumented method
uservice.log_internal()

# # Display active instrumentations
# print("\nActive instrumentations:")
# if "class_instrumentation_results" in result:
#     print(f"Instrumented classes: {len(result['class_instrumentation_results']['instrumented'])}")
#     for cls in result['class_instrumentation_results']['instrumented']:
#         print(f" - {cls}")

# print(f"\nLoguru integration status: {result.get('loguru_enabled', 'Not enabled')}")