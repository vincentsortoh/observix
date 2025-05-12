# Sample script demonstrating integrated usage of Observix
# This shows both manual instrumentation and auto instrumentation via configuration

import os
import asyncio
import json
from loguru import logger
from bootstrap import bootstrap, setup_all_tracing
from logging_helpers.integrations import setup_loguru_with_trace_context, bridge_loguru_to_std_logging

# Option 1: Use setup_all_tracing to set up everything from config
# This is the simplest approach that handles both tracing setup and class instrumentation

# setup_loguru_with_trace_context()

# # Also bridge loguru to standard logging to ensure spans can capture logs
# bridge_loguru_to_std_logging()

result = setup_all_tracing("config.json")


# Option 2: Manually bootstrap with specific settings and class instrumentation
"""
result = bootstrap(
    service_name="user-service",
    version="2.3.1",
    environment="dev",
    enable_tracing=True,
    enable_metrics=True,
    tracing_exporters=["console"],
    metrics_exporters=["console"],
    enable_class_instrumentation=True,
    class_instrumentation_config="config.json"
)
"""

# Option 3: Hybrid approach - bootstrap core components and selective instrumentation
"""
# Define settings
settings = {
    "service_name": "user-service",
    "version": "2.3.1",
    "environment": "dev",
    "tracing_exporters": ["console"],
    "metrics_exporters": ["console"]
}

# Bootstrap core components
result = bootstrap(**settings)

# Get references to the initialized components
tracer = result["tracer"]
meter = result["meter"]

# Import the instrumentation module to use directly if needed
from class_instrumentor import instrument_selected_classes

# Selectively instrument classes
instrument_config = {
    "instrument_classes": [
        "user_service.UserService",
        "order_service.OrderService"
    ],
    "ignore_classes": [
        "module.helper.HelperClass"
    ],
    "modules_to_instrument": [
        "user_service",
        "order_service"
    ]
}

instrumentation_results = instrument_selected_classes(
    tracer=tracer,
    meter=meter,
    config=instrument_config
)

print(f"Instrumented classes: {instrumentation_results['instrumented']}")
"""

# Import and use the UserService class - it's already instrumented

import user_service
uservice = user_service.UserService()

# Test synchronous method
user_data = {"user": "user-vincent", "password": "123444"}
result = uservice.create_user(user_data)
logger.info(f"Create user result: {result}")

# Test asynchronous method
async def test_async():
    user = await uservice.fetch_user("asynct-testing")
    print(f"Fetched user: {user}")

# Run the async test
asyncio.run(test_async())


uservice.log_internal()

# Display active instrumentations
# print("\nActive instrumentations:")
# if "class_instrumentation_results" in result:
#     print(f"Instrumented classes: {len(result['class_instrumentation_results']['instrumented'])}")
#     for cls in result['class_instrumentation_results']['instrumented']:
#         print(f" - {cls}")