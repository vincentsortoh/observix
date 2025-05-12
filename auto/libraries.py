"""
Author: Vincent Sortoh
Created on: 2025-05-10

Library mappings for automatic instrumentation.

This module defines the mapping between supported libraries and their
corresponding OpenTelemetry instrumentation packages.
"""

# Map of supported libraries to their instrumentation packages
SUPPORTED_LIBRARIES = {
    # HTTP and Web Frameworks
    "flask": "opentelemetry-instrumentation-flask",
    "django": "opentelemetry-instrumentation-django",
    "fastapi": "opentelemetry-instrumentation-fastapi",
    "tornado": "opentelemetry-instrumentation-tornado",
    "pyramid": "opentelemetry-instrumentation-pyramid",
    "starlette": "opentelemetry-instrumentation-starlette",
    "aiohttp-client": "opentelemetry-instrumentation-aiohttp-client",
    "aiohttp-server": "opentelemetry-instrumentation-aiohttp-server",
    "requests": "opentelemetry-instrumentation-requests",
    "urllib": "opentelemetry-instrumentation-urllib",
    "urllib3": "opentelemetry-instrumentation-urllib3",
    "httpx": "opentelemetry-instrumentation-httpx",
    
    # Messaging Systems
    "kafka": "opentelemetry-instrumentation-kafka-python",
    "pika": "opentelemetry-instrumentation-pika",
    "celery": "opentelemetry-instrumentation-celery",
    
    # Databases
    "psycopg2": "opentelemetry-instrumentation-psycopg2",
    "pymongo": "opentelemetry-instrumentation-pymongo",
    "redis": "opentelemetry-instrumentation-redis",
    "sqlalchemy": "opentelemetry-instrumentation-sqlalchemy",
    "mysql": "opentelemetry-instrumentation-mysql",
    "pymysql": "opentelemetry-instrumentation-pymysql",
    "asyncpg": "opentelemetry-instrumentation-asyncpg",
    
    # AWS
    "boto": "opentelemetry-instrumentation-boto",
    "botocore": "opentelemetry-instrumentation-botocore",
    
    # gRPC
    "grpc": "opentelemetry-instrumentation-grpc",
    
    # Asynchronous
    "asyncio": "opentelemetry-instrumentation-asyncio",
    
    # Other
    "jinja2": "opentelemetry-instrumentation-jinja2",
    "system-metrics": "opentelemetry-instrumentation-system-metrics",
}

# Libraries that are instrumented by default if found
DEFAULT_AUTO_INSTRUMENT = [
    "flask",
    "django",
    "fastapi", 
    "requests", 
    "sqlalchemy",
    "redis",
    "pymongo",
    "celery"
]