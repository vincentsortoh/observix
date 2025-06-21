"""
Author: Vincent Sortoh
Created on: 2025-05-10

Library mappings for automatic instrumentation.

This module defines the mapping between supported libraries and their
corresponding OpenTelemetry instrumentation packages and classes.
"""

# Map of supported libraries to their instrumentation packages and classes
SUPPORTED_LIBRARIES = {
    # HTTP and Web Frameworks
    "flask": {
        "module": "opentelemetry-instrumentation-flask",
        "class": "FlaskInstrumentor",
    },
    "django": {
        "module": "opentelemetry-instrumentation-django",
        "class": "DjangoInstrumentor",
    },
    "fastapi": {
        "module": "opentelemetry-instrumentation-fastapi",
        "class": "FastAPIInstrumentor",
    },
    "tornado": {
        "module": "opentelemetry-instrumentation-tornado",
        "class": "TornadoInstrumentor",
    },
    "pyramid": {
        "module": "opentelemetry-instrumentation-pyramid",
        "class": "PyramidInstrumentor",
    },
    "starlette": {
        "module": "opentelemetry-instrumentation-starlette",
        "class": "StarletteInstrumentor",
    },
    "aiohttp-client": {
        "module": "opentelemetry-instrumentation-aiohttp-client",
        "class": "AioHttpClientInstrumentor",
    },
    "aiohttp": {
        "module": "opentelemetry-instrumentation-aiohttp_client",
        "class": "AioHttpClientInstrumentor",
    },
    "aiohttp-server": {
        "module": "opentelemetry-instrumentation-aiohttp-server",
        "class": "AioHttpServerInstrumentor",
    },
    "requests": {
        "module": "opentelemetry-instrumentation-requests",
        "class": "RequestsInstrumentor",
    },
    "urllib": {
        "module": "opentelemetry-instrumentation-urllib",
        "class": "URLLibInstrumentor",
    },
    "urllib3": {
        "module": "opentelemetry-instrumentation-urllib3",
        "class": "URLLib3Instrumentor",
    },
    "httpx": {
        "module": "opentelemetry-instrumentation-httpx",
        "class": "HTTPXInstrumentor",
    },
    # Messaging Systems
    "kafka": {
        "module": "opentelemetry-instrumentation-kafka-python",
        "class": "KafkaInstrumentor",
    },
    "pika": {
        "module": "opentelemetry-instrumentation-pika",
        "class": "PikaInstrumentor",
    },
    "celery": {
        "module": "opentelemetry-instrumentation-celery",
        "class": "CeleryInstrumentor",
    },
    # Databases
    "psycopg2": {
        "module": "opentelemetry-instrumentation-psycopg2",
        "class": "Psycopg2Instrumentor",
    },
    "pymongo": {
        "module": "opentelemetry-instrumentation-pymongo",
        "class": "PymongoInstrumentor",
    },
    "redis": {
        "module": "opentelemetry-instrumentation-redis",
        "class": "RedisInstrumentor",
    },
    "sqlalchemy": {
        "module": "opentelemetry-instrumentation-sqlalchemy",
        "class": "SQLAlchemyInstrumentor",
    },
    "mysql": {
        "module": "opentelemetry-instrumentation-mysql",
        "class": "MySQLInstrumentor",
    },
    "pymysql": {
        "module": "opentelemetry-instrumentation-pymysql",
        "class": "PyMySQLInstrumentor",
    },
    "asyncpg": {
        "module": "opentelemetry-instrumentation-asyncpg",
        "class": "AsyncPGInstrumentor",
    },
    # AWS
    "boto": {
        "module": "opentelemetry-instrumentation-boto",
        "class": "BotoInstrumentor",
    },
    "botocore": {
        "module": "opentelemetry-instrumentation-botocore",
        "class": "BotocoreInstrumentor",
    },
    # gRPC
    "grpc": {
        "module": "opentelemetry-instrumentation-grpc",
        "class": "GrpcInstrumentor",
    },
    # Asynchronous
    "asyncio": {
        "module": "opentelemetry-instrumentation-asyncio",
        "class": "AsyncioInstrumentor",
    },
    # Other
    "jinja2": {
        "module": "opentelemetry-instrumentation-jinja2",
        "class": "Jinja2Instrumentor",
    },
    "system-metrics": {
        "module": "opentelemetry-instrumentation-system-metrics",
        "class": "SystemMetricsInstrumentor",
    },
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
    "celery",
]
