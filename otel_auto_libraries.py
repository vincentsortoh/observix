INSTRUMENTATION_MAP = {
    # Web Frameworks
    "fastapi": ("opentelemetry.instrumentation.fastapi", "opentelemetry-instrumentation-fastapi", "FastAPIInstrumentor"),
    "flask": ("opentelemetry.instrumentation.flask", "opentelemetry-instrumentation-flask", "FlaskInstrumentor"),
    "django": ("opentelemetry.instrumentation.django", "opentelemetry-instrumentation-django", "DjangoInstrumentor"),

    # HTTP Clients
    "requests": ("opentelemetry.instrumentation.requests", "opentelemetry-instrumentation-requests", "RequestsInstrumentor"),
    "httpx": ("opentelemetry.instrumentation.httpx", "opentelemetry-instrumentation-httpx", "HTTPXClientInstrumentor"),
    "urllib": ("opentelemetry.instrumentation.urllib", "opentelemetry-instrumentation-urllib", "UrllibInstrumentor"),

    # Databases & ORMs
    "sqlalchemy": ("opentelemetry.instrumentation.sqlalchemy", "opentelemetry-instrumentation-sqlalchemy", "SQLAlchemyInstrumentor"),
    "psycopg2": ("opentelemetry.instrumentation.psycopg2", "opentelemetry-instrumentation-psycopg2", "Psycopg2Instrumentor"),
    "mysql": ("opentelemetry.instrumentation.mysql", "opentelemetry-instrumentation-mysql", "MySQLInstrumentor"),
    "pymongo": ("opentelemetry.instrumentation.pymongo", "opentelemetry-instrumentation-pymongo", "PymongoInstrumentor"),

    # Caching / Queues
    "redis": ("opentelemetry.instrumentation.redis", "opentelemetry-instrumentation-redis", "RedisInstrumentor"),
    "celery": ("opentelemetry.instrumentation.celery", "opentelemetry-instrumentation-celery", "CeleryInstrumentor"),

    # ASGI/WSGI Servers
    "asgiref": ("opentelemetry.instrumentation.asgi", "opentelemetry-instrumentation-asgi", "AsgiInstrumentor"),
    "wsgi": ("opentelemetry.instrumentation.wsgi", "opentelemetry-instrumentation-wsgi", "WSGIInstrumentor"),

    # gRPC
    "grpc": ("opentelemetry.instrumentation.grpc", "opentelemetry-instrumentation-grpc", "GrpcInstrumentor"),

    # You can uncomment if needed
    # "logging": ("opentelemetry.instrumentation.logging", "opentelemetry-instrumentation-logging", "LoggingInstrumentor"),
}
