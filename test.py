import requests
from helpers.specials import no_trace
from observix import instrument_class, init_metrics, init_tracing
from loguru import logger
#Initialize telemetry
meter = init_metrics(
    service_name="user-service",
    version="2.3.1",
    environment="dev",
    exporters=["console"]
)

tracer = init_tracing(
    service_name="user-service",
    version="2.3.1",
    environment="dev"
)

print(tracer)

@instrument_class(tracer, meter )
class APIClient:
    def fetch_users(self):
        response = requests.get("https://jsonplaceholder.typicode.com/users")
        return response.json()





@instrument_class(tracer, meter )
class UserService:
    #@add_to_span(operation="create_user", static_tag="sync")
    def create_user(self, user_id):
        print(f"Creating user {user_id}")
        return {"status": "created", "user_id": user_id}

    #@add_to_span(operation="fetch_user", static_tag="async")
    async def fetch_user(self, user_id):
        print(f"Fetching user {user_id}...")
        await asyncio.sleep(1)
        return {"user_id": user_id, "name": "Alice"}

    @no_trace
    def log_internal(self):
        print("Log without tracing")



if __name__ == "__main__":
    import asyncio

    service = UserService()
    import time
    # Sync method
    #while True:
    result = service.create_user("u123")
    # print(result)

    # Async method
    # asyncio.run(service.fetch_user("u123"))

    # Not traced
    # service.log_internal()

    # apc = APIClient()
    # apc.fetch_users()
