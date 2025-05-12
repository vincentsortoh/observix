import asyncio
from loguru import logger
from utils.decorator import no_trace, add_to_span

#logger = logging.getLogger("jj")
class UserService:

    def __init__(self):
        print("checking if __init__ would be instrumented")

    @add_to_span(operation="create_user", static_tag="sync", me="testing")
    def create_user(self, payload: dict):
        logger.error(f"Creating user with password {payload['password']}")
        return {"status": "created", "user_id": payload['password'], "password": "fdgddfdf"}

    @add_to_span(operation="fetch_user", static_tag="async", description="tesing-async")
    async def fetch_user(self, user_id):
        print(f"Fetching user {user_id}...")
        await asyncio.sleep(1)
        return {"password": user_id, "name": "Alice"}

    @no_trace
    def log_internal(self):
        print("Log without tracing")