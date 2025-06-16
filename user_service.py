import asyncio

# from loguru import logger
import json
import logging
from utils.decorator import no_trace, add_to_span

logger = logging.getLogger()


# custom_logger = logger.bind(context="user_service")
class UserService:

    def __init__(self):
        print("checking if __init__ would be instrumented")

    @add_to_span(operation="create_user", static_tag="sync", me="testing")
    def create_user(self, payload: dict):
        print("!!!!!!!!!! test print capturing !!!!!!!!!!!!!")
        logger.error(f"Creating user with password {payload['password']}")
        logger.info(
            "DB connection failed {}".format(
                json.dumps(
                    {
                        "validation.errors": ["missing_email", "invalid_phone"],
                        "order.id": "ddfs",
                    }
                )
            )
        )
        return {
            "status": "created",
            "user_id": payload["password"],
            "password": "fdgddfdf",
        }

    @add_to_span(operation="fetch_user", static_tag="async", description="tesing-async")
    async def fetch_user(self, user_id):
        logger.info(f"Fetching user {user_id} jkkk  ...")
        await asyncio.sleep(1)
        return {"password": user_id, "name": "Alice"}

    @no_trace
    def log_internal(self):
        print("Log without tracing")
