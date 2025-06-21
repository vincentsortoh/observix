import asyncio

# from loguru import logger
import json
import logging
from utils.decorator import no_trace, add_to_span

logger = logging.getLogger(__name__)

from loguru import logger as logger2

# from opentelemetry.instrumentation.requests import RequestsInstrumentor

# RequestsInstrumentor().instrument()


#from loguru import logger


# custom_logger = logger.bind(context="user_service")
class UserService:

    def __init__(self):
        print("checking if __init__ would be instrumented")


    def create_user(self, payload: dict):
        print("!!!!!!!!!! test print capturing !!!!!!!!!!!!!")
        logger.info("this is loguru log")
        logger.info(f"Creating user with password {payload['password']}")
        import requests
        requests.get("https://google.com")
        # logger.info(
        #     "DB connection failed {}".format(
        #         json.dumps(
        #             {
        #                 "validation.errors": ["missing_email", "invalid_phone"],
        #                 "order.id": "ddfs",
        #             }
        #         )
        #     )
        # )
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


#from loguru import logger

# class Purchase:
#     def __init__(self):
#         self.transactions = {}
#         self.next_id = 1
    
#     @add_to_span(operation="purchase", static_tag="async", description="tesing-purchase")
#     async def purchase(self, item, amount):
#         logger.info("********** purchase **********")
#         transaction_id = self.next_id
#         self.transactions[transaction_id] = {
#             'item': item,
#             'amount': amount,
#             'status': 'completed'
#         }
#         self.next_id += 1
#         return f"Purchase successful. Transaction ID: {transaction_id}"
    
#     def refund(self, transaction_id):
#         logger.info("********** refund **********")
#         if transaction_id in self.transactions:
#             self.transactions[transaction_id]['status'] = 'refunded'
#             return f"Refund processed for transaction {transaction_id}"
#         return "Transaction not found"