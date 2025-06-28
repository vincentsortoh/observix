import logging
import aiohttp
import asyncio
logger = logging.getLogger(__name__)

#from loguru import logger

class Purchase:
    def __init__(self):
        self.transactions = {}
        self.next_id = 1
    
    async def purchase(self, item, amount):
        logger.info("++++++++++ purchase +++++++")
        
        async with aiohttp.ClientSession() as session:
            # API Call 1: Create a new post to log the purchase
            post_data = {
                'title': f'Purchase: {item}',
                'body': f'Item: {item}, Amount: {amount}',
                'userId': 1
            }
            async with session.post('https://jsonplaceholder.typicode.com/posts', json=post_data) as response:
                post_result = await response.json()
                logger.info(f"Created post: {post_result}")
            
            # API Call 2: Get user details (simulating customer verification)
            async with session.get('https://jsonplaceholder.typicode.com/users/1') as response:
                user_data = await response.json()
                logger.info(f"User verified: {user_data['name']}")
            
            # API Call 3: Create a todo item for order fulfillment
            todo_data = {
                'title': f'Fulfill order for {item}',
                'completed': False,
                'userId': 1
            }
            async with session.post('https://jsonplaceholder.typicode.com/todos', json=todo_data) as response:
                todo_result = await response.json()
                logger.info(f"Created fulfillment task: {todo_result}")
        
        # Original purchase logic
        transaction_id = self.next_id
        self.transactions[transaction_id] = {
            'item': item,
            'amount': amount,
            'status': 'completed',
            'post_id': post_result.get('id'),
            'todo_id': todo_result.get('id')
        }
        self.next_id += 1
    
    def refund(self, transaction_id):
        logger.info("++++++++++ refund +++++++")
        if transaction_id in self.transactions:
            self.transactions[transaction_id]['status'] = 'refunded'
            logger.info("******** kk ***************")
            return f"Refund processed for transaction {transaction_id}"
        logger.info("******** kk ***************")
        return "Transaction not found"