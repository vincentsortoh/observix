import logging
logger = logging.getLogger(__name__)

#from loguru import logger

class Purchase:
    def __init__(self):
        self.transactions = {}
        self.next_id = 1
    
    async def purchase(self, item, amount):
        logger.info("++++++++++ purchase +++++++")
        transaction_id = self.next_id
        self.transactions[transaction_id] = {
            'item': item,
            'amount': amount,
            'status': 'completed'
        }
        self.next_id += 1
        return f"Purchase successful. Transaction ID: {transaction_id}"
    
    def refund(self, transaction_id):
        logger.info("++++++++++ refund +++++++")
        if transaction_id in self.transactions:
            self.transactions[transaction_id]['status'] = 'refunded'
            logger.info("******** kk ***************")
            return f"Refund processed for transaction {transaction_id}"
        logger.info("******** kk ***************")
        return "Transaction not found"