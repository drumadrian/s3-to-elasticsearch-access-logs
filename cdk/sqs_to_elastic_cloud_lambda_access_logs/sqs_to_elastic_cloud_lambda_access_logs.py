from __future__ import print_function
import os
import logging
logger = logging.getLogger()
# logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)



def lambda_handler(event, context):
    logger.info('## ENVIRONMENT VARIABLES')
    logger.info(os.environ)
    logger.info('## EVENT')
    logger.info(event)
    logger.info("it worked, you can sleep now")










