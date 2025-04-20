import os
import boto3
import logging
from aws_utils.clients import get_client

SECURITY_ACCOUNT_ID = os.environ['SECURITY_ACCOUNT_ID']

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(_data, _context):
    # Create a SecurityHub client in the delegated security admin account
    securityhub_client = get_client('securityhub', SECURITY_ACCOUNT_ID)

    # List to hold the 12-character account IDs with Security Hub enabled
    enabled_accounts = []
    
    # Initialize the pagination
    paginator = securityhub_client.get_paginator('list_members')
    page_iterator = paginator.paginate(OnlyAssociated=True)
    
    # Iterate through each page of the response
    for page in page_iterator:
        logger.info(f"Received page: {page}")  # Log the raw API response
        for member in page['Members']:
            logger.info(f"Processing member: {member}")  # Log each member being processed
            # Check if the member account has Security Hub enabled
            if member['MemberStatus'] == 'Enabled':
                enabled_accounts.append(member['AccountId'])
    
    return enabled_accounts




