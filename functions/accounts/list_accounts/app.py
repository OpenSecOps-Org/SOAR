import os
import boto3
import logging

# Get the cross-account role from environment variables
CROSS_ACCOUNT_ROLE = os.environ['CROSS_ACCOUNT_ROLE']
SECURITY_ACCOUNT_ID = os.environ['SECURITY_ACCOUNT_ID']

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Create the non-expiring STS client
sts_client = boto3.client('sts')


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


# Function to get a client for the security account
def get_client(client_type, account_id, role=CROSS_ACCOUNT_ROLE):
    # Assume the specified role in the specified account
    other_session = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"list_accounts_{account_id}"
    )

    # Get the access key, secret key, and session token from the assumed role session
    access_key = other_session['Credentials']['AccessKeyId']
    secret_key = other_session['Credentials']['SecretAccessKey']
    session_token = other_session['Credentials']['SessionToken']

    # Create a client using the assumed role credentials
    return boto3.client(
        client_type,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )


