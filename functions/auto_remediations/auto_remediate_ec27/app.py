import os
import boto3
from aws_utils.clients import get_client

# Define the lambda_handler function
def lambda_handler(data, _context):
    # Print the input data
    print(data)

    # Get the 'finding' key from the input data
    finding = data['finding']

    # Get the 'AwsAccountId' and 'Region' values from the 'finding' dictionary
    account_id = finding['AwsAccountId']
    region = finding['Resources'][0]['Region']

    # Get the client for the specified client_type, account_id, and region
    client = get_client('ec2', account_id, region)

    # Enable EBS encryption by default
    response = client.enable_ebs_encryption_by_default(
        DryRun=False
    )
    # Print the response
    print(response)

    # Update the 'actions_taken' and 'actions_required' keys in the input data
    data['messages']['actions_taken'] = "EBS encryption has been enabled on the account level and will affect new volumes only."
    data['messages']['actions_required'] = "None"
    
    # Return the updated input data
    return data

