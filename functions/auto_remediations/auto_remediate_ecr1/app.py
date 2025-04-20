import os
import boto3
from botocore.exceptions import ClientError
from aws_utils.clients import get_client

# Lambda handler function
def lambda_handler(data, _context):
    # Print the input data
    print(data)

    # Extract the finding and resource information from the input data
    finding = data['finding']
    resource = finding['Resources'][0]

    # Extract the account ID and region from the finding and resource information
    account_id = finding['AwsAccountId']
    region = resource['Region']

    # Get the client for the specified AWS service using the cross account role
    client = get_client('ecr', account_id, region)

    # Configure the registry scanning for the client
    try:
        response = client.put_registry_scanning_configuration(
            scanType='ENHANCED',
            rules=[
                {
                    'scanFrequency': 'SCAN_ON_PUSH',
                    'repositoryFilters': [
                        {
                            'filter': '*',
                            'filterType': 'WILDCARD'
                        },
                    ]
                },
            ]
        )
        # Print the response from the client
        print(response)
    except ClientError as error:
        print(f"Error configuring registry scanning: {error}")
        data['messages']['actions_taken'] = "Could not configure registry scanning."
        data['actions']['autoremediation_not_done'] = True
        return data

    # Update the messages in the input data
    data['messages']['actions_taken'] = "Images are now scanned on push using enhanced scanning."
    data['messages']['actions_required'] = "None"

    # Return the updated input data
    return data

