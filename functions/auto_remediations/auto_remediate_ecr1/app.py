import os
import boto3
from botocore.exceptions import ClientError

# Get the cross account role from the environment variables
CROSS_ACCOUNT_ROLE = os.environ['CROSS_ACCOUNT_ROLE']

# Create an STS client
sts = boto3.client('sts')

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

# Function to get a client for the specified AWS service using the cross account role
def get_client(client_type, account_id, region, role=CROSS_ACCOUNT_ROLE):
    # Assume the cross account role using STS
    other_session = sts.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"auto_remediate_ecr1_{account_id}"
    )
    # Get the access key, secret key, and session token from the assumed role session
    access_key = other_session['Credentials']['AccessKeyId']
    secret_key = other_session['Credentials']['SecretAccessKey']
    session_token = other_session['Credentials']['SessionToken']

    # Create a client for the specified AWS service using the assumed role credentials
    return boto3.client(
        client_type,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=region
    )