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

    # Extract necessary information from the input data
    finding = data['finding']
    resource = finding['Resources'][0]
    account_id = finding['AwsAccountId']
    region = resource['Region']
    repository_arn = resource['Id']
    repository_name = repository_arn.split('/', 1)[1]

    # Get the ECR client for the specified account and region
    client = get_client('ecr', account_id, region)

    try:
        # Set the image tag mutability to 'IMMUTABLE' for the repository
        response = client.put_image_tag_mutability(
            repositoryName=repository_name,
            imageTagMutability='IMMUTABLE'
        )
    except ClientError as error:
        # If the repository is not found, suppress the finding
        if error.response['Error']['Code'] == 'RepositoryNotFoundException':
            print("The ECR repository wasn't found. Suppressing.")
            data['messages']['actions_taken'] = "The ECR repository wasn't found. This finding has been suppressed."
            data['actions']['suppress_finding'] = True
            return data
        # If any other error occurs, raise it
        raise error

    # Print the response from setting the image tag mutability
    print(response)

    # Update the messages in the input data
    data['messages']['actions_taken'] = "Image tags have been set immutable."
    data['messages']['actions_required'] = "None"

    # Return the updated input data
    return data

# Function to get a client for the specified AWS service
def get_client(client_type, account_id, region, role=CROSS_ACCOUNT_ROLE):
    # Assume the specified role in the specified account
    other_session = sts.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"auto_remediate_ecr2_{account_id}"
    )

    # Get the temporary credentials from the assumed role
    access_key = other_session['Credentials']['AccessKeyId']
    secret_key = other_session['Credentials']['SecretAccessKey']
    session_token = other_session['Credentials']['SessionToken']

    # Create a client with the temporary credentials
    return boto3.client(
        client_type,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=region
    )