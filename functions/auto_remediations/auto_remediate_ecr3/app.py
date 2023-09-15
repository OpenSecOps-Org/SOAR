import os
import boto3
import json
from botocore.exceptions import ClientError

# Get the cross-account role from the environment variables
CROSS_ACCOUNT_ROLE = os.environ['CROSS_ACCOUNT_ROLE']

# Create an STS client
sts = boto3.client('sts')

# Define the lifecycle policy as a JSON string
LIFECYCLE_POLICY_TEXT = json.dumps(
    {
        "rules": [
            {
                "rulePriority": 1,
                "description": "Keep only the two latest images.",
                "selection": {
                    "tagStatus": "any",
                    "countType": "imageCountMoreThan",
                    "countNumber": 2
                },
                "action": {
                    "type": "expire"
                }
            }
        ]
    }
)


def lambda_handler(data, _context):
    # Print the input data
    print(data)

    # Extract the finding and resource information from the input data
    finding = data['finding']
    resource = finding['Resources'][0]

    # Extract the account ID, region, repository ARN, and repository name from the resource information
    account_id = finding['AwsAccountId']
    region = resource['Region']
    repository_arn = resource['Id']
    repository_name = repository_arn.split('/', 1)[1]

    # Get the ECR client for the specified account and region
    client = get_client('ecr', account_id, region)

    try:
        # Set the lifecycle policy for the repository
        response = client.put_lifecycle_policy(
            repositoryName=repository_name,
            lifecyclePolicyText=LIFECYCLE_POLICY_TEXT
        )
    except ClientError as error:
        if error.response['Error']['Code'] == 'RepositoryNotFoundException':
            # If the repository is not found, suppress the finding and return the modified data
            print("The ECR repository wasn't found. Suppressing.")
            data['messages']['actions_taken'] = "The ECR repository wasn't found. This finding has been suppressed."
            data['actions']['suppress_finding'] = True
            return data
        raise error

    # Print the response from setting the lifecycle policy
    print(response)

    # Update the messages in the data to reflect the actions taken
    data['messages']['actions_taken'] = "The lifecycle policy has been set to keep only the two latest ECR images."
    data['messages']['actions_required'] = "None"

    # Return the modified data
    return data


def get_client(client_type, account_id, region, role=CROSS_ACCOUNT_ROLE):
    # Assume the cross-account role and create a client for the specified service
    other_session = sts.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"auto_remediate_ecr3_{account_id}"
    )
    access_key = other_session['Credentials']['AccessKeyId']
    secret_key = other_session['Credentials']['SecretAccessKey']
    session_token = other_session['Credentials']['SessionToken']
    return boto3.client(
        client_type,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=region
    )