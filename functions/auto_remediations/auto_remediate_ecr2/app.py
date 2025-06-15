"""
ECR.2 AUTOREMEDIATION - CONFIGURE ECR REPOSITORY TAG IMMUTABILITY

This Lambda function automatically remediates AWS Security Hub findings for ECR.2
(ECR repositories should have tag mutability configured as immutable).

Target Resources:
- Amazon ECR repositories
- Both private repositories

Remediation Actions:
1. Extracts repository name from repository ARN
2. Configures image tag mutability to 'IMMUTABLE' for the specific repository
3. Prevents image tags from being overwritten or deleted

Validation Commands:
# Check repository tag mutability configuration
aws ecr describe-repositories --repository-names <repository-name>

# Verify tag mutability is set to IMMUTABLE
aws ecr describe-repositories --repository-names <repository-name> --query 'repositories[0].imageTagMutability'

Security Impact:
- Prevents accidental or malicious overwriting of container image tags
- Ensures image version integrity and traceability
- Supports immutable infrastructure practices
- Critical for container supply chain security

Error Handling:
- Missing repository: Suppresses finding (repository may have been deleted)
- API errors: Re-raises for investigation

Repository ARN Format:
- Input: arn:aws:ecr:region:account:repository/repository-name
- Extracted: repository-name (everything after the last slash)
"""

import os
import boto3
from botocore.exceptions import ClientError
from aws_utils.clients import get_client

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

