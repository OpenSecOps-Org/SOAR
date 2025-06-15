"""
ECR.3 AUTOREMEDIATION - CONFIGURE ECR REPOSITORY LIFECYCLE POLICY

This Lambda function automatically remediates AWS Security Hub findings for ECR.3
(ECR repositories should have at least one lifecycle policy configured).

Target Resources:
- Amazon ECR repositories
- Both private repositories

Remediation Actions:
1. Extracts repository name from repository ARN
2. Applies predefined lifecycle policy to keep only the 2 most recent images
3. Configures automatic cleanup of older images to manage storage costs

Lifecycle Policy Configuration:
- Rule Priority: 1
- Selection: Any tag status
- Count Type: Keep images when count is more than 2
- Action: Expire (delete) older images

Validation Commands:
# Check repository lifecycle policy
aws ecr get-lifecycle-policy --repository-name <repository-name>

# Verify lifecycle policy configuration
aws ecr get-lifecycle-policy --repository-name <repository-name> --query 'lifecyclePolicyText' --output text | jq

# Preview lifecycle policy effects (dry run)
aws ecr get-lifecycle-policy-preview --repository-name <repository-name>

Security Impact:
- Implements automated image retention policies
- Reduces storage costs by removing old images
- Prevents repository bloat and potential vulnerabilities in old images
- Ensures only recent, presumably more secure images are retained

Cost Optimization:
- Automatically removes images beyond the 2 most recent
- Reduces ECR storage costs
- Maintains security by keeping only latest images

Error Handling:
- Missing repository: Suppresses finding (repository may have been deleted)
- API errors: Re-raises for investigation

Repository ARN Format:
- Input: arn:aws:ecr:region:account:repository/repository-name
- Extracted: repository-name (everything after the last slash)
"""

import os
import boto3
import json
from botocore.exceptions import ClientError
from aws_utils.clients import get_client

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


