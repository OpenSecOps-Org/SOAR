"""
ECR.1 AUTOREMEDIATION - CONFIGURE ECR REGISTRY SCANNING

This Lambda function automatically remediates AWS Security Hub findings for ECR.1
(ECR repositories should have image scanning configured).

Target Resources:
- Amazon ECR Registry (account-wide configuration)
- Applies to all repositories in the account

Remediation Actions:
1. Configures registry-wide enhanced scanning configuration
2. Enables scan-on-push for all repositories using wildcard filter
3. Sets up enhanced scanning (includes OS packages and language packages)

Scanning Configuration:
- Scan Type: ENHANCED (vs BASIC)
- Scan Frequency: SCAN_ON_PUSH (automatic scanning when images are pushed)
- Repository Filter: '*' (wildcard to include all repositories)
- Filter Type: WILDCARD

Validation Commands:
# Check registry scanning configuration
aws ecr get-registry-scanning-configuration

# Verify scanning configuration details
aws ecr get-registry-scanning-configuration --query 'scanningConfiguration'

# Check specific repository scanning status
aws ecr describe-repositories --query 'repositories[*].[repositoryName,imageScanningConfiguration]'

Security Impact:
- Enables automatic vulnerability scanning for all container images
- Detects security vulnerabilities in OS packages and application dependencies
- Provides security insights before images are deployed
- Registry-wide policy ensures consistent security scanning
- Enhanced scanning provides deeper vulnerability detection

Scope:
- Registry-level operation (affects entire AWS account)
- Automatically applies to all current and future repositories
- More comprehensive than repository-level configuration

Error Handling:
- API errors: Creates ticket for manual intervention
- Configuration failures: Returns error status for investigation

Note: This is a registry-level operation, unlike ECR.2 and ECR.3 which are repository-specific.
"""

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

