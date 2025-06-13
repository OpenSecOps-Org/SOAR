"""
AWS Security Hub Auto-Remediation: EC2.15 - VPC Subnets Public IP Auto-Assignment

This control checks that VPC subnets do not automatically assign public IP addresses 
to instances launched within them. Automatic public IP assignment can expose instances
to the internet unintentionally, creating security risks.

Test triggers:
- Subnet with public IP auto-assignment enabled: aws ec2 describe-subnets --subnet-ids subnet-12345
- Check MapPublicIpOnLaunch status: aws ec2 describe-subnets --filters "Name=map-public-ip-on-launch,Values=true"

The auto-remediation disables automatic public IP assignment (MapPublicIpOnLaunch=False)
for subnets that have this feature enabled, preventing unintentional internet exposure.

Target Resources: AWS VPC Subnets with MapPublicIpOnLaunch=True
Remediation: Set MapPublicIpOnLaunch=False to disable automatic public IP assignment
"""

import os
import botocore
import boto3
from aws_utils.clients import get_client


def lambda_handler(data, _context):
    """
    Main Lambda handler for EC2.15 auto-remediation.
    
    Args:
        data: Security Hub finding data containing subnet details
        _context: Lambda context (unused)
        
    Returns:
        dict: Updated finding data with remediation results
        
    Remediation Logic:
        1. Extract subnet ID from Security Hub finding
        2. Get cross-account EC2 client for target account and region
        3. Modify subnet attribute to disable public IP auto-assignment
        4. Handle subnet not found errors gracefully with finding suppression
        5. Return success message or error details
    """
    print(data)

    # Extract Security Hub finding information
    finding = data['finding']
    account_id = finding['AwsAccountId']
    region = finding['Resources'][0]['Region']

    # Get cross-account EC2 client for the target account and region
    client = get_client('ec2', account_id, region)

    # Extract subnet ID from Security Hub finding details
    subnet_id = finding['Resources'][0]['Details']['AwsEc2Subnet']['SubnetId']

    # REMEDIATION: Disable automatic public IP assignment for the subnet
    try:
        response = client.modify_subnet_attribute(
            SubnetId=subnet_id,
            MapPublicIpOnLaunch={
                'Value': False  # Disable automatic public IP assignment
            }
        )
    except botocore.exceptions.ClientError as error:
        # GRACEFUL ERROR HANDLING: Handle subnet not found scenarios
        if error.response['Error']['Code'] in ['InvalidSubnet', 'InvalidSubnetID.NotFound']:
            print("The subnet can't be found. Suppressing.")
            # Suppress finding when subnet no longer exists (likely deleted)
            data['messages']['actions_taken'] = "The subnet cannot be found. This finding has been suppressed."
            data['actions']['suppress_finding'] = True
            return data
        # Re-raise unexpected errors for proper error handling
        raise error

    print(response)

    # SUCCESS: Update remediation status
    data['messages']['actions_taken'] = "MapPublicIpOnLaunch has been set to FALSE for the subnet."
    data['messages']['actions_required'] = "None"
    return data

