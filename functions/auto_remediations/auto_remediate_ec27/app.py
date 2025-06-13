"""
AWS Security Hub Auto-Remediation: EC2.7 - EBS Default Encryption Enable

This control ensures that EBS (Elastic Block Store) encryption is enabled by default
for new volumes in the account. Enabling EBS encryption by default helps protect
data at rest and ensures compliance with security requirements.

Test triggers:
- Check EBS encryption status: aws ec2 get-ebs-encryption-by-default
- Verify account-level encryption: aws ec2 describe-volumes --filters "Name=encrypted,Values=false"
- Check new volume creation: aws ec2 create-volume --size 8 --availability-zone us-east-1a

The auto-remediation enables EBS encryption by default at the account level,
ensuring all new EBS volumes are automatically encrypted.

Target Resources: AWS Account-level EBS encryption settings
Remediation: Enable EBS encryption by default for new volumes
"""

import os
import boto3
from aws_utils.clients import get_client
def lambda_handler(data, _context):
    """
    Main Lambda handler for EC2.7 auto-remediation.
    
    Args:
        data: Security Hub finding data containing account details
        _context: Lambda context (unused)
        
    Returns:
        dict: Updated finding data with remediation results
        
    Remediation Logic:
        1. Extract account ID and region from Security Hub finding
        2. Get cross-account EC2 client for target account and region
        3. Enable EBS encryption by default for the account
        4. Return success message indicating encryption is enabled
        5. Note that this only affects new volumes, not existing ones
    """
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

