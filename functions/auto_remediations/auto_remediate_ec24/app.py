"""
AWS Security Hub Auto-Remediation: EC2.4 - Stopped EC2 Instance Termination

This control identifies and terminates EC2 instances that have been in a stopped
state, which may indicate they are no longer needed. Stopped instances still
incur EBS storage costs and may contain sensitive data or configurations.

Test triggers:
- Stopped EC2 instance: aws ec2 describe-instances --filters "Name=instance-state-name,Values=stopped"
- Check instance state: aws ec2 describe-instances --instance-ids i-1234567890abcdef0
- Monitor instance termination protection: aws ec2 describe-instance-attribute --instance-id i-1234567890abcdef0 --attribute disableApiTermination

The auto-remediation first disables API termination protection if enabled, then
terminates the stopped instance to reduce costs and eliminate potential security risks.

Target Resources: AWS EC2 instances in stopped state
Remediation: Disable termination protection and terminate the instance
"""

import os
import botocore
import boto3
from aws_utils.clients import get_client
def lambda_handler(data, _context):
    """
    Main Lambda handler for EC2.4 auto-remediation.
    
    Args:
        data: Security Hub finding data containing stopped instance details
        _context: Lambda context (unused)
        
    Returns:
        dict: Updated finding data with remediation results
        
    Remediation Logic:
        1. Extract instance ID from Security Hub finding
        2. Get cross-account EC2 client for target account and region
        3. Disable API termination protection to allow termination
        4. Terminate the stopped EC2 instance
        5. Handle instance not found errors with finding suppression
        6. Return success message confirming instance termination
    """
    print(data)

    # Extract relevant information from the input data
    finding = data['finding']
    account_id = finding['AwsAccountId']
    region = finding['Resources'][0]['Region']
    instance_arn = finding['Resources'][0]['Id']
    instance_id = instance_arn.rsplit('/', 1)[1]

    # Get the client for the specified AWS service in the specified account and region
    client = get_client('ec2', account_id, region)

    # Disable API termination for the instance
    print(f"Disabling API termination for instance {instance_id} in account {account_id}, region {region}...")
    try:
        response = client.modify_instance_attribute(
            DisableApiTermination={
                'Value': False
            },
            InstanceId=instance_id,
        )
        print(response)
    except Exception:
        pass

    # Terminate the instance
    print(f"Terminating instance {instance_id} in account {account_id}, region {region}...")
    try:
        response = client.terminate_instances(
            InstanceIds=[instance_id]
        )
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
            # If the instance couldn't be found, suppress the finding
            print("The instance couldn't be found. Suppressing.")
            data['messages']['actions_taken'] = "The instance couldn't be found. This finding has been suppressed."
            data['actions']['suppress_finding'] = True
            return data
        raise error
    print(response)

    # Update the messages and return the modified data
    data['messages']['actions_taken'] = "The instance has been terminated."
    return data

