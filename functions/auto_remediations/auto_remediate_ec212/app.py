"""
AWS Security Hub Auto-Remediation: EC2.12 - Unused Elastic IP Address Cleanup

This control identifies and removes Elastic IP addresses that have been unattached 
for an extended period. Unattached Elastic IPs incur unnecessary costs and may
indicate abandoned resources or misconfigurations in infrastructure management.

Test triggers:
- Unused EIP for over 30 days: aws ec2 describe-addresses --filters "Name=domain,Values=vpc"
- Check EIP association status: aws ec2 describe-addresses --allocation-ids eipalloc-12345678
- Monitor EIP first observed time: Check finding FirstObservedAt timestamp

The auto-remediation releases Elastic IP addresses that have been unused for more than
30 days, reducing costs and cleaning up orphaned network resources.

Target Resources: AWS Elastic IP addresses with no associated instances/network interfaces
Remediation: Release EIP after 30-day grace period to prevent accidental deletion
"""

import os
import datetime as dt
import botocore
import boto3
from dateutil import parser
from aws_utils.clients import get_client
def lambda_handler(data, _context):
    """
    Main Lambda handler for EC2.12 auto-remediation.
    
    Args:
        data: Security Hub finding data containing EIP details
        _context: Lambda context (unused)
        
    Returns:
        dict: Updated finding data with remediation results
        
    Remediation Logic:
        1. Extract EIP allocation ID from Security Hub finding
        2. Check finding age against 30-day minimum threshold
        3. If too young, defer remediation for later processing
        4. If old enough, release the Elastic IP address
        5. Handle various error conditions with appropriate suppression
        6. Return success message or reschedule directive
    """
    print(data)

    # Get the finding from the input data
    finding = data['finding']

    # Get the account ID, region, and resource details from the finding
    account_id = finding['AwsAccountId']
    res = finding['Resources'][0]
    region = res['Region']
    allocation_id = False
    details = res.get('Details', {})

    # Check if the finding is related to an Elastic IP
    if details.get('AwsEc2Eip', False):
        # Get the allocation ID of the Elastic IP
        allocation_id = details['AwsEc2Eip'].get('AllocationId', False)

    # If the allocation ID is not found and the finding type is AwsEc2Eip,
    # extract the allocation ID from the resource ID
    if not allocation_id and res.get('Type') == 'AwsEc2Eip':
        allocation_id = res['Id'].rsplit('/', 1)[1]
    else:
        # Otherwise, extract the allocation ID from the product fields
        allocation_id = finding['ProductFields'].get(
            'Resources:0/Id').rsplit('/', 1)[1]

    # Parse the first observed timestamp and get the current timestamp
    first_observed_at = parser.parse(finding['FirstObservedAt'])
    now = dt.datetime.now(dt.timezone.utc)

    # Calculate the age of the finding
    age = now - first_observed_at
    min_age = dt.timedelta(days=30)

    # Print the timestamps and age for debugging
    print("First: ", first_observed_at)
    print("Now:  ", now)
    print("Age: ", now - first_observed_at)
    print("Min Age: ", min_age)

    # If the age is less than the minimum age, reconsider the finding later
    if (age < min_age):
        print("This EIP is too young. Reconsider this finding later.")
        data['actions']['reconsider_later'] = True
        return data

    # If the age is greater than or equal to the minimum age, proceed with deletion
    # Create an EC2 client for the specified account and region
    client = get_client('ec2', account_id, region)

    try:
        # Release the Elastic IP using the allocation ID
        response = client.release_address(AllocationId=allocation_id)
    except botocore.exceptions.ClientError as error:
        # Handle specific errors and suppress the finding
        if error.response['Error']['Code'] == 'InvalidIPAddress.InUse':
            print("The EIP is in use. Suppressing.")
            data['messages']['actions_taken'] = "The EIP is now in use. This finding has been suppressed."
            data['actions']['suppress_finding'] = True
            return data
        if error.response['Error']['Code'] == 'AuthFailure':
            print("AuthFailure. Suppressing.")
            data['messages']['actions_taken'] = "Authentication failure. This finding has been suppressed."
            data['actions']['suppress_finding'] = True
            return data
        if error.response['Error']['Code'] == 'InvalidAllocationID.NotFound':
            print("EIP not found. Suppressing.")
            data['messages']['actions_taken'] = "EIP not found. This finding has been suppressed."
            data['actions']['suppress_finding'] = True
            return data
        raise error

    # Print the response for debugging
    print(response)

    # Update the messages and actions in the input data
    data['messages']['actions_taken'] = "The Elastic IP has been released."
    data['messages']['actions_required'] = "Unused Elastic IPs will be released after 30 days. Make sure they are always in use and create them through code."
    return data

