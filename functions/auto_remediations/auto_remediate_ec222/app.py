"""
AWS Security Hub Auto-Remediation: EC2.22 - Unused Security Group Cleanup

This control identifies and removes security groups that have been unused for an
extended period. Unused security groups can clutter the environment and may pose
security risks if they contain overly permissive rules.

Test triggers:
- Unused security group for over 24 hours: aws ec2 describe-security-groups --group-ids sg-12345678
- Check security group usage: aws ec2 describe-instances --filters "Name=instance.group-id,Values=sg-12345678"
- Monitor security group first observed time: Check finding FirstObservedAt timestamp

The auto-remediation deletes security groups that have been unused for more than
24 hours, reducing security risks and cleaning up orphaned network configurations.

Target Resources: AWS Security Groups with no associated instances or network interfaces
Remediation: Delete security group after 24-hour grace period to prevent accidental deletion
"""

import os
import datetime as dt
import botocore
import boto3
from dateutil import parser
from aws_utils.clients import get_client
def lambda_handler(data, _context):
    """
    Main Lambda handler for EC2.22 auto-remediation.
    
    Args:
        data: Security Hub finding data containing security group details
        _context: Lambda context (unused)
        
    Returns:
        dict: Updated finding data with remediation results
        
    Remediation Logic:
        1. Extract security group ID from Security Hub finding
        2. Check finding age against 24-hour minimum threshold
        3. If too young, defer remediation for later processing
        4. If old enough, delete the unused security group
        5. Handle dependency violations and not found errors with suppression
        6. Return success message or reschedule directive
    """
    print(data)

    # Get the finding from the input data
    finding = data['finding']

    # Extract relevant information from the finding
    account_id = finding['AwsAccountId']
    region = finding['Resources'][0]['Region']
    sg_arn = finding['Resources'][0]['Id']
    sg_id = sg_arn.rsplit('/', 1)[1]

    # Parse the first observed timestamp and get the current time
    first_observed_at = parser.parse(finding['FirstObservedAt'])
    now = dt.datetime.now(dt.timezone.utc)

    # Calculate the age of the finding
    age = now - first_observed_at
    min_age = dt.timedelta(days=1)

    # Print the timestamps and age
    print("First: ", first_observed_at)
    print("Now:  ", now)
    print("Age: ", now - first_observed_at)
    print("Min Age: ", min_age)

    # Check if the age is less than the minimum age
    if (age < min_age):
        # If the age is less than the minimum age, print a message and return the data
        print("This SG is too young. Reconsider this finding later.")
        data['actions']['reconsider_later'] = True
        return data

    # If the age is greater than or equal to the minimum age, proceed with deleting the security group

    # Get the client for the specified account and region
    client = get_client('ec2', account_id, region)

    try:
        # Delete the security group
        response = client.delete_security_group(
            GroupId=sg_id
        )
    except botocore.exceptions.ClientError as error:
        # Handle specific errors that may occur during deletion

        # If the security group is not found, print a message and suppress the finding
        if error.response['Error']['Code'] == 'InvalidGroup.NotFound':
            print("The SG can't be found. Suppressing.")
            data['messages']['actions_taken'] = "The security group cannot be found. This finding has been suppressed."
            data['actions']['suppress_finding'] = True
            return data

        # If there is a dependency violation, print a message and suppress the finding
        if error.response['Error']['Code'] == 'DependencyViolation':
            print("Dependency Violation. Suppressing.")
            data['messages']['actions_taken'] = "The security group is now in use. This finding has been suppressed."
            data['actions']['suppress_finding'] = True
            return data

        # If any other error occurs, raise the error
        raise error

    # Print the response from deleting the security group
    print(response)

    # Update the messages in the data
    data['messages']['actions_taken'] = "The security group has been deleted."
    data['messages']['actions_required'] = "Unused security groups will be deleted after 24 hours. Make sure they are always in use and create them through code."

    # Return the updated data
    return data

