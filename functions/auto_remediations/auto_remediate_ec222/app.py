import os
import datetime as dt
import botocore
import boto3
from dateutil import parser

# Get the cross account role from the environment variables
CROSS_ACCOUNT_ROLE = os.environ['CROSS_ACCOUNT_ROLE']

# Create an STS client
sts_client = boto3.client('sts')

# Lambda handler function
def lambda_handler(data, _context):
    # Print the input data
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

# Function to get a client for the specified account, region, and role
def get_client(client_type, account_id, region, role=CROSS_ACCOUNT_ROLE):
    # Assume the specified role in the specified account
    other_session = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"auto_remediate_ec222_{account_id}"
    )

    # Get the access key, secret key, and session token from the assumed role session
    access_key = other_session['Credentials']['AccessKeyId']
    secret_key = other_session['Credentials']['SecretAccessKey']
    session_token = other_session['Credentials']['SessionToken']

    # Create a client using the assumed role credentials and specified region
    return boto3.client(
        client_type,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=region
    )