# Import necessary libraries
import os
import datetime as dt
import botocore
import boto3
from dateutil import parser

# Get the cross-account role from environment variables
CROSS_ACCOUNT_ROLE = os.environ['CROSS_ACCOUNT_ROLE']

# Create an STS client
sts_client = boto3.client('sts')

# Lambda handler function
def lambda_handler(data, _context):
    # Print the input data
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

# Function to get a client for the specified AWS service, account, and region
def get_client(client_type, account_id, region, role=CROSS_ACCOUNT_ROLE):
    # Assume the cross-account role using STS
    other_session = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"auto_remediate_ec212_{account_id}"
    )
    # Get the temporary credentials from the assumed role
    access_key = other_session['Credentials']['AccessKeyId']
    secret_key = other_session['Credentials']['SecretAccessKey']
    session_token = other_session['Credentials']['SessionToken']
    # Create a client with the temporary credentials
    return boto3.client(
        client_type,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=region
    )