import os
import boto3

# Get the value of the CROSS_ACCOUNT_ROLE environment variable
CROSS_ACCOUNT_ROLE = os.environ['CROSS_ACCOUNT_ROLE']

# Create an STS client
sts_client = boto3.client('sts')

# Define the lambda_handler function
def lambda_handler(data, _context):
    # Print the input data
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

# Define the get_client function
def get_client(client_type, account_id, region, role=CROSS_ACCOUNT_ROLE):
    # Assume the specified role using the STS client
    other_session = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"auto_remediate_ec27_{account_id}"
    )
    # Get the access key, secret key, and session token from the assumed role session
    access_key = other_session['Credentials']['AccessKeyId']
    secret_key = other_session['Credentials']['SecretAccessKey']
    session_token = other_session['Credentials']['SessionToken']
    
    # Create and return a new client using the obtained credentials and region
    return boto3.client(
        client_type,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=region
    )
