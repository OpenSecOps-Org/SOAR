import os
import botocore
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

    # Get the EC2 client for the specified account and region
    client = get_client('ec2', account_id, region)

    # Get the 'SubnetId' value from the 'Details' dictionary in the 'finding' dictionary
    subnet_id = finding['Resources'][0]['Details']['AwsEc2Subnet']['SubnetId']

    # Try to modify the 'MapPublicIpOnLaunch' attribute of the subnet
    try:
        response = client.modify_subnet_attribute(
            SubnetId=subnet_id,
            MapPublicIpOnLaunch={
                'Value': False
            }
        )
    # If an error occurs, check if it is an 'InvalidSubnet' or 'InvalidSubnetID.NotFound' error
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] in ['InvalidSubnet', 'InvalidSubnetID.NotFound']:
            # Print a message indicating that the subnet can't be found
            print("The subnet can't be found. Suppressing.")
            # Update the 'messages' and 'actions' keys in the input data
            data['messages']['actions_taken'] = "The subnet cannot be found. This finding has been suppressed."
            data['actions']['suppress_finding'] = True
            # Return the updated input data
            return data
        # If the error is not one of the expected errors, raise the error
        raise error

    # Print the response from modifying the subnet attribute
    print(response)

    # Update the 'messages' key in the input data
    data['messages']['actions_taken'] = "MapPublicIpOnLaunch has been set to FALSE for the subnet."
    data['messages']['actions_required'] = "None"
    # Return the updated input data
    return data

# Define the get_client function
def get_client(client_type, account_id, region, role=CROSS_ACCOUNT_ROLE):
    # Assume the specified role in the specified account and region
    other_session = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"auto_remediate_ec215_{account_id}"
    )
    # Get the access key, secret key, and session token from the assumed role session
    access_key = other_session['Credentials']['AccessKeyId']
    secret_key = other_session['Credentials']['SecretAccessKey']
    session_token = other_session['Credentials']['SessionToken']
    # Create a client with the specified client type, access key, secret key, session token, and region
    return boto3.client(
        client_type,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=region
    )