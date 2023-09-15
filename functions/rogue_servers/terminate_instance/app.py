import os
import boto3

# Get the cross account role from environment variables
CROSS_ACCOUNT_ROLE = os.environ['CROSS_ACCOUNT_ROLE']

# Create an STS client
sts_client = boto3.client('sts')

# Lambda function handler
def lambda_handler(data, _context):
    # Print the input data
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
    response = client.terminate_instances(
        InstanceIds=[instance_id]
    )
    print(response)

    # Update the messages in the input data to indicate the actions taken
    data['messages']['actions_taken'] = "The instance has been terminated."
    return data

# Function to get a client for the specified AWS service in the specified account and region
def get_client(client_type, account_id, region, role=CROSS_ACCOUNT_ROLE):
    # Assume the specified role in the specified account
    other_session = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"auto_remediate_terminate_instance_{account_id}"
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