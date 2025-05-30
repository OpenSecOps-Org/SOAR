import os
import botocore
import boto3
from aws_utils.clients import get_client

# Define the lambda_handler function
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

