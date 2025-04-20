import os
import botocore
import boto3
from aws_utils.clients import get_client

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

