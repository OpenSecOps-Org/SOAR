import os
import boto3
from botocore.exceptions import ClientError
from aws_utils.clients import get_client

# Get the table name from environment variables
TABLE_NAME = os.environ['TABLE_NAME']

# Create DynamoDB client
dynamodb_client = boto3.client('dynamodb')


def lambda_handler(data, _context):
    # Extract the account ID from the _data parameter
    account_id = data.get('account_id')
    if not account_id:
        raise ValueError("Account ID not provided in input data")
    
    try:
        # Get the Security Hub client for the provided account ID
        sec_hub_client = get_client('securityhub', account_id)
    except ClientError as error:
        # Check if the exception is an AccessDenied error
        if error.response.get("Error", {}).get("Code") == "AccessDenied":
            print(f"Access denied for account {account_id} - skipping")
            return True
        raise  # Re-raise the error if it's not AccessDenied

    print(f"Processing account {account_id}...")

    # Get the enabled standards for the account
    global_enabled_standards = get_enabled_standards(sec_hub_client)
    
    # Get the security controls for the enabled standards
    global_security_controls = get_security_controls(sec_hub_client, global_enabled_standards)
    
    # Write the security controls to the DynamoDB table
    write_to_table(global_security_controls, account_id)
    
    return True


def get_enabled_standards(sec_hub_client):
    print("Getting enabled standards...")
    
    # Get the enabled standards for the security account
    subs = sec_hub_client.get_enabled_standards(MaxResults=10)['StandardsSubscriptions']
    
    print("Enabled Standards: ", subs)
    
    return subs


def get_security_controls(sec_hub_client, enabled_standards):
    print("Getting security controls...")
    
    definitions = []
    
    # Iterate over each enabled standard
    for standard in enabled_standards:
        standards_arn = standard['StandardsArn']
        
        # Get the security control definitions for the standard
        response = sec_hub_client.list_security_control_definitions(StandardsArn=standards_arn)
        definitions += response['SecurityControlDefinitions']
        
        next_token = response.get('NextToken')
        
        # If there are more security control definitions, continue retrieving them
        while next_token:
            response = sec_hub_client.list_security_control_definitions(
                StandardsArn=standards_arn,
                NextToken=next_token
            )
            definitions += response['SecurityControlDefinitions']
            next_token = response.get('NextToken')

    result = {}
    
    # Iterate over each security control definition
    for definition in definitions:
        security_control_id = definition['SecurityControlId']
        availability = definition['CurrentRegionAvailability']
        
        # If the security control is available and not already in the result, get its associations
        if availability == 'AVAILABLE' and not result.get(security_control_id):
            result[security_control_id] = get_standards_control_associations(sec_hub_client, security_control_id)

    print(result)
    
    return result


def get_standards_control_associations(sec_hub_client, security_control_id):
    result = []
    
    # Get the associations for the security control
    response = sec_hub_client.list_standards_control_associations(SecurityControlId=security_control_id)
    
    # Iterate over each association
    for association in response['StandardsControlAssociationSummaries']:
        item = {
            'StandardsArn': association['StandardsArn'],
            'AssociationStatus': association['AssociationStatus']
        }
        
        # If there is an updated reason, add it to the item
        if association.get('UpdatedReason'):
            item['UpdatedReason'] = association['UpdatedReason']
        
        result.append(item)
    
    return result


def write_to_table(global_security_controls, account_id):
    # Iterate over each security control and its associations
    for security_control_id, associations in global_security_controls.items():

        # Construct the control identifier with account ID and control ID
        control_identifier = f"{account_id}#{security_control_id}"
        
        if len(associations) == 0:
            print(f"The control {security_control_id} has no associations (deleted by AWS)")
            delete_control(control_identifier)
            continue

        association_status = associations[0]['AssociationStatus']
        
        # If the association status is enabled, put the control in the DynamoDB table
        if association_status == 'ENABLED':
            put_control(control_identifier)
        # Otherwise, delete the control from the DynamoDB table
        else:
            delete_control(control_identifier)


def put_control(control_identifier):
    print("Enabling ", control_identifier)
    
    # Put the control in the DynamoDB table
    dynamodb_client.put_item(
        Item={
            'id': {
                'S': control_identifier
            }
        },
        TableName=TABLE_NAME
    )


def delete_control(control_identifier):
    print("Disabling ", control_identifier)
    
    # Delete the control from the DynamoDB table
    dynamodb_client.delete_item(
        Key={
            'id': {
                'S': control_identifier
            }
        },
        TableName=TABLE_NAME
    )


