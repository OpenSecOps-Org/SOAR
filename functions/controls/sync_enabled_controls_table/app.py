import os
import boto3

# Get the table name and cross-account role from environment variables
TABLE_NAME = os.environ['TABLE_NAME']
CROSS_ACCOUNT_ROLE = os.environ['CROSS_ACCOUNT_ROLE']

# Create DynamoDB and STS clients
dynamodb_client = boto3.client('dynamodb')
sts_client = boto3.client('sts')


def lambda_handler(data, _context):
    # Extract the account ID from the _data parameter
    account_id = data.get('account_id')
    if not account_id:
        raise ValueError("Account ID not provided in input data")

    # Get the Security Hub client for the provided account ID
    sec_hub_client = get_client('securityhub', account_id)
    
    # Get the enabled standards for the security account
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
        association_status = associations[0]['AssociationStatus']
        
        # Construct the control identifier with account ID and control ID
        control_identifier = f"{account_id}#{security_control_id}"
        
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


def get_client(client_type, account_id, role=CROSS_ACCOUNT_ROLE):
    # Assume the cross-account role to get the client for the specified account
    other_session = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"update_enabled_sec_hub_controls_table_{account_id}"
    )
    
    # Get the access key, secret key, and session token from the assumed role
    access_key = other_session['Credentials']['AccessKeyId']
    secret_key = other_session['Credentials']['SecretAccessKey']
    session_token = other_session['Credentials']['SessionToken']
    
    # Create the client with the assumed role credentials
    return boto3.client(
        client_type,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
