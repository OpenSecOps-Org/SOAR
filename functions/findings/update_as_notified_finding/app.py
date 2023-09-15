import os
import json
import boto3
import botocore


CROSS_ACCOUNT_ROLE = os.environ['CROSS_ACCOUNT_ROLE']
PRODUCT_NAME = os.environ['PRODUCT_NAME']

sts_client = boto3.client('sts')


def lambda_handler(data, _context):
    print(data)

    finding = data['finding']

    account_id = finding['AwsAccountId']
    client = get_client('securityhub', account_id)

    try:
        response = client.batch_update_findings(
            FindingIdentifiers=[
                {
                    'Id': finding['Id'],
                    'ProductArn': finding['ProductArn']
                },
            ],
            UserDefinedFields={
                'TicketOpen': finding.get('UserDefinedFields', {}).get('TicketOpen', "No"),
                'TicketId': finding.get('UserDefinedFields', {}).get('TicketId', 'N/A'),
                'AccountDataJSON': json.dumps(data['account'])[:1024]
            },
            Note={
                'Text': f'Incident handled and reported by {PRODUCT_NAME}',
                'UpdatedBy': f'{PRODUCT_NAME}'
            },
            Workflow={
                'Status': 'NOTIFIED'
            }
        )
    except botocore.exceptions.ClientError as e:
        if 'TooManyRequestsException' in str(e):
            raise Exception('TooManyRequestsException')
        else:
            raise e

    print(response)
    if response['UnprocessedFindings'] != []:
        raise Exception("Unprocessed finding")

    print("Finding updated successfully")
    return data


def get_client(client_type, account_id, role=CROSS_ACCOUNT_ROLE):
    other_session = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"update_as_notified_finding_{account_id}"
    )
    access_key = other_session['Credentials']['AccessKeyId']
    secret_key = other_session['Credentials']['SecretAccessKey']
    session_token = other_session['Credentials']['SessionToken']
    return boto3.client(
        client_type,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
