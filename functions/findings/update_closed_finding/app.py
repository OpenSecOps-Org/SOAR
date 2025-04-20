import os
import json
import boto3
import botocore
from aws_utils.clients import get_client

PRODUCT_NAME = os.environ['PRODUCT_NAME']


def lambda_handler(data, _context):
    print(data)

    finding = data['finding']
    ticket_id = finding.get('UserDefinedFields', {}).get('TicketId', 'N/A')

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
                'TicketOpen': "No",
                'TicketId': ticket_id,
                'AccountDataJSON': json.dumps(data['account'])[:1024]
            },
            Note={
                'Text': f'Ticket closed by {PRODUCT_NAME}',
                'UpdatedBy': f'{PRODUCT_NAME}'
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


