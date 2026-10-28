import os
import json
import boto3
from aws_utils.clients import get_client
from aws_utils.errors import transient_aws_errors
from aws_utils.security_hub import check_batch_update

PRODUCT_NAME = os.environ['PRODUCT_NAME']


@transient_aws_errors
def lambda_handler(data, _context):
    print(data)

    finding = data['finding']
    finding_id = finding['Id']
    product_arn = finding['ProductArn']

    account_id = finding['AwsAccountId']
    client = get_client('securityhub', account_id)

    response = client.batch_update_findings(
        FindingIdentifiers=[
            {
                'Id': finding_id,
                'ProductArn': product_arn
            }
        ],
        Workflow={
            'Status': 'SUPPRESSED'
        },
        UserDefinedFields={
            'TicketOpen': finding.get('UserDefinedFields', {}).get('TicketOpen', "No"),
            'TicketId': finding.get('UserDefinedFields', {}).get('TicketId', 'N/A'),
            'AccountDataJSON': json.dumps(data['account'])[:1024]
        },
        Note={
            'Text': f'Suppressed by {PRODUCT_NAME}',
            'UpdatedBy': f'{PRODUCT_NAME}'
        }
    )

    print(response)
    if check_batch_update(response):
        print("Finding updated successfully")
    return data


