import os
import boto3

# Get environment variables
OPENAI_REPORT_TABLE = os.environ['OPENAI_REPORT_TABLE']

# Boto3 resources and clients
dynamodb = boto3.resource('dynamodb')
openai_report = dynamodb.Table(OPENAI_REPORT_TABLE)


def scan_with_paging(table):
    last_evaluated_key = None
    results = []

    while True:
        if last_evaluated_key:
            response = table.scan(ExclusiveStartKey=last_evaluated_key)
        else:
            response = table.scan()

        results.extend(response['Items'])

        last_evaluated_key = response.get('LastEvaluatedKey')
        if not last_evaluated_key:
            break

    return results


# Lambda handler
def lambda_handler(_data, _context):
    # scan all items in the table
    items = scan_with_paging(openai_report)

    # delete each item
    for item in items:
        openai_report.delete_item(
            Key={
                'id': item['id']
            }
        )
        
    return True
