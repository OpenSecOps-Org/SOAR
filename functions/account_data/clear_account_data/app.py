import os
import boto3


CACHED_ACCOUNT_DATA_TABLE_NAME = os.environ['CACHED_ACCOUNT_DATA_TABLE_NAME']

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(CACHED_ACCOUNT_DATA_TABLE_NAME)


def lambda_handler(_event, _context):
    # Scan the table to get all items with only the 'id' attribute projected
    response = table.scan(ProjectionExpression="id")
    result = response['Items']

    # If there are more items to scan, continue scanning and adding to the result list
    while 'LastEvaluatedKey' in response:
        response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
        result.extend(response['Items'])

    # Create a list of delete requests for each item in the result list
    remaining_delete_requests = [delete_request(x['id']) for x in result]

    # Process delete requests in batches of 25
    while len(remaining_delete_requests) > 0:
        delete_requests = remaining_delete_requests[:25]
        remaining_delete_requests = remaining_delete_requests[25:]

        # Process each batch of delete requests
        while len(delete_requests) > 0:
            print(delete_requests)
            # Use the batch_write_item method to delete the items in the batch
            response = dynamodb.batch_write_item(
                RequestItems={
                    CACHED_ACCOUNT_DATA_TABLE_NAME: delete_requests
                }
            )
            print(response)
            # Get any unprocessed items and add them back to the delete_requests list
            delete_requests = response.get('UnprocessedItems', {}).get(
                CACHED_ACCOUNT_DATA_TABLE_NAME, [])


def delete_request(account_id):
    # Create a delete request for a given account_id
    return {
        'DeleteRequest': {
            'Key': {
                'id': account_id
            }
        }
    }