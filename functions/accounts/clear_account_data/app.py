"""
AWS Account Data Cache Management: Clear Account Data

This Lambda function clears all cached account data from the DynamoDB table used 
for account information caching. This is typically used for maintenance operations
or when a full refresh of account data is needed across the SOAR system.

Operations:
1. Scan the entire cached account data table to get all account IDs
2. Create batch delete requests for all found accounts
3. Process deletions in batches of 25 (DynamoDB batch limit)
4. Handle unprocessed items with retry logic

Target Resources: DynamoDB cached account data table
Purpose: Complete cache invalidation for account data refresh
"""

import os
import boto3


CACHED_ACCOUNT_DATA_TABLE_NAME = os.environ['CACHED_ACCOUNT_DATA_TABLE_NAME']

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(CACHED_ACCOUNT_DATA_TABLE_NAME)


def lambda_handler(_event, _context):
    """
    Main Lambda handler for clearing all cached account data.
    
    Args:
        _event: Lambda event data (unused)
        _context: Lambda context (unused)
        
    Returns:
        None (implicit)
        
    Process:
        1. Scan table for all account IDs using pagination
        2. Create delete requests in batches of 25 items
        3. Process each batch with retry handling for unprocessed items
        4. Continue until all cached account data is cleared
    """
    # STEP 1: Scan entire table to collect all account IDs
    # Use ProjectionExpression to minimize data transfer by only retrieving IDs
    response = table.scan(ProjectionExpression="id")
    result = response['Items']

    # Handle pagination - continue scanning if more items exist
    while 'LastEvaluatedKey' in response:
        response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
        result.extend(response['Items'])

    # STEP 2: Create delete requests for all discovered accounts
    remaining_delete_requests = [delete_request(x['id']) for x in result]

    # STEP 3: Process deletions in batches of 25 (DynamoDB limit)
    while len(remaining_delete_requests) > 0:
        delete_requests = remaining_delete_requests[:25]
        remaining_delete_requests = remaining_delete_requests[25:]

        # STEP 4: Execute batch delete with retry handling for unprocessed items
        while len(delete_requests) > 0:
            print(delete_requests)
            # Execute batch delete operation
            response = dynamodb.batch_write_item(
                RequestItems={
                    CACHED_ACCOUNT_DATA_TABLE_NAME: delete_requests
                }
            )
            print(response)
            
            # Handle unprocessed items - retry them in the next iteration
            delete_requests = response.get('UnprocessedItems', {}).get(
                CACHED_ACCOUNT_DATA_TABLE_NAME, [])


def delete_request(account_id):
    """
    Create a DynamoDB delete request structure for a given account ID.
    
    Args:
        account_id: AWS account ID to delete from cache
        
    Returns:
        dict: DynamoDB delete request structure for batch operations
        
    Format:
        Returns the standard DynamoDB batch delete request format with
        the account ID as the primary key.
    """
    return {
        'DeleteRequest': {
            'Key': {
                'id': account_id
            }
        }
    }