import os
import boto3
import cfnresponse
import logging

AI_PROMPTS_TABLE = os.environ['AI_PROMPTS_TABLE']

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')

def lambda_handler(event, context):
    try:
        logger.info('Received event: %s', event)

        table_name = AI_PROMPTS_TABLE
        table = dynamodb.Table(table_name)

        # Retrieve the files from the deployment package
        request_type = event.get('RequestType', '')
        if request_type == 'Create' or request_type == 'Update':
            data_dir = 'ai-prompts'

            # Insert new items from the files
            for filename in os.listdir(data_dir):
                if filename.endswith('.txt'):
                    with open(os.path.join(data_dir, filename), 'r') as file:
                        data = file.read()

                    item = {
                        'id': os.path.splitext(filename)[0],
                        'instructions': data
                    }
                    table.put_item(Item=item)

        # Succeed for Create, Update, AND the no-op Delete
        cfnresponse.send(event, context, cfnresponse.SUCCESS, {})
        # Add a log statement for successful completion
        logger.info('Function execution completed successfully')

    # If anything at all fails, just fail and return
    except Exception as e:
        logger.error('Error occurred: %s', str(e))
        cfnresponse.send(event, context, cfnresponse.FAILED, 'Error occurred: {}'.format(str(e)))

