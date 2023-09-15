import os
import boto3
import json
import logging
import decimal

# Set the logging level to INFO
logger = logging.getLogger()
logger.setLevel(logging.INFO)


# Get environment variables
OPENAI_PROMPTS_TABLE = os.environ['OPENAI_PROMPTS_TABLE']
OPENAI_REPORT_TABLE = os.environ['OPENAI_REPORT_TABLE']

dynamodb = boto3.resource('dynamodb')
openai_prompts = dynamodb.Table(OPENAI_PROMPTS_TABLE)
openai_report = dynamodb.Table(OPENAI_REPORT_TABLE)


# Lambda handler
def lambda_handler(data, _context):
    logger.info(data)

    system = retrieve_db_item(openai_prompts, 'weekly_ai_report_0_common')['instructions'] + "\n"
    system += retrieve_db_item(openai_prompts, 'weekly_ai_report_3_recommendations')['instructions']

    # Concatenate all the generated account summaries into one string
    accounts = data['bb']['accounts_with_issues']
    summaries = concatenate_account_summaries(openai_report, accounts)

    # Prepare the return data
    data['messages']['report']['html'] = ''
    data['system'] = system
    data['user'] = {
        "account_summaries": summaries,
    }
    data['user'] = json.dumps(data['user'], default=decimal_default)

    return data


def decimal_default(obj):
    if isinstance(obj, decimal.Decimal):
        return float(obj)
    raise TypeError("Object of type '%s' is not JSON serializable" % type(obj).__name__)


def concatenate_account_summaries(table, accounts):
    """
    Fetches account summaries from a DynamoDB table and concatenates them.

    Parameters:
        - table (resource): The DynamoDB table resource.
        - accounts (list of str): List of account names.

    Returns:
        - str: Concatenated account summaries separated by three newlines.
    """

    # List to store the retrieved account summaries
    summaries = []

    for account in accounts:
        # Construct the composite key
        key_value = "Summary#" + account
        
        # Fetch the item using the constructed key
        item = retrieve_db_item(table, key_value)
        
        if item and 'data' in item:
            # Append the 'data' field of the item to the summaries list
            data = item['data']
            data = account + ":\n" + data
            data = f"[ACCOUNT {account}]:\n{data}"
            summaries.append(data)

    # Concatenate summaries with two newlines as separator and return
    return '\n\n\n'.join(summaries)


# ----------------------------------------------------------------
#
#   DynamoDB queries
#
# ----------------------------------------------------------------

def retrieve_db_item(table, key_value):
    """
    Retrieves an item from DynamoDB based on the given key value.

    Parameters:
        - table (resource): The DynamoDB table resource.
        - key_value (str): The primary key value to query the table with.

    Returns:
        - dict: The retrieved item data.
    """
    # Define the key dictionary based on assumed attribute name 'id'
    key_dict = {'id': key_value}
    
    # Retrieve the item from DynamoDB
    response = table.get_item(Key=key_dict)
    
    # Return the item data
    return response.get('Item')

