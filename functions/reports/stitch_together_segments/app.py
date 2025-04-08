import os
import boto3
from datetime import datetime, timezone, timedelta


# Get environment variables
AI_REPORT_TABLE = os.environ['AI_REPORT_TABLE']
BUCKET = os.environ['BUCKET']
PRODUCT_NAME = os.environ['PRODUCT_NAME']


# Boto3 resources and clients
dynamodb = boto3.resource('dynamodb')
s3 = boto3.client('s3')
openai_report = dynamodb.Table(AI_REPORT_TABLE)


h2 = '<h2 style="background-color: #d9c8e3; width: 100%; height: 50px; line-height: 50px; padding-left: 20px; margin-top: 70px;">'


# Lambda handler
def lambda_handler(data, _context):

    # Current UTC datetime
    date = str(datetime.utcnow().date())

    result = '<div style="font-family: Verdana, sans-serif; font-size:16px;">'
    result += f'<h1>{PRODUCT_NAME} Weekly Security Report {date}</h1>'

    result += f'{h2}Overview</h2>'
    overview = retrieve_db_item(openai_report, 'overview')['html']
    result += overview

    result += f'{h2}Recommendations</h2>'
    recommendations = retrieve_db_item(openai_report, 'recommendations')['html']
    result += recommendations

    result += f'{h2}Accounts with Issues This Week</h2>'
    account_names = data['bb']['accounts_with_issues']
    result += stitch_accounts(openai_report, account_names)

    result += "</div>"

    # Write the result to S3 and capture the ARN
    s3_arn = write_to_s3(result)
    
    # Add the ARN to the returned data so that we can pass it to the SendEmail function later
    data['report_arn'] = s3_arn

    # Tidy up a little
    if data.get('messages'):
        del data['messages']

    if data.get('no_html_post_processing'):
        del data['no_html_post_processing']

    if data.get('html_substitutions'):
        del data['html_substitutions']

    if data.get('system'):
        del data['system']

    if data.get('user'):
        del data['user']

    return data


def stitch_accounts(table, account_names):
    """
    Retrieve and concatenate data from DynamoDB items based on a list of account names.

    :param table: The DynamoDB table object
    :param account_names: List of account names
    :return: Concatenated data from all the accounts
    """

    concatenated_data = []

    for account_name in account_names:
        # Retrieve data from DynamoDB
        data = retrieve_db_item(table, account_name)
        concatenated_data.append(data['html'])

    # Join the segments with the <hr> tag
    concatenated_data = '<hr style="border: none; border-top: 50px solid #d9c8e3; margin: 50px 0;">'.join(concatenated_data)

    return concatenated_data


# ----------------------------------------------------------------
#
#   S3
#
# ----------------------------------------------------------------

def write_to_s3(content):
    """
    Write given content to an S3 object.

    Parameters:
        - content (str): The content to write to S3.

    Returns:
        - str: The ARN of the created S3 object.
    """
    # Get the current date
    current_date = datetime.utcnow().date()
    
    # Create the object key in the format "weekly-report-YYYY-MM-DD.html"
    object_key = f"weekly-security-report-{current_date}.html"
    
    s3.put_object(Body=content, Bucket=BUCKET, Key=object_key)
    
    # Construct and return the ARN of the object
    return f"arn:aws:s3:::{BUCKET}/{object_key}"


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
