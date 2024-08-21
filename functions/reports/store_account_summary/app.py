import os
import boto3
import logging
import html2text
import re


# Set the logging level to INFO
logger = logging.getLogger()
logger.setLevel(logging.INFO)


# Get environment variables
AI_REPORT_TABLE = os.environ['AI_REPORT_TABLE']

dynamodb = boto3.resource('dynamodb')
openai_report = dynamodb.Table(AI_REPORT_TABLE)


# Lambda handler
def lambda_handler(data, _context):
    logger.info(data)

    account = data['account']
    html = data['html']

    key = f"Summary#{account}"
    plaintext = extract_summary(html)
    logger.info(plaintext)

    write_db_item(openai_report, key, plaintext)

    return True


# Extract the summary
def extract_summary(html, full=False):
    # Convert the entire HTML to plaintext
    plain_text = html2text.html2text(html)
    
    # If full is True, process the text to remove headers and excessive newlines
    if full:
        # Remove everything between double square brackets
        plain_text = re.sub(r'\[\[.+?\]\]', '', plain_text)

        # Remove headers. Assuming headers are in markdown style e.g. # Header
        plain_text = re.sub(r'\n#+ .+\n', '\n', plain_text)
        
        # Replace three or more newlines with exactly two
        plain_text = re.sub(r'\n{3,}', '\n\n', plain_text)
        
        # Return the processed text immediately
        return plain_text.strip()
    
    # Find the position where "Summary" ends a line
    start_position = plain_text.find("Summary\n")
    
    # If it's found, move the start position past "Summary"
    if start_position != -1:
        start_position += 7  # account for the length of the matching string
    
    # If "Summary" not found, return the whole plaintext
    else:
        return plain_text.strip()
    
    # Extract and return the content from "Summary" onwards
    return plain_text[start_position:].strip()



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


def write_db_item(table, key_value, data_string):
    """
    Writes an item to DynamoDB.

    Parameters:
        - table (resource): The DynamoDB table resource.
        - key_value (str): The primary key value for the item.
        - data_string (str): The data string to be stored for the item.

    Returns:
        - dict: The response from the DynamoDB write operation.
    """
    # Define the item dictionary based on assumed attribute name 'id'
    item = {'id': key_value, 'data': data_string}
    
    # Put the item into DynamoDB
    response = table.put_item(Item=item)
    
    # Return the response
    return response
