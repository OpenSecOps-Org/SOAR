import os
import re
import boto3
import botocore
import botocore.exceptions
import json
from openai import OpenAI
from openai import BadRequestError, RateLimitError, APITimeoutError, APIConnectionError, APIStatusError, OpenAIError
import html2text
import logging
from bs4 import BeautifulSoup


# Set the logging level to INFO
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Get environment variables
AI_PROVIDER = os.environ['AI_PROVIDER']
AI_IAC_SNIPPETS = os.environ['AI_IAC_SNIPPETS']
AI_ANONYMIZE_ACCOUNT_NUMBERS = os.environ['AI_ANONYMIZE_ACCOUNT_NUMBERS']
AI_ANONYMIZE_HEX_STRINGS = os.environ['AI_ANONYMIZE_HEX_STRINGS']
AI_REMOVE_ARNS = os.environ['AI_REMOVE_ARNS']
AI_REMOVE_EMAIL_ADDRESSES = os.environ['AI_REMOVE_EMAIL_ADDRESSES']

BEDROCK_REGION = os.environ['BEDROCK_REGION']
BEDROCK_MODEL = os.environ['BEDROCK_MODEL']

CHATGPT_DEFAULT_MODEL = os.environ['CHATGPT_DEFAULT_MODEL']
CHATGPT_FALLBACK_MODEL = os.environ['CHATGPT_FALLBACK_MODEL']
CHATGPT_ORGANIZATION_ID_PARAMETER_PATH = os.environ['CHATGPT_ORGANIZATION_ID_PARAMETER_PATH']
CHATGPT_API_KEY_PARAMETER_PATH = os.environ['CHATGPT_API_KEY_PARAMETER_PATH']

SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']

# Initialize the SNS client
sns_client = boto3.client('sns')

# Conditional client initialization
if AI_PROVIDER == 'OPENAI':
    # Create a boto3 client for SSM
    ssm_client = boto3.client('ssm')
    # Get the OpenAI parameters from SSM
    openai_organization = ssm_client.get_parameter(Name=CHATGPT_ORGANIZATION_ID_PARAMETER_PATH)['Parameter']['Value']
    openai_api_key = ssm_client.get_parameter(Name=CHATGPT_API_KEY_PARAMETER_PATH)['Parameter']['Value']
    # Create the OpenAI client
    openai_client = OpenAI(organization=openai_organization, api_key=openai_api_key)

elif AI_PROVIDER == 'BEDROCK':
    # Create the Bedrock client
    bedrock_client = boto3.client('bedrock-runtime', region_name=BEDROCK_REGION)


# Define the lambda_handler function
def lambda_handler(data, _context):
    # Return immediately if AI isn't to be used
    if AI_PROVIDER == 'NONE':
        return data
    
    # Should we post-process the html?
    no_html_post_processing = data.get('no_html_post_processing')

    # Get the system_text and instructions from the input data
    system_text = data.get('system')
    instructions = data.get('instructions')

    # If instructions are not provided, get them from nested_instructions
    if not instructions:
        nested_instructions = data.get('nested_instructions')
        if nested_instructions:
            instructions = nested_instructions['instructions']

    # If system_text is not provided, set a default value
    if not system_text:
        system_text = "You are a helpful security assistant offering detailed expert advice and answers on AWS security controls and incidents.\n\n"
        system_text += "Context: Severity levels are INFORMATIONAL, requiring no attention; LOW, requiring attention when convenient; MEDIUM, requiring attention within the current sprint; HIGH, requiring attention within a few hours; and CRITICAL, a show-stopper requiring immediate attention.\n\n"
        system_text += 'The output is HTML. Output your results as HTML inside a <div style="font-family: Verdana, sans-serif; font-size:16px;"> ... </div>.\n\n'
        system_text += "Clearly header your output using as few words as possible. For instance, 'Analysis' is better than 'Detailed Expert Analysis of the Security Issue' or 'Detailed Expert Analysis'.\n\n"
        system_text += instructions

    # Insert the desired IaC snippet languages
    system_text = system_text.replace('[[IAC_SNIPPETS]]', AI_IAC_SNIPPETS)

    # Get the user_text from the input data or anonymize the email body
    user_text = data.get('user') or anonymise(data['messages']['email']['body'].split("====================")[0])

    # Call the right API and model and set the HTML result
    if AI_PROVIDER == 'BEDROCK':
        html = call_bedrock_api(BEDROCK_MODEL, system_text, user_text)
    else:  # OPENAI
        html = call_openai_api(CHATGPT_DEFAULT_MODEL, CHATGPT_FALLBACK_MODEL, system_text, user_text)

    # Post-processing galore
    if not no_html_post_processing:
        html = format_tables_inline(html)
        html = format_pre_sections(html)

    # Add the plaintext and html messages to the data
    if not data.get('messages'):
        data['messages'] = {}

    if not data['messages'].get('ai'):
        data['messages']['ai'] = {}

    data['messages']['ai'] = {
        'plaintext': html2text.html2text(html),
        'html': html
    }

    return data


# Call the Bedrock API
def call_bedrock_api(model, system_text, user_text):
    """
    Call the Bedrock API with the specified model (right now only the Anthropic format is supported).
    """
    messages = [{"role": "user", "content": [{"type": "text", "text": f"{system_text}\n\n{user_text}"}]}]
    logger.info(f"Bedrock API input: {messages}")

    try:
        # Prepare the request body
        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 8192,
            "messages": messages,
            "temperature": 0.3,
            # "top_p": 0.7,
            "top_k": 250
        })

        # Call the Bedrock API
        response = bedrock_client.invoke_model(
            modelId=model,
            contentType='application/json',
            accept='application/json',
            body=body
        )
        
        # Parse the response
        response_body = json.loads(response['body'].read())
        logger.info(f"Bedrock API response: {response_body}")
        completion = response_body['content'][0]['text']
        logger.info(f"Completion: {completion}")
        return completion

    except Exception as e:
        logger.error(f"Error calling Bedrock API: {str(e)}")
        send_sns_notification(f"Bedrock API Error: {str(e)}")
        raise


# Call the OpenAI API, with fallback
def call_openai_api(model, fallback_model, system_text, user_text):
    """
    Call OpenAI API with the provided model. If token limit is exceeded,
    and a fallback model is provided, it retries with the fallback model.
    """
    messages = [
        {"role": "system", "content": system_text},
        {"role": "user", "content": user_text}
    ]
    logger.info(f"OpenAI API input: {messages}")

    try:
        # Attempt to create a chat completion with the OpenAI API
        response = openai_client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0.3,
            top_p=0.7,
            frequency_penalty=0.3,
            presence_penalty=0.1
        )
        response = response.model_dump()
        logger.info(f"OpenAI API response: {response}")
        # Get the message and html from the response
        message = response['choices'][0]['message']
        html = message['content']
        logger.info(f"HTML: {html}")
        return html

    except BadRequestError as e:
        # BadRequestError indicates a problem with the request; it might not be transient.
        # Check if the error is because of token limit and a fallback model is provided
        if 'context_length_exceeded' in str(e) and model != fallback_model:
            # If the error is due to token limit and a fallback model is provided,
            # retry with the fallback model.
            logger.info("Token limit exceeded, trying fallback model")
            return call_openai_api(fallback_model, None, messages)
        else:
            # For other bad request errors, log and raise the exception to be caught by the Step Functions state machine.
            logger.error(f"BadRequestError: {str(e)}")
            send_sns_notification(f"BadRequestError occurred: {str(e)}")
            raise

    except RateLimitError as e:
        # RateLimitError indicates too many requests; it's transient and should be retried.
        # This will trigger the Retry policy in the Step Functions state machine.
        logger.error(f"RateLimitError: {str(e)}")
        send_sns_notification(f"RateLimitError occurred: {str(e)}")
        raise_lambda_too_many_requests_exception(str(e))

    except APITimeoutError as e:
        # APITimeoutError indicates a timeout; it's transient and should be retried.
        # This will trigger the Retry policy in the Step Functions state machine.
        logger.error(f"APITimeoutError: {str(e)}")
        send_sns_notification(f"APITimeoutError occurred: {str(e)}")
        raise_lambda_service_exception(str(e))

    except APIConnectionError as e:
        # APIConnectionError indicates a network connection error; it's transient and should be retried.
        # This will trigger the Retry policy in the Step Functions state machine.
        logger.error(f"APIConnectionError: {str(e)}")
        send_sns_notification(f"APIConnectionError occurred: {str(e)}")
        raise_lambda_service_exception(str(e))

    except APIStatusError as e:
        # APIStatusError is raised for non-200 HTTP status codes from the API.
        # If the status code is >= 500, it's a server-side error and should be retried.
        # Other status codes indicate client-side errors and should not be retried.
        logger.error(f"APIStatusError: {e.status_code} - {str(e.response)}")
        send_sns_notification(f"APIStatusError occurred: {e.status_code} - {str(e.response)}")
        if e.status_code >= 500:
            raise_lambda_service_exception(str(e))
        else:
            raise

    except OpenAIError as e:
        # OpenAIError is a catch-all for any other OpenAI-related exceptions not explicitly caught above.
        # This will not be retried by the Step Functions state machine and will move to the Catch block.
        logger.error(f"Unexpected OpenAIError: {str(e)}")
        send_sns_notification(f"OpenAIError occurred: {str(e)}")
        raise

    except botocore.exceptions.BotoCoreError as e:
        # BotoCoreError indicates an issue with the AWS SDK for Python (Boto3).
        # If the error message is "An unspecified error occurred", it's considered transient and should be retried.
        # Otherwise, it will not be retried by the Step Functions state machine and will move to the Catch block.
        logger.error(f"BotoCoreError: {str(e)}")
        send_sns_notification(f"BotoCoreError occurred: {str(e)}")
        if str(e) == "An unspecified error occurred":
            raise_lambda_service_exception("BotoCoreError: An unspecified error occurred")
        else:
            raise


# Helper function to raise a Lambda TooManyRequestsException
def raise_lambda_too_many_requests_exception(error_message):
    error_code = 'Lambda.TooManyRequestsException'
    raise botocore.exceptions.BotoCoreError(error_code=error_code, message=error_message)

# Helper function to raise a Lambda ServiceException
def raise_lambda_service_exception(error_message):
    error_code = 'Lambda.ServiceException'
    raise botocore.exceptions.BotoCoreError(error_code=error_code, message=error_message)


# Helper function to send an SNS notification
def send_sns_notification(message):
    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Message=message,
        Subject="GenAI Call Error"
    )


# Helper function to anonymize input
def anonymise(input):
    if AI_ANONYMIZE_ACCOUNT_NUMBERS == 'Yes':
        aws_account_number_pattern = r"\b\d{12}\b"
        input = re.sub(aws_account_number_pattern, '[suppressed-account]', input)

    if AI_REMOVE_ARNS == 'Yes':
        aws_arn_pattern = r"arn:(aws[a-zA-Z0-9-]*):([a-zA-Z0-9-\.\_]*):([a-zA-Z0-9-\.\_]*):([0-9]*):([a-zA-Z0-9-\.\_\/]*)"
        input = re.sub(aws_arn_pattern, '[suppressed-arn]', input)

    if AI_REMOVE_EMAIL_ADDRESSES == 'Yes':
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        input = re.sub(email_pattern, '[suppressed-email]', input)

    if AI_ANONYMIZE_HEX_STRINGS == 'Yes':
        uuid_pattern = r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        input = re.sub(uuid_pattern, '[suppressed-uuid]', input)

        hex_pattern = r"\b[0-9A-Fa-f]{5,}\b"
        input = re.sub(hex_pattern, '[suppressed-hex]', input)

    return input


# Add inline styling to all tables, as email clients are dodgy with HEAD style and classes
def format_tables_inline(html):
    logger.info(html)

    # Create a BeautifulSoup object to parse the HTML
    soup = BeautifulSoup(html, 'html.parser')

    # Replace inline styling for table elements
    for table in soup.find_all('table'):
        table['style'] = 'border: 1px solid black; border-collapse: collapse; padding: 4px; background-color: #EEEEEE; font-size: 14px;'

    # Replace inline styling for th elements
    for th in soup.find_all('th'):
        th['style'] = 'background-color: grey; color: white; border: 1px solid black; border-collapse: collapse; padding: 4px;'

    # Add or replace inline styling in td elements
    for td in soup.find_all('td'):
        if 'style' in td.attrs:
            td['style'] += '; border: 1px solid black; border-collapse: collapse; padding: 4px;'
        else:
            td['style'] = 'border: 1px solid black; border-collapse: collapse; padding: 4px;'

        # Check if the contents of the <td> tag contain "OVERDUE"
        if 'OVERDUE' in td.text:
            td['style'] += '; background-color: red;'

        # Check if the contents of the <td> tag contain severity levels
        if td.text in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
            severity = td.text

            # Set the background color based on the severity level
            if severity == "CRITICAL":
                bgcolour = "FF00FF"  # violet
            elif severity == "HIGH":
                bgcolour = "FF0000"  # red
            elif severity == "MEDIUM":
                bgcolour = "FF8000"  # orange
            elif severity == "LOW":
                bgcolour = "FFFF00"  # yellow
            elif severity == "INFORMATIONAL":
                bgcolour = "E0E0E0"  # light gray

            td['style'] += f'; background-color: #{bgcolour};'


    # Return the modified HTML
    html = str(soup)
    logger.info(html)
    return html


def format_pre_sections(html):
    # Define the style to be inserted
    style = 'style="background-color: #030204; padding: 12px; color: #f8f9d2;"'

    # Use a regular expression to search and replace all <pre> tags with the modified version
    updated_html = re.sub(r'<pre>', f'<pre {style}>', html)

    return updated_html
