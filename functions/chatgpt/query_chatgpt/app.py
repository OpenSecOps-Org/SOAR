import os
import re
import boto3
import botocore
import botocore.exceptions
from openai import OpenAI
from openai import BadRequestError, RateLimitError, APITimeoutError, APIConnectionError, APIStatusError, OpenAIError
import html2text
import logging
from bs4 import BeautifulSoup


# Set the logging level to INFO
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Get environment variables
USE_CHATGPT = os.environ['USE_CHATGPT']
CHATGPT_DEFAULT_MODEL = os.environ['CHATGPT_DEFAULT_MODEL']
CHATGPT_FALLBACK_MODEL = os.environ['CHATGPT_FALLBACK_MODEL']

CHATGPT_ORGANIZATION_ID_PARAMETER_PATH = os.environ['CHATGPT_ORGANIZATION_ID_PARAMETER_PATH']
CHATGPT_API_KEY_PARAMETER_PATH = os.environ['CHATGPT_API_KEY_PARAMETER_PATH']

CHATGPT_IAC_SNIPPETS = os.environ['CHATGPT_IAC_SNIPPETS']

CHATGPT_ANONYMIZE_ACCOUNT_NUMBERS = os.environ['CHATGPT_ANONYMIZE_ACCOUNT_NUMBERS']
CHATGPT_ANONYMIZE_HEX_STRINGS = os.environ['CHATGPT_ANONYMIZE_HEX_STRINGS']
CHATGPT_REMOVE_ARNS = os.environ['CHATGPT_REMOVE_ARNS']
CHATGPT_REMOVE_EMAIL_ADDRESSES = os.environ['CHATGPT_REMOVE_EMAIL_ADDRESSES']

# Create a boto3 client for SSM
ssm_client = boto3.client('ssm')

# Get the OpenAI parameters from SSM
openai_organization = ssm_client.get_parameter(Name=CHATGPT_ORGANIZATION_ID_PARAMETER_PATH)['Parameter']['Value']
openai_api_key = ssm_client.get_parameter(Name=CHATGPT_API_KEY_PARAMETER_PATH)['Parameter']['Value']

# Create the OpenAI client
openai_client = OpenAI(organization=openai_organization, 
                       api_key=openai_api_key
                      )

# Define the lambda_handler function
def lambda_handler(data, _context):
    # Check if USE_CHATGPT is set to 'No'
    if USE_CHATGPT == 'No':
        return data
    
    # Should we post-process the html?
    no_html_post_processing = data.get('no_html_post_processing')

    # Get the model, temperature, top_p, frequency_penalty, and presence_penalty from the input data
    model = data.get('model', CHATGPT_DEFAULT_MODEL)
    fallback_model = data.get('model', CHATGPT_FALLBACK_MODEL)
    temperature = data.get('temperature', 0.2)
    top_p = data.get('top_p', 0.7)
    frequency_penalty = data.get('frequency_penalty', 0.3)
    presence_penalty = data.get('presence_penalty', 0.3)

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
    system_text = system_text.replace('[[IAC_SNIPPETS]]', CHATGPT_IAC_SNIPPETS)

    # Get the user_text from the input data or anonymize the email body
    user_text = data.get('user') or anonymise(data['messages']['email']['body'].split("====================")[0])

    # Create a list of messages
    messages = []

    # Add the system message to the messages list
    messages.append({
        "role": "system",
        "content": system_text
    })

    # Add the user message to the messages list
    messages.append({
        "role": "user",
        "content": user_text
    })

    response = call_openai_api(model, fallback_model, messages, temperature, top_p, frequency_penalty, presence_penalty)
    response = response.model_dump()
    logger.info(response)

    # Get the message and html from the response
    message = response['choices'][0]['message']
    html = message['content']
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


# Call the OpenAI API, with fallback
def call_openai_api(model, fallback_model, messages, temperature, top_p, frequency_penalty, presence_penalty):
    """
    Call OpenAI API with the provided model. If token limit is exceeded,
    and a fallback model is provided, it retries with the fallback model.
    """
    try:
        # Attempt to create a chat completion with the OpenAI API
        response = openai_client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
            top_p=top_p,
            frequency_penalty=frequency_penalty,
            presence_penalty=presence_penalty
        )
        return response

    except BadRequestError as e:
        # BadRequestError indicates a problem with the request; it might not be transient.
        # Check if the error is because of token limit and a fallback model is provided
        if 'context_length_exceeded' in str(e) and model != fallback_model:
            # If the error is due to token limit and a fallback model is provided,
            # retry with the fallback model.
            logger.info("Token limit exceeded, trying fallback model")
            return call_openai_api(fallback_model, None, messages, temperature, top_p, frequency_penalty, presence_penalty)
        else:
            # For other bad request errors, log and raise the exception to be caught by the Step Functions state machine.
            logger.error(f"BadRequestError: {str(e)}")
            raise

    except RateLimitError as e:
        # RateLimitError indicates too many requests; it's transient and should be retried.
        # This will trigger the Retry policy in the Step Functions state machine.
        logger.error(f"RateLimitError: {str(e)}")
        raise_lambda_too_many_requests_exception(str(e))

    except APITimeoutError as e:
        # APITimeoutError indicates a timeout; it's transient and should be retried.
        # This will trigger the Retry policy in the Step Functions state machine.
        logger.error(f"APITimeoutError: {str(e)}")
        raise_lambda_service_exception(str(e))

    except APIConnectionError as e:
        # APIConnectionError indicates a network connection error; it's transient and should be retried.
        # This will trigger the Retry policy in the Step Functions state machine.
        logger.error(f"APIConnectionError: {str(e)}")
        raise_lambda_service_exception(str(e))

    except APIStatusError as e:
        # APIStatusError is raised for non-200 HTTP status codes from the API.
        # If the status code is >= 500, it's a server-side error and should be retried.
        # Other status codes indicate client-side errors and should not be retried.
        if e.status_code >= 500:
            logger.error(f"InternalServerError: {str(e)}")
            raise_lambda_service_exception(str(e))
        else:
            logger.error(f"APIStatusError: {e.status_code} - {str(e.response)}")
            raise

    except OpenAIError as e:
        # OpenAIError is a catch-all for any other OpenAI-related exceptions not explicitly caught above.
        # This will not be retried by the Step Functions state machine and will move to the Catch block.
        logger.error(f"Unexpected OpenAIError: {str(e)}")
        raise

    except botocore.exceptions.BotoCoreError as e:
        # BotoCoreError indicates an issue with the AWS SDK for Python (Boto3).
        # If the error message is "An unspecified error occurred", it's considered transient and should be retried.
        # Otherwise, it will not be retried by the Step Functions state machine and will move to the Catch block.
        if str(e) == "An unspecified error occurred":
            logger.error("BotoCoreError: An unspecified error occurred")
            raise_lambda_service_exception("BotoCoreError: An unspecified error occurred")
        else:
            logger.error(f"Unexpected BotoCoreError: {str(e)}")
            raise


# Helper function to raise a Lambda TooManyRequestsException
def raise_lambda_too_many_requests_exception(error_message):
    error_code = 'Lambda.TooManyRequestsException'
    raise botocore.exceptions.BotoCoreError(error_code=error_code, message=error_message)

# Helper function to raise a Lambda ServiceException
def raise_lambda_service_exception(error_message):
    error_code = 'Lambda.ServiceException'
    raise botocore.exceptions.BotoCoreError(error_code=error_code, message=error_message)


# Helper function to anonymize input
def anonymise(input):
    if CHATGPT_ANONYMIZE_ACCOUNT_NUMBERS == 'Yes':
        aws_account_number_pattern = r"\b\d{12}\b"
        input = re.sub(aws_account_number_pattern, '[suppressed-account]', input)

    if CHATGPT_REMOVE_ARNS == 'Yes':
        aws_arn_pattern = r"arn:(aws[a-zA-Z0-9-]*):([a-zA-Z0-9-\.\_]*):([a-zA-Z0-9-\.\_]*):([0-9]*):([a-zA-Z0-9-\.\_\/]*)"
        input = re.sub(aws_arn_pattern, '[suppressed-arn]', input)

    if CHATGPT_REMOVE_EMAIL_ADDRESSES == 'Yes':
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        input = re.sub(email_pattern, '[suppressed-email]', input)

    if CHATGPT_ANONYMIZE_HEX_STRINGS == 'Yes':
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
