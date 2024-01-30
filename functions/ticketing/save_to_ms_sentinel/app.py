import os
import boto3
import requests
from requests.exceptions import RequestException
import json
import datetime
import hashlib
import hmac
import base64


INCIDENTS_TO_SENTINEL = os.environ['INCIDENTS_TO_SENTINEL']   # NONE/INFRA/APP/ALL
SENTINEL_WORKSPACE_ID_PARAMETER_PATH = os.environ['SENTINEL_WORKSPACE_ID_PARAMETER_PATH']
SENTINEL_SHARED_KEY_PARAMETER_PATH = os.environ['SENTINEL_SHARED_KEY_PARAMETER_PATH']
SENTINEL_LOG_TYPE_PARAMETER_PATH = os.environ['SENTINEL_LOG_TYPE_PARAMETER_PATH']


# Create a boto3 client for AWS SSM
client = boto3.client('ssm')

# Get the MS Sentinel connection data from AWS Parameter Store
WORKSPACE_ID = client.get_parameter(Name=SENTINEL_WORKSPACE_ID_PARAMETER_PATH)['Parameter']['Value']
SHARED_KEY = client.get_parameter(Name=SENTINEL_SHARED_KEY_PARAMETER_PATH)['Parameter']['Value']
LOG_TYPE = client.get_parameter(Name=SENTINEL_LOG_TYPE_PARAMETER_PATH)['Parameter']['Value']

CREDS = [WORKSPACE_ID, SHARED_KEY, LOG_TYPE]


# Define the lambda_handler function
def lambda_handler(data, _context):
    if 'REPLACE_ME' in CREDS:
        print("Microsoft Sentinel WORKSPACE_ID, SHARED_KEY or LOG_TYPE not defined.")
        return False

    print(data)

    # The incident domain defaults to INFRA. Can be INFRA or APP.
    incident_domain = data['finding']['ProductFields'].get('IncidentDomain', 'INFRA')

    # Shall we bother?
    is_right_domain = (INCIDENTS_TO_SENTINEL == 'ALL' or INCIDENTS_TO_SENTINEL == incident_domain)

    if not is_right_domain:
        # No, we shall not bother
        return True

    # Do the thing
    json_data = compose_json_data(data)
    print(json_data)

    body = json.dumps(json_data)
    headers = authenticate(WORKSPACE_ID, SHARED_KEY, LOG_TYPE, body)
    response = send_data(WORKSPACE_ID, body, headers)

    # Check if the response is None (which indicates a silent fail)
    if response is None or (200 <= response.status_code <= 299):
        print('Data was successfully ingested or failed silently.')
        return True
    else:
        print(f"Failed to ingest data. Status code: {response.status_code}, Response text: {response.text}")
        return False


# Build the API signature
def build_signature(workspace_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = f'x-ms-date:{date}'
    string_to_hash = f'{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}'
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = f"SharedKey {workspace_id}:{encoded_hash}"
    return authorization


# Authenticate and return headers
def authenticate(workspace_id, shared_key, log_type, body):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(workspace_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    headers = {
        'Content-Type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }
    return headers


# Send the data to the Azure Log Analytics workspace
def send_data(workspace_id, body, headers):
    uri = f'https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01'
    try:
        response = requests.post(uri, data=body, headers=headers, timeout=10)  # Set a reasonable timeout
        return response
    except RequestException as e:
        print(f"An error occurred while sending data to Sentinel: {e}")
        return None  # Return None or a custom response indicating a silent fail


# Compose the JSON data from the input data
def compose_json_data(data):
    finding = data['finding']
    account = finding.get('account', {})
    log_data = {
        "CreatedAt": finding.get('CreatedAt'),                  # ISO 8601 UTC
        "UpdatedAt": finding.get('UpdatedAt'),                  # ISO 8601 UTC
        "ProcessedAt": finding.get('ProcessedAt'),              # ISO 8601 UTC
        "FindingId": finding.get('Id'),                         # Long URL-like or ARN
        "GeneratorId": finding.get('GeneratorId'),              # Text string
        "Type": (finding.get('FindingProviderFields', {}).get('Types') or [None])[0],   # Text string
        "ProductName": finding.get('ProductName'),              # Text string ("GuardDuty")
        "Severity": finding.get('Severity', {}).get('Label'),   # Text string: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
        "Title": finding.get('Title'),                          # Text string
        "Description": finding.get('Description'),              # Text string
        "Region": finding.get('Region'),                        # Text string (eu-north-1, etc)
        "AwsAccountName": finding.get('AwsAccountName'),        # Text string ("Blahonga-account")
        "AwsAccountId": finding.get('AwsAccountId'),            # Text string, 12 decimal characters
        "Team": account.get('Team'),                            # Text string ("Infra")
        "TeamEmail": account.get('TeamEmail'),                  # Text string ("some-email@lynxhedge.se")
        "Environment": account.get('Environment'),              # Text string (DEV/PROD/PREPROD)
        "OrganizationalUnit": account.get('OrganizationalUnit') # Text string ("Sandbox")
    }
    # Remove keys with None values to avoid sending them to Azure Monitor
    log_data = {k: v for k, v in log_data.items() if v is not None}
    return [log_data]  # The API expects an array of log data objects
