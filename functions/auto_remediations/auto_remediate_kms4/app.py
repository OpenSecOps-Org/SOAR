import os
import boto3
from botocore.exceptions import ClientError
from aws_utils.clients import get_client


def lambda_handler(data, _context):
    print(data)

    finding = data['finding']

    account_id = finding['AwsAccountId']
    region = finding['Resources'][0]['Region']
    key_arn = finding['Resources'][0]['Id']
    key_id = key_arn.rsplit('/', 1)[1]

    client = get_client('kms', account_id, region)

    try:
        client.enable_key_rotation(KeyId=key_id)
    except ClientError as error:
        error_code = error.response['Error']['Code']
        error_message = error.response['Error']['Message']
        print(f"Error enabling key rotation: {error_code} - {error_message}")
        
        if error_code in ['AccessDeniedException', 'KMSInvalidStateException', 'NotFoundException']:
            data['messages']['actions_taken'] = f"Couldn't enable key rotation: {error_code}. This finding has been suppressed."
            data['actions']['suppress_finding'] = True
        else:
            data['messages']['actions_taken'] = f"Failed to enable key rotation: {error_code}"
            data['actions']['autoremediation_not_done'] = True
        return data
    except Exception as exc:
        print(f"Unexpected exception: {exc}, suppressing.")
        data['messages']['actions_taken'] = "Couldn't enable key rotation due to an unexpected error. This finding has been suppressed."
        data['actions']['suppress_finding'] = True
        return data

    data['messages']['actions_taken'] = "Automatic yearly key rotation has been enabled."
    return data
