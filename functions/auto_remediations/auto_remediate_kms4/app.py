import os
import boto3

CROSS_ACCOUNT_ROLE = os.environ['CROSS_ACCOUNT_ROLE']

sts_client = boto3.client('sts')


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
    except Exception as exc:
        print(f"Exception: {exc}, suppressing.")
        data['messages']['actions_taken'] = "Couldn't enable key rotation. This finding has been suppressed."
        data['actions']['suppress_finding'] = True
        return data

    data['messages']['actions_taken'] = "Automatic yearly key rotation has been enabled."
    return data


def get_client(client_type, account_id, region, role=CROSS_ACCOUNT_ROLE):
    other_session = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"auto_remediate_kms4_{account_id}"
    )
    access_key = other_session['Credentials']['AccessKeyId']
    secret_key = other_session['Credentials']['SecretAccessKey']
    session_token = other_session['Credentials']['SessionToken']
    return boto3.client(
        client_type,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=region
    )
