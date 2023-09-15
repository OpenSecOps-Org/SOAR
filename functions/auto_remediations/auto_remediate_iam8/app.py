import os
import boto3

CROSS_ACCOUNT_ROLE = os.environ['CROSS_ACCOUNT_ROLE']

sts_client = boto3.client('sts')


def lambda_handler(data, _context):
    print(data)

    finding = data['finding']

    account_id = finding['AwsAccountId']
    region = finding['Resources'][0]['Region']
    user_name = finding['Resources'][0]['Details']['AwsIamUser']['UserName']

    client = get_client('iam', account_id, region)

    # Delete password
    try:
        client.delete_login_profile(UserName=user_name)
    except client.exceptions.NoSuchEntityException:
        pass

    # Delete access keys
    response = client.list_access_keys(UserName=user_name)
    for access_key in response['AccessKeyMetadata']:
        if access_key['Status'] == 'Active':
            client.delete_access_key(
                UserName=user_name,
                AccessKeyId=access_key['AccessKeyId']
            )

    data['messages']['actions_taken'] = "The IAM User remains, but password and access keys have been deleted."
    data['messages']['actions_required'] = "Delete the user or contact an administrator to reactivate access."
    return data


def get_client(client_type, account_id, region, role=CROSS_ACCOUNT_ROLE):
    other_session = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"auto_remediate_iam8_{account_id}"
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
