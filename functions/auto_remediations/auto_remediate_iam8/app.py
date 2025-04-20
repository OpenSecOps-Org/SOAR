import os
import boto3
from aws_utils.clients import get_client


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


