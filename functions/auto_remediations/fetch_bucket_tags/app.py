import os
import botocore
import boto3

CROSS_ACCOUNT_ROLE = os.environ['CROSS_ACCOUNT_ROLE']

sts_client = boto3.client('sts')


def lambda_handler(data, _context):
    print(data)

    finding = data['finding']

    account_id = finding['AwsAccountId']
    region = finding['Resources'][0]['Region']
    bucket_name = finding['Resources'][0]['Id'].split(':::', 1)[1]

    client = get_client('s3', account_id, region)

    try:
        response = client.get_bucket_tagging(
            Bucket=bucket_name,
            ExpectedBucketOwner=account_id
        )
        tags = response['TagSet']
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'NoSuchTagSet':
            tags = []
        elif error.response['Error']['Code'] == 'NoSuchBucket':
            tags = []
        else:
            raise error

    data['tags']['resource'] = tags
    return data


def get_client(client_type, account_id, region, role=CROSS_ACCOUNT_ROLE):
    other_session = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"fetch_bucket_tags_{account_id}"
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
