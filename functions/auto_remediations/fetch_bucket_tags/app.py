import os
import botocore
import boto3
from aws_utils.clients import get_client


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


