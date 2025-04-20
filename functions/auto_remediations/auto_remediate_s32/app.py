import os
import boto3
from botocore.exceptions import ClientError
from aws_utils.clients import get_client

TAG = os.environ['TAG']


def lambda_handler(data, _context):
    print(data)

    finding = data['finding']
    tags = data['tags']['resource']

    if has_tag(TAG, tags):
        print(f"This bucket has the {TAG} tag. Suppressing this finding.")
        data['actions']['suppress_finding'] = True
        return data

    account_id = finding['AwsAccountId']
    bucket_id = finding['Resources'][0]['Id']
    region = finding['Resources'][0]['Region']
    bucket_name = bucket_id.split(':::', 1)[1]

    client = get_client('s3', account_id, region)

    try:
        response = client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        print(response)
    except ClientError as error:
        error_code = error.response['Error']['Code']
        error_message = error.response['Error']['Message']
        print(f"Error blocking public access: {error_code} - {error_message}")
        
        if error_code in ['NoSuchBucket', 'AccessDenied']:
            data['messages']['actions_taken'] = f"Unable to block public access: {error_code}. This finding has been suppressed."
            data['actions']['suppress_finding'] = True
            return data
        else:
            data['messages']['actions_taken'] = f"Failed to block public access: {error_code}"
            data['actions']['autoremediation_not_done'] = True
            return data

    data['messages'][
        'actions_taken'] = f"Public access has been disabled, as the tag '{TAG}' wasn't found on the bucket."
    data['messages']['actions_required'] = f"Adding the tag '{TAG}' to an existing bucket will not re-enable public access. You must redeploy with the correct tag, or add the tag and manually re-enable public access."
    return data


def has_tag(tag, tags):
    for pair in tags:
        if pair['Key'] == tag:
            return True
    return False
