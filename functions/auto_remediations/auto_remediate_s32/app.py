import os
import boto3
from botocore.exceptions import ClientError

CROSS_ACCOUNT_ROLE = os.environ['CROSS_ACCOUNT_ROLE']
TAG = os.environ['TAG']

sts_client = boto3.client('sts')


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


def get_client(client_type, account_id, region, role=CROSS_ACCOUNT_ROLE):
    other_session = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"auto_remediate_s32_{account_id}"
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


def has_tag(tag, tags):
    for pair in tags:
        if pair['Key'] == tag:
            return True
    return False
