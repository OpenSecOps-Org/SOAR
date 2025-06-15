"""
S3.2 AUTOREMEDIATION - BLOCK S3 BUCKET PUBLIC ACCESS

This Lambda function automatically remediates AWS Security Hub findings for S3.2 
(S3 buckets should prohibit public access).

Target Resources:
- S3 buckets with public access allowed

Remediation Actions:
1. Check for exemption tag - if present, suppress finding
2. Apply public access block configuration with all restrictions enabled:
   - BlockPublicAcls: True
   - IgnorePublicAcls: True
   - BlockPublicPolicy: True
   - RestrictPublicBuckets: True

Error Handling:
- NoSuchBucket: Finding suppressed (resource no longer exists)
- AccessDenied: Finding suppressed (insufficient permissions)
- Other errors: Auto-remediation marked as failed

Test Triggers:
1. Create S3 bucket with public access allowed
2. Verify the finding appears in Security Hub for S3.2
3. aws s3api get-public-access-block --bucket [bucket-name] (should show public access allowed)

Security Hub Control:
- https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-2
"""

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
