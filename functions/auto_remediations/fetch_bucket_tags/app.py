"""
FETCH S3 BUCKET TAGS - HELPER FUNCTION FOR TAG-BASED EXEMPTIONS

This Lambda function retrieves S3 bucket tags to support tag-based exemption logic 
in S3 auto-remediation functions.

Target Resources:
- S3 buckets requiring tag information for downstream processing

Functionality:
1. Extract bucket details from Security Hub finding
2. Retrieve bucket tags using cross-account S3 client
3. Handle expected error scenarios gracefully
4. Add tags to data structure for downstream consumption

Error Handling:
- NoSuchTagSet: Returns empty tag array (bucket has no tags)
- NoSuchBucket: Returns empty tag array (bucket doesn't exist)
- Other ClientError: Re-raises for upstream handling

Integration:
- Used by S3.2 and S3.3 auto-remediation functions
- Populates data['tags']['resource'] for tag exemption logic
- Critical for organizational override policies

Test Triggers:
1. Create S3 bucket with tags
2. Create S3 bucket without tags
3. Test with non-existent bucket
4. aws s3api get-bucket-tagging --bucket [bucket-name]

Security Features:
- Uses ExpectedBucketOwner parameter for additional security
- Cross-account access via role assumption
"""

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


