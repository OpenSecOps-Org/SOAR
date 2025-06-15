"""
S3.10 AUTOREMEDIATION - ENABLE S3 BUCKET LIFECYCLE CONFIGURATION

This Lambda function automatically remediates AWS Security Hub findings for S3.10 
(S3 buckets should have lifecycle configuration).

Target Resources:
- S3 buckets without lifecycle configuration

Remediation Actions:
1. Apply lifecycle configuration with cost optimization rules:
   - Delete noncurrent versions after 365 days (keeping 1 newer version)
   - Abort incomplete multipart uploads after 1 day
2. Rule applies to all objects in the bucket (empty prefix filter)

Lifecycle Configuration Details:
- Rule ID: 'DeleteNoncurrentAndIncomplete'
- NoncurrentVersionExpiration: 365 days, keeps 1 newer version
- AbortIncompleteMultipartUpload: 1 day cleanup

Error Handling:
- Generic exception handling: All errors result in finding suppression
- Conservative approach: Suppress finding on any API failure

Test Triggers:
1. Create S3 bucket without lifecycle configuration
2. Verify the finding appears in Security Hub for S3.10
3. aws s3api get-bucket-lifecycle-configuration --bucket [bucket-name] (should return no configuration)

Security Hub Control:
- https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-10
"""

import os
import boto3
from aws_utils.clients import get_client


def lambda_handler(data, _context):
    print(data)

    finding = data['finding']

    account_id = finding['AwsAccountId']
    bucket_id = finding['Resources'][0]['Id']
    region = finding['Resources'][0]['Region']
    bucket_name = bucket_id.split(':::', 1)[1]

    client = get_client('s3', account_id, region)

    try:
        response = client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration={
                'Rules': [
                    {
                        'ID': 'DeleteNoncurrentAndIncomplete',
                        'Status': 'Enabled',
                        'Filter': {
                            'Prefix': '',
                        },
                        'NoncurrentVersionExpiration': {
                            'NoncurrentDays': 365,
                            'NewerNoncurrentVersions': 1
                        },
                        'AbortIncompleteMultipartUpload': {
                            'DaysAfterInitiation': 1
                        }
                    },
                ],
            },
        )
        print(response)
    except Exception as exc:
        print(f"Exception: {exc}, suppressing.")
        data['messages']['actions_taken'] = "Couldn't create a bucket lifecycle configuration. This finding will be suppressed."
        data['actions']['suppress_finding'] = True
        return data

    data['messages']['actions_taken'] = "A lifecycle configuration has been added to the bucket. Noncurrent versions will be deleted after a year, and incomplete uploads after a day."
    return data


