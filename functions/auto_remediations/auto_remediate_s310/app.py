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


