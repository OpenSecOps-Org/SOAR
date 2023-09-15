import os
import boto3

CROSS_ACCOUNT_ROLE = os.environ['CROSS_ACCOUNT_ROLE']

sts_client = boto3.client('sts')


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


def get_client(client_type, account_id, region, role=CROSS_ACCOUNT_ROLE):
    other_session = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"auto_remediate_s310_{account_id}"
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
