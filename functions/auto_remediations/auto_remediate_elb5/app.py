import os
import json
import boto3
from aws_utils.clients import get_client

ELB_ACCOUNTS = {
    'eu-north-1': '897822967062',
    'us-east-1': '127311923021',
    'us-east-2': '033677994240',
    'us-west-1': '027434742980',
    'us-west-2': '797873946194',
    'af-south-1': '098369216593',
    'ca-central-1': '985666609251',
    'eu-central-1': '054676820928',
    'eu-west-1': '156460612806',
    'eu-west-2': '652711504416',
    'eu-south-1': '635631232127',
    'eu-west-3': '009996457667',
    'ap-east-1': '754344448648',
    'ap-northeast-1': '582318560864',
    'ap-northeast-2': '600734575887',
    'ap-northeast-3': '383597477331',
    'ap-southeast-1': '114774131450',
    'ap-southeast-2': '783225319266',
    'ap-south-1': '718504428378',
    'me-south-1': '076674570225',
    'sa-east-1': '507241528517',
    'us-gov-west-1': '048591011584',
    'us-gov-east-1': '190560391635',
    'cn-north-1': '638102146993',
    'cn-northwest-1': '037604701340',
}


def lambda_handler(data, _context):
    print(data)

    finding = data['finding']
    account_id = finding['AwsAccountId']
    resource = finding['Resources'][0]
    region = resource['Region']
    elb_type = resource['Type']
    elb_account_id = ELB_ACCOUNTS[region]

    lb_arn = resource['Id']
    lb_dns_name = resource['Details'][elb_type]['DNSName']
    lb_name = lb_dns_name.split('.')[0][0:50]

    bucket_name = f"lb-logs-for-{lb_name.lower()}"

    print(f"lb_dns_name: {lb_dns_name}")
    print(f"lb_name: {lb_name}")
    print(f"bucket_name: {bucket_name}")


    s3_client = get_client('s3', account_id, region)
    elbv2_client = get_client('elbv2', account_id, region)

    # First, verify the load balancer exists
    try:
        print(f"Checking if load balancer '{lb_arn}' exists...")
        elbv2_client.describe_load_balancers(LoadBalancerArns=[lb_arn])
        print("Load balancer exists, proceeding with remediation.")
    except elbv2_client.exceptions.LoadBalancerNotFoundException:
        print(f"Load balancer not found: {lb_arn}")
        data['messages']['actions_taken'] = f"Load balancer not found: {lb_arn}. This finding has been suppressed."
        data['actions']['suppress_finding'] = True
        return data
    except Exception as e:
        print(f"Error checking load balancer existence: {str(e)}")
        data['messages']['actions_taken'] = f"Error checking load balancer existence: {str(e)}. This finding has been suppressed."
        data['actions']['suppress_finding'] = True
        return data

    try:
        print(f"Creating bucket '{bucket_name}'...")
        response = s3_client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={
                'LocationConstraint': region,
            },
        )
        print(response)
    except s3_client.exceptions.BucketAlreadyExists:
        print(f"Warning: The bucket '{bucket_name}' already exists.")
    except s3_client.exceptions.BucketAlreadyOwnedByYou:
        print(f"Warning: Bucket '{bucket_name}' is already owned by you.")


    print(f"Enabling versioning for bucket '{bucket_name}'...")
    response = s3_client.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={
            'MFADelete': 'Disabled',
            'Status': 'Enabled'
        }
    )
    print(response)

    print(f"Putting access block on bucket '{bucket_name}'...")
    response = s3_client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )
    print(response)

    print(f"Encrypting bucket '{bucket_name}'...")
    response = s3_client.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            'Rules': [
                {
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'AES256'
                    }
                },
            ]
        }
    )
    print(response)

    print(f"Attaching bucket policy to bucket '{bucket_name}'...")
    response = s3_client.put_bucket_policy(
        Bucket=bucket_name,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": f"arn:aws:iam::{elb_account_id}:root"
                        },
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/*"
                    },
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "logdelivery.elb.amazonaws.com"
                        },
                        "Action": "s3:GetBucketAcl",
                        "Resource": f"arn:aws:s3:::{bucket_name}"
                    }
                ]
            }
        )
    )
    print(response)

    print(f"Enabling access logs for LB '{lb_arn}'...")
    try:
        response = elbv2_client.modify_load_balancer_attributes(
            Attributes=[
                {
                    'Key': 'access_logs.s3.enabled',
                    'Value': 'true',
                },
                {
                    'Key': 'access_logs.s3.bucket',
                    'Value': bucket_name,
                },
                {
                    'Key': 'access_logs.s3.prefix',
                    'Value': '',
                },
            ],
            LoadBalancerArn=lb_arn,
        )
        print(response)
    except elbv2_client.exceptions.LoadBalancerNotFoundException:
        print(f"Load balancer not found during modification: {lb_arn}")
        data['messages']['actions_taken'] = f"Load balancer not found during modification: {lb_arn}. This finding has been suppressed."
        data['actions']['suppress_finding'] = True
        return data
    except Exception as e:
        print(f"Error modifying load balancer attributes: {str(e)}")
        data['messages']['actions_taken'] = f"Error modifying load balancer attributes: {str(e)}. This finding has been suppressed."
        data['actions']['suppress_finding'] = True
        return data

    data['messages']['actions_taken'] = f"The bucket {bucket_name} was successfully created and configured for Load Balancer access logs."
    data['messages']['actions_required'] = f"None"
    return data


