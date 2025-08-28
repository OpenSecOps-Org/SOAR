"""
ELB.5 AUTOREMEDIATION - ENABLE ALB AND CLB ACCESS LOGGING

This Lambda function automatically remediates AWS Security Hub findings for ELB.5
(Application and Classic Load Balancers logging should be enabled).

Target Resources:
- Application Load Balancers (ALBs)
- Classic Load Balancers (CLBs)
- Both internet-facing and internal load balancers

Remediation Actions:
1. Verifies load balancer exists
2. Creates dedicated S3 bucket for access logs with secure configuration:
   - Enables versioning for audit trails
   - Blocks all public access
   - Configures bucket policy for ELB service account access
   - Uses default S3 encryption (automatically enabled)
3. Enables access logging on the load balancer pointing to the S3 bucket

Validation Commands:
# Check load balancer access logging configuration
aws elbv2 describe-load-balancer-attributes --load-balancer-arn arn:aws:elasticloadbalancing:region:account:loadbalancer/app/name/id

# Verify access logs are enabled
aws elbv2 describe-load-balancer-attributes --load-balancer-arn <lb-arn> --query 'Attributes[?Key==`access_logs.s3.enabled`].Value'

# Check S3 bucket configuration
aws s3api get-bucket-policy --bucket lb-logs-for-<lb-name>
aws s3api get-bucket-versioning --bucket lb-logs-for-<lb-name>

Security Impact:
- Enables comprehensive access logging for security monitoring
- Creates audit trail for all load balancer requests
- Supports forensic analysis and compliance requirements
- Secure S3 bucket configuration prevents data exposure

S3 Bucket Security Features:
- Versioning enabled for data integrity
- Public access completely blocked
- Default encryption automatically enabled
- Bucket policy restricts access to ELB service accounts only

Error Handling:
- Missing load balancer: Suppresses finding
- Load balancer configuration errors: Flags for manual remediation
- S3 operation failures: Flags for manual remediation
- Existing bucket conflicts: Continues with configuration
"""

import os
import json
import boto3
import botocore
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


def extract_load_balancer_name(resource_details, lb_arn, max_length=50):
    """
    Extract load balancer name with multiple fallback options.
    
    Returns:
        tuple: (success: bool, name: str, source: str, error_message: str)
    """
    # Try LoadBalancerName first (use as-is)
    if 'LoadBalancerName' in resource_details and resource_details['LoadBalancerName']:
        value = resource_details['LoadBalancerName']
        return True, str(value)[:max_length], 'LoadBalancerName field', None
    
    # Try DNS fields (split on '.' and take first part)
    for dns_field in ['DnsName', 'DNSName']:
        if dns_field in resource_details and resource_details[dns_field]:
            value = resource_details[dns_field]
            name = value.split('.')[0][:max_length]
            return True, name, f'{dns_field} field', None
    
    # Fallback: extract from ARN
    try:
        # ARN format: arn:aws:elasticloadbalancing:region:account:loadbalancer/name
        arn_parts = lb_arn.split('/')
        if len(arn_parts) >= 2:
            name = arn_parts[-1][:max_length]  # Last part after final '/'
            return True, name, 'ARN extraction', None
    except Exception as e:
        pass  # Continue to error case
    
    # If nothing worked
    available_fields = list(resource_details.keys())
    error_msg = f"Unable to extract load balancer name from fields {available_fields} or ARN {lb_arn}"
    return False, None, None, error_msg


def lambda_handler(data, _context):
    print(data)

    finding = data['finding']
    account_id = finding['AwsAccountId']
    resource = finding['Resources'][0]
    region = resource['Region']
    elb_type = resource['Type']
    elb_account_id = ELB_ACCOUNTS[region]

    lb_arn = resource['Id']
    elb_details = resource['Details'][elb_type]

    success, lb_name, source, error_message = extract_load_balancer_name(elb_details, lb_arn)

    if not success:
        print(f"Unable to extract load balancer name: {error_message}")
        data['messages']['actions_taken'] = f"Cannot identify load balancer for remediation: {error_message}"
        data['messages']['actions_required'] = "Investigate why load balancer name could not be extracted from Security Hub finding data."
        data['actions']['autoremediation_not_done'] = True
        return data

    bucket_name = f"lb-logs-for-{lb_name.lower()}"

    print(f"lb_name: {lb_name} (extracted from {source})")
    print(f"bucket_name: {bucket_name}")

    s3_client = get_client('s3', account_id, region)

    # Determine LB type and appropriate client
    if elb_type == 'AwsElbLoadBalancer':  # Classic Load Balancer
        elb_client = get_client('elb', account_id, region)
        is_classic = True
        print("Detected Classic Load Balancer")
    else:  # Application/Network Load Balancer
        elb_client = get_client('elbv2', account_id, region)
        is_classic = False
        print("Detected Application/Network Load Balancer")

    # First, verify the load balancer exists
    try:
        print(f"Checking if load balancer '{lb_arn}' exists...")
        if is_classic:
            # Classic ELB uses LoadBalancerNames parameter
            elb_client.describe_load_balancers(LoadBalancerNames=[lb_name])
        else:
            # ALB/NLB uses LoadBalancerArns parameter
            elb_client.describe_load_balancers(LoadBalancerArns=[lb_arn])
        print("Load balancer exists, proceeding with remediation.")
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] in ['LoadBalancerNotFound', 'LoadBalancerNotFoundException']:
            print(f"Load balancer not found: {lb_arn}")
            data['messages']['actions_taken'] = f"Load balancer not found: {lb_arn}. This finding has been suppressed."
            data['actions']['suppress_finding'] = True
            return data
        else:
            raise e
    except Exception as e:
        print(f"Error checking load balancer existence: {str(e)}")
        data['messages']['actions_taken'] = f"Error checking load balancer existence: {str(e)}. This finding has been suppressed."
        data['actions']['suppress_finding'] = True
        return data

    # Create S3 bucket with region-specific handling
    try:
        print(f"Creating bucket '{bucket_name}' in region '{region}'...")
        if region == 'us-east-1':
            # us-east-1 doesn't accept LocationConstraint
            response = s3_client.create_bucket(Bucket=bucket_name)
        else:
            # All other regions require LocationConstraint
            response = s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': region}
            )
        print(response)
    except s3_client.exceptions.BucketAlreadyExists:
        print(f"Warning: The bucket '{bucket_name}' already exists.")
    except s3_client.exceptions.BucketAlreadyOwnedByYou:
        print(f"Warning: Bucket '{bucket_name}' is already owned by you.")
    except Exception as e:
        print(f"Error creating S3 bucket: {str(e)}")
        data['messages']['actions_taken'] = f"Error creating S3 bucket: {str(e)}"
        data['messages']['actions_required'] = "Investigate S3 bucket creation issue and create logging bucket manually."
        data['actions']['autoremediation_not_done'] = True
        return data

    # Configure S3 bucket with error handling
    try:
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

        # Note: S3 encryption is enabled by default, no explicit configuration needed

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

    except Exception as e:
        print(f"Error configuring S3 bucket: {str(e)}")
        data['messages']['actions_taken'] = f"Bucket created but configuration failed: {str(e)}"
        data['actions']['autoremediation_not_done'] = True
        return data

    # Enable access logging with type-specific handling
    print(f"Enabling access logs for LB '{lb_arn}'...")
    try:
        if is_classic:
            # Classic Load Balancer uses different API
            response = elb_client.modify_load_balancer_attributes(
                LoadBalancerName=lb_name,
                LoadBalancerAttributes={
                    'AccessLog': {
                        'Enabled': True,
                        'S3BucketName': bucket_name,
                        'S3BucketPrefix': ''
                    }
                }
            )
        else:
            # Application/Network Load Balancer
            response = elb_client.modify_load_balancer_attributes(
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
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] in ['LoadBalancerNotFound', 'LoadBalancerNotFoundException']:
            print(f"Load balancer not found during modification: {lb_arn}")
            data['messages']['actions_taken'] = f"Load balancer not found during modification: {lb_arn}. This finding has been suppressed."
            data['actions']['suppress_finding'] = True
            return data
        else:
            raise e
    except Exception as e:
        print(f"Error modifying load balancer attributes: {str(e)}")
        data['messages']['actions_taken'] = f"Error modifying load balancer attributes: {str(e)}"
        data['messages']['actions_required'] = "Investigate load balancer configuration issue and enable logging manually."
        data['actions']['autoremediation_not_done'] = True
        return data

    data['messages']['actions_taken'] = f"The bucket {bucket_name} was successfully created and configured for Load Balancer access logs."
    data['messages']['actions_required'] = "None"
    return data
