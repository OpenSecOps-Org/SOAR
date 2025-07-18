"""
DYNAMODB.2 AUTOREMEDIATION - ENABLE POINT-IN-TIME RECOVERY

This Lambda function automatically remediates AWS Security Hub findings for DynamoDB.2
(DynamoDB tables should have point-in-time recovery enabled).

Target Resources:
- Amazon DynamoDB tables
- All DynamoDB table types (provisioned and on-demand)

Remediation Actions:
1. Extracts table name from DynamoDB table ARN
2. Checks for exemption tag using pagination
3. Enables point-in-time recovery if not exempted
4. Configures automatic backup capability

Tag-Based Exemption:
- Checks for DYNAMODB_NO_PIT_RECOVERY_TAG environment variable
- If tag is present, suppresses auto-remediation
- Uses pagination to handle tables with many tags

Validation Commands:
# Check point-in-time recovery status
aws dynamodb describe-continuous-backups --table-name <table-name>

# Verify point-in-time recovery is enabled
aws dynamodb describe-continuous-backups --table-name <table-name> --query 'ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus'

# List table tags
aws dynamodb list-tags-of-resource --resource-arn <table-arn>

Security Impact:
- Enables automatic point-in-time recovery for data protection
- Provides 35-day backup retention for accidental data loss
- Supports compliance requirements for data retention
- Critical for disaster recovery and business continuity

Data Protection Benefits:
- Continuous backups with second-level granularity
- No performance impact on table operations
- Automatic backup management and retention
- Supports table restoration to any point in time within 35 days

Error Handling:
- Missing table: Suppresses finding (table may have been deleted)
- Tag exemption: Suppresses auto-remediation based on tag
- API errors: Re-raises for investigation

Table ARN Format:
- Input: arn:aws:dynamodb:region:account:table/table-name
- Extracted: table-name (everything after the last slash)

Environment Variables:
- DYNAMODB_NO_PIT_RECOVERY_TAG: Tag key for exempting tables from auto-remediation
"""

import os
import botocore
import boto3
from aws_utils.clients import get_client

# Get the DYNAMODB_NO_PIT_RECOVERY_TAG environment variable
DYNAMODB_NO_PIT_RECOVERY_TAG = os.environ['DYNAMODB_NO_PIT_RECOVERY_TAG']

# Lambda handler function
def lambda_handler(data, _context):
    # Print the input data
    print(data)

    # Extract the finding from the input data
    finding = data['finding']

    # Extract relevant information from the finding
    account_id = finding['AwsAccountId']
    region = finding['Resources'][0]['Region']
    table_arn = finding['Resources'][0]['Id']
    table_name = table_arn.rsplit('/', 1)[1]

    # Get a client for DynamoDB in the specified account and region
    client = get_client('dynamodb', account_id, region)

    # Print a message indicating that tags are being fetched for the table
    print("Fetching tags for {table_arn}...")

    # Use a paginator to retrieve all tags for the table
    paginator = client.get_paginator('list_tags_of_resource')
    page_iterator = paginator.paginate(ResourceArn=table_arn)
    for page in page_iterator:
        for tags in page['Tags']:
            if tags['Key'] == DYNAMODB_NO_PIT_RECOVERY_TAG:
                # If the DYNAMODB_NO_PIT_RECOVERY_TAG is present, suppress the auto-remediation
                data['messages']['actions_taken'] = f"The tag {DYNAMODB_NO_PIT_RECOVERY_TAG} is present, suppressing the auto-remediation."
                data['actions']['suppress_finding'] = True
                print(data['messages']['actions_taken'])
                return data

    # If the DYNAMODB_NO_PIT_RECOVERY_TAG is not present, enable point-in-time recovery for the table
    print(f"Enabling PIT recovery for {table_name} in account {account_id}, region {region}...")

    try:
        # Call the update_continuous_backups API to enable point-in-time recovery
        response = client.update_continuous_backups(
            TableName=table_name,
            PointInTimeRecoverySpecification={
                'PointInTimeRecoveryEnabled': True
            }
        )
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] in ['TableNotFoundException']:
            # If the DynamoDB table is not found, suppress the finding
            data['messages']['actions_taken'] = f"The DynamoDB table wasn't found. Suppressing the finding."
            data['actions']['suppress_finding'] = True
            print(data['messages']['actions_taken'])
            return data
        else:
            # Unexpected errors bubble up to state machine for ticketing fallback (v2.2.1+)
            print(f"Unexpected error: {error}. State machine will handle fallback to ticketing.")
            raise

    # Print the response from the update_continuous_backups API
    print(response)

    # Update the actions_taken message in the input data
    data['messages']['actions_taken'] = "Point-in-time recovery has been enabled."
    return data

