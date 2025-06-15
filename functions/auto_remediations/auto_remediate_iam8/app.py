"""
IAM.8 AUTOREMEDIATION - REMOVE UNUSED IAM USER CREDENTIALS

This Lambda function automatically remediates AWS Security Hub findings for IAM.8 
(Unused IAM user credentials should be removed).

Target Resources:
- IAM users with unused or inactive credentials

Remediation Actions:
1. Delete IAM user login password (console access)
2. List and delete all active access keys (programmatic access)
3. Preserve the IAM user account for potential reactivation

Security Impact:
- CRITICAL: Removes all authentication mechanisms for IAM users
- Cross-account credential modification across entire AWS organization
- Immediate loss of access for affected users

Error Handling:
- NoSuchEntityException: Gracefully handles missing login profiles
- WARNING: No error handling for access key operations or other failures

Test Triggers:
1. Create IAM user with login password: aws iam create-login-profile --user-name test-user
2. Create IAM user with access keys: aws iam create-access-key --user-name test-user
3. Verify the finding appears in Security Hub for IAM.8
4. Check user credentials: aws iam get-login-profile --user-name test-user

Security Hub Control:
- https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-8
"""

import os
import boto3
from aws_utils.clients import get_client


def lambda_handler(data, _context):
    print(data)

    finding = data['finding']

    account_id = finding['AwsAccountId']
    region = finding['Resources'][0]['Region']
    user_name = finding['Resources'][0]['Details']['AwsIamUser']['UserName']

    client = get_client('iam', account_id, region)

    # Delete password
    try:
        client.delete_login_profile(UserName=user_name)
    except client.exceptions.NoSuchEntityException:
        pass

    # Delete access keys
    response = client.list_access_keys(UserName=user_name)
    for access_key in response['AccessKeyMetadata']:
        if access_key['Status'] == 'Active':
            client.delete_access_key(
                UserName=user_name,
                AccessKeyId=access_key['AccessKeyId']
            )

    data['messages']['actions_taken'] = "The IAM User remains, but password and access keys have been deleted."
    data['messages']['actions_required'] = "Delete the user or contact an administrator to reactivate access."
    return data


