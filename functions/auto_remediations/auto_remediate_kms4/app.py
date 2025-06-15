"""
KMS.4 AUTOREMEDIATION - ENABLE KMS KEY ROTATION

This Lambda function automatically remediates AWS Security Hub findings for KMS.4
(KMS keys should have automatic rotation enabled).

Target Resources:
- AWS KMS customer-managed keys
- Applies only to customer-managed keys (AWS managed keys automatically rotate)

Remediation Actions:
1. Extracts key ID from KMS key ARN
2. Enables automatic yearly key rotation for the specific key
3. Configures yearly rotation schedule

Validation Commands:
# Check key rotation status
aws kms get-key-rotation-status --key-id <key-id>

# Verify key rotation is enabled
aws kms describe-key --key-id <key-id> --query 'KeyMetadata.KeyRotationStatus'

# List key rotation history
aws kms list-key-rotations --key-id <key-id>

Security Impact:
- Enables automatic yearly rotation of encryption keys
- Reduces risk of key compromise through regular rotation
- Maintains compliance with security best practices
- Critical for long-term data protection and regulatory compliance

Compliance Benefits:
- Meets NIST, SOC, and other regulatory requirements
- Supports PCI DSS key rotation standards
- Ensures cryptographic key lifecycle management
- Reduces manual key management overhead

Error Handling Categories:
1. **Suppressible Errors** (suppress finding):
   - AccessDeniedException: Insufficient permissions
   - KMSInvalidStateException: Key not in valid state (e.g., disabled, deleted)
   - NotFoundException: Key doesn't exist
   - Unexpected exceptions: Unknown errors

2. **Actionable Errors** (create ticket):
   - Other API errors: Require manual investigation

Key ARN Format:
- Input: arn:aws:kms:region:account:key/key-id
- Extracted: key-id (everything after the last slash)

Note: Only customer-managed keys support rotation. AWS managed keys automatically rotate yearly.
"""

import os
import boto3
from botocore.exceptions import ClientError
from aws_utils.clients import get_client


def lambda_handler(data, _context):
    print(data)

    finding = data['finding']

    account_id = finding['AwsAccountId']
    region = finding['Resources'][0]['Region']
    key_arn = finding['Resources'][0]['Id']
    key_id = key_arn.rsplit('/', 1)[1]

    client = get_client('kms', account_id, region)

    try:
        client.enable_key_rotation(KeyId=key_id)
    except ClientError as error:
        error_code = error.response['Error']['Code']
        error_message = error.response['Error']['Message']
        print(f"Error enabling key rotation: {error_code} - {error_message}")
        
        if error_code in ['AccessDeniedException', 'KMSInvalidStateException', 'NotFoundException']:
            data['messages']['actions_taken'] = f"Couldn't enable key rotation: {error_code}. This finding has been suppressed."
            data['actions']['suppress_finding'] = True
        else:
            data['messages']['actions_taken'] = f"Failed to enable key rotation: {error_code}"
            data['actions']['autoremediation_not_done'] = True
        return data
    except Exception as exc:
        print(f"Unexpected exception: {exc}, suppressing.")
        data['messages']['actions_taken'] = "Couldn't enable key rotation due to an unexpected error. This finding has been suppressed."
        data['actions']['suppress_finding'] = True
        return data

    data['messages']['actions_taken'] = "Automatic yearly key rotation has been enabled."
    return data
