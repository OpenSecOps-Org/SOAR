"""
AWS Health Reclassifier

Reclassifies AWS Health informational notifications from HIGH/MEDIUM/LOW/CRITICAL 
to INFORMATIONAL severity to prevent false positives in SOAR processing.

This function implements the established SOAR pattern:
1. Update Security Hub finding severity via API
2. Set actions.reconsider_later flag to route to "Do Nothing" 
3. Let the new event trigger fresh processing with correct severity

Uses pattern-based detection of AWS Health notification types rather than 
maintaining service-specific lists.
"""

import os
import json
import botocore
from aws_utils.clients import get_client

PRODUCT_NAME = os.environ['PRODUCT_NAME']
RECLASSIFY_ENABLED = os.environ.get('RECLASSIFY_AWS_HEALTH_INCIDENTS', 'No')


def lambda_handler(data, context):
    """
    Main handler for AWS Health reclassifier.
    
    Args:
        data: SOAR scratchpad containing finding, account, actions, etc.
        context: Lambda context
        
    Returns:
        dict: Modified scratchpad with actions.reconsider_later flag if reclassified
    """
    finding = data.get('finding', {})
    current_severity = finding.get('Severity', {}).get('Label', 'unknown')
    
    print(f"AWS Health Reclassifier starting - Enabled: {RECLASSIFY_ENABLED}, Current severity: {current_severity}")
    
    # Check if reclassification is enabled
    if RECLASSIFY_ENABLED != 'Yes':
        print(f"DECISION: AWS Health reclassification is disabled - no action taken")
        return data
    
    # Check if this is an AWS Health informational notification
    reclassify_decision = should_reclassify_finding(finding)
    
    if reclassify_decision['should_reclassify']:
        print(f"DECISION: Reclassifying to INFORMATIONAL - {reclassify_decision['reason']}")
        
        try:
            # Update Security Hub with corrected severity
            update_security_hub_severity(finding)
            
            # Signal state machine to reconsider later (uses existing SOAR pattern)
            data['actions']['reconsider_later'] = True
            print(f"SUCCESS: Security Hub updated, setting actions.reconsider_later = True")
            
        except Exception as e:
            print(f"ERROR: Failed to update Security Hub: {e}")
            print(f"DECISION: Continuing with original severity due to error")
            # Continue processing with original severity on error (no flag set)
    else:
        print(f"DECISION: No reclassification needed - {reclassify_decision['reason']}")
        # No flag set - continue normal processing
    
    return data


def should_reclassify_finding(finding):
    """
    Determine if finding should be reclassified from current severity to INFORMATIONAL.
    
    Uses pattern-based detection for AWS Health notification types rather than 
    maintaining service-specific lists.
    
    Args:
        finding (dict): Security Hub finding
        
    Returns:
        dict: {'should_reclassify': bool, 'reason': str}
    """
    finding_id = finding.get('Id', 'unknown')
    
    # Check current severity - only reclassify non-INFORMATIONAL findings
    current_severity = finding.get('Severity', {}).get('Label', '')
    if current_severity == 'INFORMATIONAL':
        return {
            'should_reclassify': False,
            'reason': f'Finding already has INFORMATIONAL severity'
        }
    
    # Check if this is an AWS Health notification
    aws_health_check = is_aws_health_notification(finding)
    if not aws_health_check['is_aws_health']:
        return {
            'should_reclassify': False,
            'reason': aws_health_check['reason']
        }
    
    # Pattern-based notification type classification
    generator_id = finding.get('GeneratorId', '')
    
    # OPERATIONAL_NOTIFICATION: Always informational (service improvements, policy changes)
    if '_OPERATIONAL_NOTIFICATION' in generator_id:
        return {
            'should_reclassify': True,
            'reason': f'AWS Health operational notification detected: {generator_id}'
        }
    
    # SECURITY_NOTIFICATION: Most are actually service announcements, not security incidents
    if '_SECURITY_NOTIFICATION' in generator_id:
        return {
            'should_reclassify': True,
            'reason': f'AWS Health security notification (typically informational): {generator_id}'
        }
    
    # Other notification types - conservative approach (keep original severity)
    if '_NOTIFICATION' in generator_id:
        return {
            'should_reclassify': False,
            'reason': f'Unknown AWS Health notification type, keeping original severity: {generator_id}'
        }
    
    # Not a notification pattern
    return {
        'should_reclassify': False,
        'reason': f'AWS Health finding but not a notification pattern: {generator_id}'
    }


def is_aws_health_notification(finding):
    """
    Check if finding is from AWS Health service.
    
    Args:
        finding (dict): Security Hub finding
        
    Returns:
        dict: {'is_aws_health': bool, 'reason': str}
    """
    product_arn = finding.get('ProductArn', '')
    product_name = finding.get('ProductName', '')
    company_name = finding.get('CompanyName', '')
    generator_id = finding.get('GeneratorId', '')
    types = finding.get('Types', [])
    
    # AWS Health pattern matching
    if not (product_arn.startswith('arn:aws:securityhub:') and 
            product_arn.endswith('::product/aws/health')):
        return {
            'is_aws_health': False,
            'reason': f'Not AWS Health ProductArn: {product_arn}'
        }
    
    if product_name != 'Health':
        return {
            'is_aws_health': False,
            'reason': f'ProductName is not Health: {product_name}'
        }
    
    if company_name != 'AWS':
        return {
            'is_aws_health': False,
            'reason': f'CompanyName is not AWS: {company_name}'
        }
    
    if types != ['Software and Configuration Checks']:
        return {
            'is_aws_health': False,
            'reason': f'Types do not match AWS Health pattern: {types}'
        }
    
    return {
        'is_aws_health': True,
        'reason': f'AWS Health notification confirmed: {generator_id}'
    }


def update_security_hub_severity(finding):
    """
    Update Security Hub finding severity to INFORMATIONAL.
    
    Args:
        finding (dict): Security Hub finding to update
        
    Raises:
        Exception: If Security Hub update fails
    """
    finding_id = finding['Id']
    product_arn = finding['ProductArn']
    account_id = finding['AwsAccountId']
    current_severity = finding.get('Severity', {}).get('Label', 'UNKNOWN')
    
    print(f"Updating Security Hub: {current_severity} → INFORMATIONAL")
    
    # Get cross-account Security Hub client
    client = get_client('securityhub', account_id)
    
    try:
        response = client.batch_update_findings(
            FindingIdentifiers=[
                {
                    'Id': finding_id,
                    'ProductArn': product_arn
                }
            ],
            Severity={
                'Label': 'INFORMATIONAL',
                'Normalized': 1  # INFORMATIONAL severity level
            },
            Note={
                'Text': f'Severity reclassified from {current_severity} to INFORMATIONAL by {PRODUCT_NAME} AWS Health Reclassifier',
                'UpdatedBy': f'{PRODUCT_NAME}'
            }
        )
        
        print(f"Security Hub API response: {response}")
        
        if response.get('UnprocessedFindings'):
            raise Exception(f"Unprocessed findings: {response['UnprocessedFindings']}")
            
        print(f"Successfully updated severity to INFORMATIONAL")
        
    except botocore.exceptions.ClientError as e:
        if 'TooManyRequestsException' in str(e):
            raise Exception('TooManyRequestsException - Security Hub throttling')
        else:
            raise Exception(f'Security Hub API error: {e}')