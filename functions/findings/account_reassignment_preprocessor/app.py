import os
import boto3
from datetime import datetime, timezone
from aws_utils.clients import get_client

SECURITY_ADM_ACCOUNT = os.environ.get('SECURITY_ADM_ACCOUNT', '111111111111')


def lambda_handler(data, context):
    """
    Account Reassignment Preprocessor - Phase 1 Decision Logic Implementation.
    
    This function implements account reassignment detection logic for findings
    that need to be moved from Security-Adm to the actual resource owner account.
    
    Uses the established SOAR pattern: sets actions.suppress_finding = True
    when account reassignment is needed, allowing the state machine Choice node
    to route to the existing "Suppress Finding" functionality.
    """
    # Debug logging: Always log the complete input data for troubleshooting
    print(f"PREPROCESSOR INPUT DATA: {data}")
    # Critical error check: No finding data
    if not data.get('finding'):
        print("ERROR: No finding data in preprocessor input - returning data unchanged")
        return data
    
    finding = data['finding']
    finding_account = finding.get('AwsAccountId')
    
    # Optimization: Skip processing if finding is not in security-adm account
    if finding_account != SECURITY_ADM_ACCOUNT:
        return data
    
    # Check if account reassignment is needed
    target_account = must_recreate_in_other_account(data)
    
    if target_account:
        print(f"Account reassignment needed: {finding_account} -> {target_account}")
        
        # Attempt to recreate finding in target account
        recreation_success = recreate_asff_finding(target_account, data)
        
        if recreation_success:
            # Only set suppress_finding flag if recreation succeeded
            data['actions']['suppress_finding'] = True
            print(f"Finding successfully recreated in account {target_account}")
            print(f"Setting actions.suppress_finding = True to trigger suppression workflow")
        else:
            print(f"Failed to recreate finding in account {target_account}")
            print(f"Continuing with original finding (no suppression)")
            # data is returned unchanged - original finding continues in workflow
    
    return data


def must_recreate_in_other_account(data):
    """
    Determine if finding requires account reassignment correction.
    
    Returns:
        False: No correction needed
        str: Target account ID if correction is needed
    """
    finding = data['finding']
    finding_account = finding.get('AwsAccountId')
    finding_id = finding.get('Id', 'unknown')
    
    # Early return if essential fields are missing
    if not finding_account:
        print(f"  Decision: NO CORRECTION - Missing AwsAccountId field")
        return False
    
    print(f"Account reassignment check for finding {finding_id}")
    print(f"  Finding account: {finding_account}")
    
    # Priority 1: Check for ResourceOwnerAccount field
    resource_owner_account = finding.get('ProductFields', {}).get('ResourceOwnerAccount')
    if resource_owner_account:
        print(f"  ResourceOwnerAccount found: {resource_owner_account}")
        if resource_owner_account != finding_account:
            print(f"  Decision: CORRECTION NEEDED - ResourceOwnerAccount {resource_owner_account} != finding account {finding_account}")
            return resource_owner_account
        else:
            print(f"  Decision: NO CORRECTION - ResourceOwnerAccount matches finding account")
            return False
    
    # Priority 2: Parse account from resource ARN
    resources = finding.get('Resources', [])
    if resources:
        resource_id = resources[0].get('Id', '')
        print(f"  Resource ID: {resource_id}")
        if resource_id.startswith('arn:aws:'):
            # Parse ARN: arn:aws:service:region:account:resource
            parts = resource_id.split(':')
            if len(parts) >= 5:
                arn_account = parts[4]
                print(f"  ARN account extracted: {arn_account}")
                if arn_account and arn_account != finding_account:
                    print(f"  Decision: CORRECTION NEEDED - ARN account {arn_account} != finding account {finding_account}")
                    return arn_account
                else:
                    print(f"  Decision: NO CORRECTION - ARN account matches finding account")
                    return False
            else:
                print(f"  ARN parsing failed: insufficient parts ({len(parts)})")
        else:
            print(f"  Resource ID is not an ARN")
    else:
        print(f"  No resources found in finding")
    
    print(f"  Decision: NO CORRECTION - No account extraction method successful")
    return False


def recreate_asff_finding(account_id, data):
    """
    Create new ASFF finding in target account using BatchImportFindings.
    
    Args:
        account_id (str): Target account ID where finding should be created
        data (dict): SOAR data containing the finding to be recreated
        
    Returns:
        bool: True if finding was successfully created, False otherwise
    """
    try:
        # Get the original finding from SOAR data
        original_finding = data['finding']
        
        # Get region from original finding for ProductArn construction
        region = original_finding.get('Region')
        if not region:
            print(f"ERROR: Region not found in original finding")
            return False
        
        # Create properly structured ASFF finding for BatchImportFindings
        current_time = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        
        # Build corrected finding with only required/allowed fields
        corrected_finding = {
            # Required fields
            'SchemaVersion': original_finding.get('SchemaVersion', '2018-10-08'),
            'Id': f"{original_finding['Id']}-reassigned-{account_id}",  # Make unique for target account
            # ProductArn: Use generic default product for cross-account finding creation
            # - Original ProductArn (e.g., arn:aws:securityhub:region::product/aws/access-analyzer) 
            #   caused AccessDeniedException due to service-specific product restrictions
            # - Generic default product works across all accounts without special permissions
            # - Same approach used by SOAR-all-alarms-to-sec-hub for creating new findings
            # - Must use same region as original finding for ProductArn construction
            # - Format: arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default
            'ProductArn': f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default",
            'GeneratorId': original_finding['GeneratorId'],
            'AwsAccountId': account_id,  # This is the key change
            'Types': original_finding['Types'],
            'CreatedAt': current_time,  # Required for BatchImportFindings
            'UpdatedAt': current_time,  # Required for BatchImportFindings
            'Severity': original_finding['Severity'],
            'Title': original_finding['Title'],
            'Description': original_finding['Description'],
            'Resources': original_finding['Resources'],
            
            # Optional but important fields
            'Compliance': original_finding.get('Compliance', {}),
            'RecordState': 'ACTIVE',  # Set to active for new finding
            'WorkflowState': 'NEW',   # Set to new for fresh processing
        }
        
        # Add optional fields if they exist
        if 'Remediation' in original_finding:
            corrected_finding['Remediation'] = original_finding['Remediation']
        if 'SourceUrl' in original_finding:
            corrected_finding['SourceUrl'] = original_finding['SourceUrl']
        if 'ProductFields' in original_finding:
            corrected_finding['ProductFields'] = original_finding['ProductFields']
        
        # Get cross-account Security Hub client
        client = get_client('securityhub', account_id)
        
        # Create new finding in target account
        response = client.batch_import_findings(Findings=[corrected_finding])
        
        # Check if creation was successful
        if response['FailedCount'] > 0:
            print(f"BatchImportFindings failed: {response.get('FailedFindings', [])}")
            return False
            
        print(f"Successfully created finding in account {account_id}")
        return True
        
    except Exception as e:
        print(f"Error recreating finding in account {account_id}: {e}")
        return False
