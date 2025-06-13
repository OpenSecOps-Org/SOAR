"""
AWS Security Hub Auto-Remediation: EC2.2 - VPC Default Security Group Rules

This control checks that the default security group of a VPC does not allow inbound 
or outbound traffic. AWS default security groups come with an inbound rule that allows 
all traffic from the security group itself, and an outbound rule that allows all 
traffic to all destinations (0.0.0.0/0).

Test triggers:
- Default security group with default rules: aws ec2 describe-security-groups --group-names default
- Check instances using default SG: aws ec2 describe-instances --filters "Name=instance.group-name,Values=default"

The auto-remediation removes default rules from unused default security groups.
If the security group is in use by instances or has been modified from its pristine 
state, remediation is skipped and a ticket is created for manual resolution.

Target Resources: AWS EC2 Default Security Groups
Remediation: Remove ingress and egress rules from pristine, unused default security groups
"""

import os
import botocore
import boto3
from aws_utils.clients import get_client


def lambda_handler(data, _context):
    """
    Main Lambda handler for EC2.2 auto-remediation.
    
    Args:
        data: Security Hub finding data containing security group details
        _context: Lambda context (unused)
        
    Returns:
        dict: Updated finding data with remediation results
        
    Remediation Logic:
        1. Extract security group details from finding or fetch via API
        2. Check if security group is in use by EC2 instances
        3. Check if security group rules have been modified from pristine state
        4. If unused and pristine, remove default ingress and egress rules
        5. If in use or modified, skip remediation and create ticket
    """
    print(data)

    # Extract necessary information from the Security Hub finding
    finding = data['finding']
    account_id = finding['AwsAccountId']
    region = finding['Resources'][0]['Region']
    resource = finding['Resources'][0]
    details = resource.get('Details', False)

    # Get cross-account EC2 client for the target account and region
    client = get_client('ec2', account_id, region)

    # Extract security group details from finding or fetch via API if missing
    if details:
        # Security group details are available in the finding
        sg_id = details['AwsEc2SecurityGroup']['GroupId']
        owner_id = details['AwsEc2SecurityGroup']['OwnerId']
        ingress_perms = details['AwsEc2SecurityGroup'].get('IpPermissions', [])
        egress_perms = details['AwsEc2SecurityGroup'].get('IpPermissionsEgress', [])
    else:
        # Security group details missing from finding - extract ID from ARN and fetch details
        sg_id = resource['Id'].rsplit('/', 1)[1]  # Extract SG ID from ARN
        owner_id, ingress_perms, egress_perms = get_details(sg_id, client)
        if not owner_id and not ingress_perms and not egress_perms:
            # Security group not found - suppress the finding
            data['actions']['suppress_finding'] = True
            return data

    # SAFETY CHECK: Ensure security group is not in use by any EC2 instances
    # This prevents breaking active infrastructure by removing rules from SGs in use
    if security_group_in_use(client, sg_id):
        print("The SG is in use, create ticket to team to fix.")
        data['actions']['autoremediation_not_done'] = True
        data['messages']['actions_taken'] = "None, as the security group is in use."
        data['messages']['actions_required'] = "Please update your infrastructure not to use the VPC default security group: create a new one with more restrictive routing rules, then remove the ingress and egress rules of the VPC default security group."
        return data

    # PRISTINE STATE CHECK: Ensure security group rules haven't been customized
    # Only remove rules if the SG is in its default AWS state to avoid breaking custom configurations
    if ingress_modified(ingress_perms, sg_id, owner_id) or egress_modified(egress_perms):
        print("The SG has been modified, create ticket to team to fix.")
        data['actions']['autoremediation_not_done'] = True
        data['messages']['actions_taken'] = "None, as the security group no longer is in its pristine state."
        data['messages']['actions_required'] = "Please update your infrastructure not to use the VPC default security group: create a new one with more restrictive routing rules, then remove the ingress and egress rules of the VPC default security group."
        return data

    # REMEDIATION: Remove default rules from unused, pristine default security group
    data['messages']['actions_taken'] = ''

    # Remove ingress rules (default: allow all traffic from self-reference)
    # Only processes first rule as pristine default SGs have exactly one ingress rule
    if ingress_perms and revoke_ingress(ingress_perms[0], client, sg_id):
        data['messages']['actions_taken'] += "All ingress rules have been removed. "

    # Remove egress rules (default: allow all traffic to 0.0.0.0/0)
    # Only processes first rule as pristine default SGs have exactly one egress rule
    if egress_perms and revoke_egress(egress_perms[0], client, sg_id):
        data['messages']['actions_taken'] += "All egress rules have been removed. "

    # Check if any remediation actions were successful
    if data['messages']['actions_taken'] != '':
        data['messages']['actions_required'] = "None."
        return data

    # No rules could be removed - create ticket for manual investigation
    print("The SG rules can't be revoked, create ticket to team to fix.")
    data['actions']['autoremediation_not_done'] = True
    data['messages']['actions_taken'] = "None. The ingress and egress rules could not be revoked."
    data['messages']['actions_required'] = "Please update your infrastructure not to use the VPC default security group: create a new one with more restrictive routing rules, then remove the ingress and egress rules of the VPC default security group."
    return data

def security_group_in_use(client, sg_id):
    """
    Check if a security group is currently attached to any EC2 instances.
    
    This safety check prevents auto-remediation from removing rules from security 
    groups that are actively protecting running infrastructure.
    
    Args:
        client: EC2 client for the target account/region
        sg_id: Security group ID to check
        
    Returns:
        bool: True if security group is attached to any instances, False otherwise
    """
    response = client.describe_instances()
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            for security_group in instance['SecurityGroups']:
                if sg_id == security_group['GroupId']:
                    return True
    return False


def ingress_modified(perms, sg_id, owner_id):
    """
    Check if ingress rules have been modified from the AWS default state.
    
    AWS default security groups come with one ingress rule that allows all traffic
    from the security group itself (self-reference). This function verifies the
    rules match this exact pristine state.
    
    Pristine ingress rule:
    - Exactly 1 rule
    - Protocol: '-1' (all protocols)  
    - Source: Single UserIdGroupPair referencing the same security group
    
    Args:
        perms: List of ingress permission dictionaries
        sg_id: Security group ID for self-reference validation
        owner_id: AWS account ID that owns the security group
        
    Returns:
        bool: False if rules are pristine, True if modified
    """
    if len(perms) == 0:
        return False  # No rules = pristine (already cleaned)
    if len(perms) != 1:
        return True   # Multiple rules = modified
    if perms[0].get('IpProtocol', False) != '-1':
        return True   # Wrong protocol = modified
    
    user_id_group_pairs = perms[0].get('UserIdGroupPairs', [])
    if len(user_id_group_pairs) != 1:
        return True   # Wrong number of group pairs = modified
    if user_id_group_pairs[0].get('GroupId', False) != sg_id:
        return True   # Wrong group reference = modified
    if user_id_group_pairs[0].get('UserId', False) != owner_id:
        return True   # Wrong account ID = modified
    
    return False      # All checks passed = pristine


def egress_modified(perms):
    """
    Check if egress rules have been modified from the AWS default state.
    
    AWS default security groups come with one egress rule that allows all traffic
    to all destinations (0.0.0.0/0). This function verifies the rules match this
    exact pristine state.
    
    Pristine egress rule:
    - Exactly 1 rule
    - Protocol: '-1' (all protocols)
    - Destination: Single IP range '0.0.0.0/0'
    
    Args:
        perms: List of egress permission dictionaries
        
    Returns:
        bool: False if rules are pristine, True if modified
    """
    if len(perms) == 0:
        return False  # No rules = pristine (already cleaned)
    if len(perms) != 1:
        return True   # Multiple rules = modified
    if perms[0].get('IpProtocol', False) != '-1':
        return True   # Wrong protocol = modified
    
    ip_ranges = perms[0].get('IpRanges', False)
    if not ip_ranges:
        return True   # No IP ranges = modified
    if len(ip_ranges) != 1:
        return True   # Multiple IP ranges = modified
    if ip_ranges[0].get('CidrIp', False) != '0.0.0.0/0':
        return True   # Wrong CIDR = modified
    
    return False      # All checks passed = pristine

def revoke_ingress(perm, client, sg_id):
    """
    Remove an ingress rule from a security group.
    
    Args:
        perm: Permission dictionary to revoke
        client: EC2 client for the target account/region
        sg_id: Security group ID to modify
        
    Returns:
        bool: True if rule was successfully removed, False otherwise
        
    Error Handling:
        - InvalidPermission.NotFound: Rule doesn't exist (returns False)
        - InvalidGroup.NotFound: Security group doesn't exist (returns False)
        - Other errors: Re-raised for caller to handle
    """
    print("Revoking: ", perm)

    try:
        response = client.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[perm]
        )
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] in ['InvalidPermission.NotFound', 'InvalidGroup.NotFound']:
            print("Not found, ignoring")
            return False
        else:
            raise error

    print(response)

    # AWS returns 'Return': False on failure, True on success
    if response['Return'] == False:
        return False
    return True


def revoke_egress(perm, client, sg_id):
    """
    Remove an egress rule from a security group.
    
    Args:
        perm: Permission dictionary to revoke
        client: EC2 client for the target account/region
        sg_id: Security group ID to modify
        
    Returns:
        bool: True if rule was successfully removed, False otherwise
        
    Error Handling:
        - InvalidPermission.NotFound: Rule doesn't exist (returns False)
        - InvalidGroup.NotFound: Security group doesn't exist (returns False)
        - Other errors: Re-raised for caller to handle
    """
    print("Revoking: ", perm)

    try:
        response = client.revoke_security_group_egress(
            GroupId=sg_id,
            IpPermissions=[perm]
        )
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] in ['InvalidPermission.NotFound', 'InvalidGroup.NotFound']:
            print("Not found, ignoring")
            return False
        else:
            raise error

    print(response)

    # AWS returns 'Return': False on failure, True on success
    if response['Return'] == False:
        return False
    return True


def get_details(sg_id, client):
    """
    Fetch security group details from AWS API when not available in finding.
    
    This fallback function is used when Security Hub findings don't include
    complete security group rule details.
    
    Args:
        sg_id: Security group ID to look up
        client: EC2 client for the target account/region
        
    Returns:
        tuple: (owner_id, ingress_perms, egress_perms) or (False, False, False) if not found
        
    Error Handling:
        - InvalidGroup.NotFound: Security group doesn't exist
        - Other errors: Re-raised for caller to handle
    """
    try:
        response = client.describe_security_groups(GroupIds=[sg_id])
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] in ['InvalidGroup.NotFound']:
            print("Not found, ignoring")
            return False, False, False
        else:
            raise error

    sg = response['SecurityGroups'][0]
    owner_id = sg['OwnerId']
    ingress_perms = sg['IpPermissions']
    egress_perms = sg['IpPermissionsEgress']

    return owner_id, ingress_perms, egress_perms