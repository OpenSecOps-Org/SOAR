"""
AWS Security Hub Auto-Remediation: EC2.13 - Security Groups SSH Access Restriction

This control checks that security groups do not allow unrestricted access to port 22 (SSH).
Security groups should only allow restricted inbound traffic on SSH port 22.

Test triggers:
- Security group with SSH access from 0.0.0.0/0: aws ec2 describe-security-groups --group-ids sg-12345 
- Add unrestricted SSH rule: aws ec2 authorize-security-group-ingress --group-id sg-12345 --protocol tcp --port 22 --cidr 0.0.0.0/0

The auto-remediation removes or modifies ingress rules that allow SSH access from 0.0.0.0/0 or ::/0.
Rules with other allowed sources are preserved to maintain legitimate access patterns.

Target Resources: AWS EC2 Security Groups with SSH access from anywhere
Remediation: Remove 0.0.0.0/0 and ::/0 sources from SSH rules, preserving other sources
"""

import os
import botocore
import boto3
from aws_utils.clients import get_client

# SSH port number for security rule evaluation
PORT = 22


def lambda_handler(data, _context):
    """
    Main Lambda handler for EC2.13 auto-remediation.
    
    Args:
        data: Security Hub finding data containing security group details
        _context: Lambda context (unused)
        
    Returns:
        dict: Updated finding data with remediation results
        
    Remediation Logic:
        1. Extract security group details from Security Hub finding
        2. Iterate through all ingress rules to find SSH-related permissions
        3. For each SSH rule, remove unrestricted access (0.0.0.0/0, ::/0)
        4. Preserve specific IP ranges and other allowed sources
        5. Update security group with modified rules
    """
    print(data)

    # Extract Security Hub finding information
    finding = data['finding']
    details = finding['Resources'][0].get('Details', False)

    # Validate that security group details are available in the finding
    if not details:
        print("No SG details in finding. Suppressing.")
        data['actions']['suppress_finding'] = True
        return data

    # Extract security group information and permissions
    sg_id = details['AwsEc2SecurityGroup']['GroupId']
    perms = details['AwsEc2SecurityGroup']['IpPermissions']
    account_id = finding['AwsAccountId']
    region = finding['Resources'][0]['Region']

    # Get cross-account EC2 client for the target account and region
    client = get_client('ec2', account_id, region)

    # Track whether any remediation actions were performed
    did_something = False

    # Process each ingress rule to identify and fix SSH access violations
    for perm in perms:
        print("Existing IpPermissions: ", perm)

        # Analyze permission and generate improved version without unrestricted access
        better_perm = improve_perm(perm)
        print("Improved IpPermissions: ", better_perm)

        # Handle different improvement outcomes:
        if better_perm is True:
            # No valid sources remain - remove the entire rule
            if revoke(perm, client, sg_id):
                did_something = True

        elif better_perm:
            # Rule can be improved - replace with restricted version
            # Use atomic operation: revoke old rule, then authorize new rule
            if revoke(perm, client, sg_id):
                if authorize(better_perm, client, sg_id):
                    did_something = True
                else:
                    # Rollback: restore original rule if new rule authorization failed
                    authorize(perm, client, sg_id)
        
        else:
            # Rule is already secure (no unrestricted SSH access)
            did_something = True

    # Set remediation status based on whether any actions were taken
    if not did_something:
        data['actions']['autoremediation_not_done'] = True
        return data

    data['messages']['actions_taken'] = "The ingress rule has been modified or deleted."
    return data


def improve_perm(perm):
    """
    Analyze a security group permission and remove unrestricted SSH access.
    
    This function identifies rules that allow SSH access from anywhere (0.0.0.0/0 or ::/0)
    and creates improved versions that preserve legitimate access while removing
    unrestricted access patterns.
    
    Args:
        perm: Security group permission dictionary containing protocol, ports, and sources
        
    Returns:
        - False: Permission doesn't affect SSH or is already secure
        - True: Permission should be completely removed (only unrestricted sources)
        - dict: Modified permission with unrestricted sources removed
        
    SSH Rule Identification:
        - Protocol is '-1' (all protocols) OR
        - Protocol is 'tcp' AND port range includes port 22
    """
    # Work with a copy to avoid modifying the original permission
    perm = perm.copy()
    proto = perm['IpProtocol']

    # Check if this rule affects SSH traffic (port 22)
    # Skip rules that don't involve SSH
    if proto != "-1" and (proto != "tcp" or perm.get('FromPort', 0) > PORT or perm.get('ToPort', 99999) < PORT):
        return False  # Rule doesn't affect SSH

    # Extract IP ranges for analysis
    ip_ranges = perm.get('IpRanges', False)
    if not ip_ranges:
        return False  # No IP sources to evaluate

    # Special case: If rule only allows access from 0.0.0.0/0, remove entirely
    if len(ip_ranges) == 1 and ip_ranges[0]['CidrIp'] == "0.0.0.0/0":
        return True  # Signal complete removal

    # Filter out unrestricted access patterns while preserving specific sources
    modified = False
    new_ip_ranges = []
    new_ipv6_ranges = []
    
    # Process IPv4 ranges - remove 0.0.0.0/0, keep specific CIDR blocks
    for ip_range in ip_ranges:
        if ip_range.get('CidrIp', False) != '0.0.0.0/0':
            new_ip_ranges.append(ip_range)
        else:
            modified = True  # Found unrestricted IPv4 access

    # Process IPv6 ranges - remove ::/0, keep specific IPv6 blocks
    for ipv6_range in perm.get('Ipv6Ranges', []):
        if ipv6_range.get('CidrIpv6', False) != '::/0':
            new_ipv6_ranges.append(ipv6_range)
        else:
            modified = True  # Found unrestricted IPv6 access

    # Return improved permission if unrestricted access was found and removed
    if modified:
        if not new_ip_ranges and not new_ipv6_ranges:
            return True   # No legitimate sources remain - remove entire rule
        
        # Update permission with filtered IP ranges
        if new_ip_ranges:
            perm['IpRanges'] = new_ip_ranges
        else:
            # Remove empty IpRanges key if no IPv4 ranges remain
            if perm.get('IpRanges', False):
                perm.pop('IpRanges')
                
        if new_ipv6_ranges:
            perm['Ipv6Ranges'] = new_ipv6_ranges
        else:
            # Remove empty Ipv6Ranges key if no IPv6 ranges remain
            if perm.get('Ipv6Ranges', False):
                perm.pop('Ipv6Ranges')
        
        return perm  # Return improved permission

    # No unrestricted access found - permission is already secure
    return False


def revoke(perm, client, sg_id):
    """
    Remove a security group ingress rule.
    
    Args:
        perm: Permission dictionary to revoke
        client: EC2 client for the target account/region
        sg_id: Security group ID to modify
        
    Returns:
        bool: True if rule was successfully removed, False otherwise
        
    Error Handling:
        - InvalidPermission.NotFound: Rule doesn't exist (returns False)
        - Other errors: Re-raised for caller to handle
    """
    print("Revoking: ", perm)

    try:
        response = client.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[perm]
        )
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'InvalidPermission.NotFound':
            print("Not found, ignoring")
            return False
        else:
            raise error

    print(response)

    # AWS returns 'Return': False on failure, True on success
    if response['Return'] is False:
        return False
    return True


def authorize(perm, client, sg_id):
    """
    Add a new security group ingress rule.
    
    Used to install improved rules after revoking problematic ones.
    Includes rollback capability when used in conjunction with revoke().
    
    Args:
        perm: Permission dictionary to authorize
        client: EC2 client for the target account/region
        sg_id: Security group ID to modify
        
    Returns:
        bool: True if rule was successfully added, False otherwise
        
    Error Handling:
        - InvalidPermission.NotFound: Rule context missing (returns False)
        - InvalidPermission.Duplicate: Rule already exists (returns False)
        - Other errors: Re-raised for caller to handle
    """
    print("Authorising: ", perm)

    try:
        response = client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[perm]
        )
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'InvalidPermission.NotFound':
            print("Not found, ignoring")
            return False
        elif error.response['Error']['Code'] == 'InvalidPermission.Duplicate':
            print("Duplicate, ignoring")
            return False
        else:
            raise error

    print(response)
    return True


