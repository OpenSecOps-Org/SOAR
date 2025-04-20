import os
import botocore
import boto3
from aws_utils.clients import get_client

# Lambda handler function
def lambda_handler(data, _context):
    print(data)

    # Extract necessary information from the data
    finding = data['finding']
    account_id = finding['AwsAccountId']
    region = finding['Resources'][0]['Region']
    resource = finding['Resources'][0]
    details = resource.get('Details', False)

    # Get the client for the specified account and region
    client = get_client('ec2', account_id, region)

    # Check if there are details available for the security group
    if details:
        sg_id = details['AwsEc2SecurityGroup']['GroupId']
        owner_id = details['AwsEc2SecurityGroup']['OwnerId']
        ingress_perms = details['AwsEc2SecurityGroup'].get('IpPermissions', [])
        egress_perms = details['AwsEc2SecurityGroup'].get('IpPermissionsEgress', [])
    else:
        # If details are not available, get the details using the security group ID
        sg_id = resource['Id'].rsplit('/', 1)[1]
        owner_id, ingress_perms, egress_perms = get_details(sg_id, client)
        if not owner_id and not ingress_perms and not egress_perms:
            # If no details are found, suppress the finding and return the data
            data['actions']['suppress_finding'] = True
            return data

    # Check if the security group is in use
    if security_group_in_use(client, sg_id):
        print("The SG is in use, create ticket to team to fix.")
        data['actions']['autoremediation_not_done'] = True
        data['messages']['actions_taken'] = "None, as the security group is in use."
        data['messages']['actions_required'] = "Please update your infrastructure not to use the VPC default security group: create a new one with more restrictive routing rules, then remove the ingress and egress rules of the VPC default security group."
        return data

    # Check if the ingress or egress rules have been modified
    if ingress_modified(ingress_perms, sg_id, owner_id) or egress_modified(egress_perms):
        print("The SG has been modified, create ticket to team to fix.")
        data['actions']['autoremediation_not_done'] = True
        data['messages']['actions_taken'] = "None, as the security group no longer is in its pristine state."
        data['messages']['actions_required'] = "Please update your infrastructure not to use the VPC default security group: create a new one with more restrictive routing rules, then remove the ingress and egress rules of the VPC default security group."
        return data

    data['messages']['actions_taken'] = ''

    # Revoke the ingress rules if necessary
    if revoke_ingress(ingress_perms[0], client, sg_id):
        data['messages']['actions_taken'] += "All ingress rules have been removed. "

    # Revoke the egress rules if necessary
    if revoke_egress(egress_perms[0], client, sg_id):
        data['messages']['actions_taken'] += "All egress rules have been removed. "

    # If any actions were taken, update the required actions message and return the data
    if data['messages']['actions_taken'] != '':
        data['messages']['actions_required'] = "None."
        return data

    # If neither ingress nor egress rules could be revoked, create a ticket for the team to fix
    print("The SG rules can't be revoked, create ticket to team to fix.")
    data['actions']['autoremediation_not_done'] = True
    data['messages']['actions_taken'] = "None. The ingress and egress rules could not be revoked."
    data['messages']['actions_required'] = "Please update your infrastructure not to use the VPC default security group: create a new one with more restrictive routing rules, then remove the ingress and egress rules of the VPC default security group."
    return data

# Check if the security group is in use
def security_group_in_use(client, sg_id):
    response = client.describe_instances()
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            for security_group in instance['SecurityGroups']:
                if sg_id == security_group['GroupId']:
                    return True
    return False

# Check if the ingress rules have been modified
def ingress_modified(perms, sg_id, owner_id):
    if len(perms) == 0:
        return False
    if len(perms) != 1:
        return True
    if perms[0].get('IpProtocol', False) != '-1':
        return True
    user_id_group_pairs = perms[0].get('UserIdGroupPairs', [])
    if len(user_id_group_pairs) != 1:
        return True
    if user_id_group_pairs[0].get('GroupId', False) != sg_id:
        return True
    if user_id_group_pairs[0].get('UserId', False) != owner_id:
        return True
    return False

# Check if the egress rules have been modified
def egress_modified(perms):
    if len(perms) == 0:
        return False
    if len(perms) != 1:
        return True
    if perms[0].get('IpProtocol', False) != '-1':
        return True
    ip_ranges = perms[0].get('IpRanges', False)
    if not ip_ranges:
        return True
    if len(ip_ranges) != 1:
        return True
    if ip_ranges[0].get('CidrIp', False) != '0.0.0.0/0':
        return True
    return False

# Revoke the ingress rules
def revoke_ingress(perm, client, sg_id):
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

    if response['Return'] == False:
        return False
    return True

# Revoke the egress rules
def revoke_egress(perm, client, sg_id):
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

    if response['Return'] == False:
        return False
    return True


# Get the details of the security group
def get_details(sg_id, client):
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