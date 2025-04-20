import os
import botocore
import boto3
from aws_utils.clients import get_client

# Set the port number
PORT = 22


def lambda_handler(data, _context):
    # Print the input data
    print(data)

    # Get the finding from the input data
    finding = data['finding']

    # Get the details of the finding
    details = finding['Resources'][0].get('Details', False)

    # If there are no details, suppress the finding and return the modified data
    if not details:
        print("No SG details in finding. Suppressing.")
        data['actions']['suppress_finding'] = True
        return data

    # Get the security group ID and IP permissions from the details
    sg_id = details['AwsEc2SecurityGroup']['GroupId']
    perms = details['AwsEc2SecurityGroup']['IpPermissions']

    # Get the AWS account ID and region from the finding
    account_id = finding['AwsAccountId']
    region = finding['Resources'][0]['Region']

    # Get the EC2 client for the specified account and region
    client = get_client('ec2', account_id, region)

    # Variable to track if any action was taken
    did_something = False

    # Iterate over each permission in the list
    for perm in perms:
        # Print the existing permission
        print("Existing IpPermissions: ", perm)

        # Improve the permission
        better_perm = improve_perm(perm)

        # Print the improved permission
        print("Improved IpPermissions: ", better_perm)

        # If there are no IP ranges left in the permission, revoke the whole permission
        if better_perm is True:
            if revoke(perm, client, sg_id):
                did_something = True

        # If there is a better version of the permission, revoke the whole permission and authorize the new one
        elif better_perm:
            if revoke(perm, client, sg_id):
                if authorize(better_perm, client, sg_id):
                    did_something = True
                else:
                    # If the new permission failed, reinstall the old one
                    authorize(perm, client, sg_id)

    # If no action was taken, set the flag in the data and return the modified data
    if not did_something:
        data['actions']['autoremediation_not_done'] = True
        return data

    # Set the action taken message in the data and return the modified data
    data['messages']['actions_taken'] = "The ingress rule has been modified or deleted."
    return data


def improve_perm(perm):
    # Create a copy of the permission
    perm = perm.copy()

    # Get the protocol of the permission
    proto = perm['IpProtocol']

    # If the protocol is not "-1" (all protocols) and not "tcp" or the port range is not within the specified port, return False
    if proto != "-1" and (proto != "tcp" or perm.get('FromPort', 0) > PORT or perm.get('ToPort', 99999) < PORT):
        return False

    # Get the IP ranges of the permission
    ip_ranges = perm.get('IpRanges', False)

    # If there are no IP ranges, return False
    if not ip_ranges:
        return False

    # If there is only one IP range and it is "0.0.0.0/0", return True
    if len(ip_ranges) == 1 and ip_ranges[0]['CidrIp'] == "0.0.0.0/0":
        return True

    # Remove any "0.0.0.0/0" and "::/0" from the IP ranges
    modified = False
    new_ip_ranges = []
    new_ipv6_ranges = []
    for ip_range in ip_ranges:
        if ip_range.get('CidrIp', False) != '0.0.0.0/0':
            new_ip_ranges.append(ip_range)
            modified = True
    for ipv6_range in perm.get('Ipv6Ranges', []):
        if ipv6_range.get('CidrIpv6', False) != '::/0':
            new_ipv6_ranges.append(ipv6_range)
            modified = True

    # If anything was removed, return the permission with the modified IP ranges
    if modified:
        if not new_ip_ranges and not new_ipv6_ranges:
            return True   # No IP ranges left, signal full removal
        if new_ip_ranges:
            perm['IpRanges'] = new_ip_ranges
        else:
            if perm.get('IpRanges', False):
                perm.pop('IpRanges')
        if new_ipv6_ranges:
            perm['Ipv6Ranges'] = new_ipv6_ranges
        else:
            if perm.get('Ipv6Ranges', False):
                perm.pop('Ipv6Ranges')
        return perm

    # If nothing was removed, return False: this permission is okay
    return False


def revoke(perm, client, sg_id):
    # Print the permission being revoked
    print("Revoking: ", perm)

    try:
        # Revoke the security group ingress with the specified permission
        response = client.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[perm]
        )
    except botocore.exceptions.ClientError as error:
        # If the permission is not found, ignore the error and return False
        if error.response['Error']['Code'] == 'InvalidPermission.NotFound':
            print("Not found, ignoring")
            return False
        else:
            # If there is any other error, raise it
            raise error

    # Print the response
    print(response)

    # If the return value is False, return False
    if response['Return'] is False:
        return False

    # Return True if the permission was revoked successfully
    return True


def authorize(perm, client, sg_id):
    # Print the permission being authorized
    print("Authorising: ", perm)

    try:
        # Authorize the security group ingress with the specified permission
        response = client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[perm]
        )
    except botocore.exceptions.ClientError as error:
        # If the permission is not found, ignore the error and return False
        if error.response['Error']['Code'] == 'InvalidPermission.NotFound':
            print("Not found, ignoring")
            return False
        # If the permission is a duplicate, ignore the error and return False
        elif error.response['Error']['Code'] == 'InvalidPermission.Duplicate':
            print("Duplicate, ignoring")
            return False
        else:
            # If there is any other error, raise it
            raise error

    # Print the response
    print(response)

    # Return True if the permission was authorized successfully
    return True


