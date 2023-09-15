import os
import botocore
import boto3

# Get the cross account role from the environment variables
CROSS_ACCOUNT_ROLE = os.environ['CROSS_ACCOUNT_ROLE']

# Create an STS client
sts_client = boto3.client('sts')

# Set the port number for RDP
PORT = 3389


def lambda_handler(data, _context):
    # Print the input data
    print(data)

    # Extract the finding and details from the input data
    finding = data['finding']
    details = finding['Resources'][0].get('Details', False)

    # If there are no details, suppress the finding and return the modified data
    if not details:
        print("No SG details in finding. Suppressing.")
        data['actions']['suppress_finding'] = True
        return data

    # Extract the security group ID and permissions from the details
    sg_id = details['AwsEc2SecurityGroup']['GroupId']
    perms = details['AwsEc2SecurityGroup']['IpPermissions']

    # Extract the AWS account ID and region from the finding
    account_id = finding['AwsAccountId']
    region = finding['Resources'][0]['Region']

    # Get the EC2 client for the specified account and region
    client = get_client('ec2', account_id, region)

    # Flag to track if any changes were made
    did_something = False

    # Iterate over each permission in the list
    for perm in perms:
        # Print the existing permission
        print("Existing IpPermissions: ", perm)

        # Improve the permission by removing unnecessary IP ranges
        better_perm = improve_perm(perm)

        # Print the improved permission
        print("Improved IpPermissions: ", better_perm)

        # If there are no IP ranges left in the permission, revoke the whole permission
        if better_perm == True:
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

    # If no changes were made, flag the autoremediation as not done and return the modified data
    if not did_something:
        data['actions']['autoremediation_not_done'] = True
        return data

    # Add a message to indicate that the ingress rule has been modified or deleted
    data['messages']['actions_taken'] = "The ingress rule has been modified or deleted."
    return data


def improve_perm(perm):
    # Make a copy of the permission
    perm = perm.copy()

    # Extract the protocol from the permission
    proto = perm['IpProtocol']

    # Check if the protocol is not "-1" (all protocols) and not "tcp" or the port range does not include the RDP port
    if proto != "-1" and (proto != "tcp" or perm.get('FromPort', 0) > PORT or perm.get('ToPort', 99999) < PORT):
        return False

    # Extract the IP ranges from the permission
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

    # If anything was removed, return the modified permission
    if modified:
        if len(new_ip_ranges) == 0 and len(new_ipv6_ranges) == 0:
            return True   # No IP ranges left, signal full removal
        if len(new_ip_ranges) > 0:
            perm['IpRanges'] = new_ip_ranges
        else:
            if perm.get('IpRanges', False):
                perm.pop('IpRanges')
        if len(new_ipv6_ranges) > 0:
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
        if error.response['Error']['Code'] == 'InvalidPermission.NotFound':
            print("Not found, ignoring")
            return False
        else:
            raise error

    # Print the response from revoking the permission
    print(response)

    # If the return value is False, return False
    if response['Return'] == False:
        return False
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
        if error.response['Error']['Code'] == 'InvalidPermission.NotFound':
            print("Not found, ignoring")
            return False
        elif error.response['Error']['Code'] == 'InvalidPermission.Duplicate':
            print("Duplicate, ignoring")
            return False
        else:
            raise error

    # Print the response from authorizing the permission
    print(response)
    return True


def get_client(client_type, account_id, region, role=CROSS_ACCOUNT_ROLE):
    # Assume the cross account role and create a new session
    other_session = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"auto_remediate_ec214_{account_id}"
    )

    # Extract the access key, secret key, and session token from the assumed role session
    access_key = other_session['Credentials']['AccessKeyId']
    secret_key = other_session['Credentials']['SecretAccessKey']
    session_token = other_session['Credentials']['SessionToken']

    # Create a new client with the assumed role credentials
    return boto3.client(
        client_type,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=region
    )