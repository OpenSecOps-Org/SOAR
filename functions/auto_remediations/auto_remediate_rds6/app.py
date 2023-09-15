import os
import json
import logging

import boto3
from botocore.exceptions import ClientError

CROSS_ACCOUNT_ROLE = os.environ['CROSS_ACCOUNT_ROLE']

logger = logging.getLogger(__name__)

sts = boto3.client('sts')


def lambda_handler(data, _context):
    print(data)

    finding = data['finding']
    resource = finding['Resources'][0]

    account_id = finding['AwsAccountId']
    region = resource['Region']

    details = resource['Details']['AwsRdsDbInstance']
    db_instance_identifier = details['DBInstanceIdentifier']
    db_cluster_identifier = details.get('DBClusterIdentifier')

    client = get_client('rds', account_id, region)

    role_name = 'rds-monitoring-role'
    role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'
    policy_arn = 'arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole'

    iam = get_client('iam', account_id, region)

    create_role(iam, role_name, ['monitoring.rds.amazonaws.com'])
    attach_policy(iam, role_name, policy_arn)

    if not db_cluster_identifier:

        waiter = client.get_waiter('db_instance_available')
        waiter.wait(DBInstanceIdentifier=db_instance_identifier)
        try:
            response = client.modify_db_instance(
                DBInstanceIdentifier=db_instance_identifier,
                ApplyImmediately=True,
                MonitoringRoleArn=role_arn,
                MonitoringInterval=60
            )
        except ClientError as error:
            if error.response['Error']['Code'] == 'DBInstanceNotFound':
                print("The DB instance wasn't found. Suppressing.")
                data['messages']['actions_taken'] = "The DB instance wasn't found. This finding has been suppressed."
                data['actions']['suppress_finding'] = True
                return data
            raise error
        print(response)

    else:

        waiter = client.get_waiter('db_cluster_available')
        waiter.wait(DBClusterIdentifier=db_cluster_identifier)
        try:
            response = client.modify_db_cluster(
                DBClusterIdentifier=db_cluster_identifier,
                ApplyImmediately=True,
                MonitoringRoleArn=role_arn,
                MonitoringInterval=60
            )
        except ClientError as error:
            if error.response['Error']['Code'] == 'DBClusterNotFound':
                print("The DB cluster wasn't found. Suppressing.")
                data['messages']['actions_taken'] = "The DB cluster wasn't found. This finding has been suppressed."
                data['actions']['suppress_finding'] = True
                return data
            raise error
        print(response)

    data['messages']['actions_taken'] = "Enhanced monitoring has been enabled with a monitoring interval of 60 seconds."
    data['messages']['actions_required'] = "None"
    return data


def get_client(client_type, account_id, region, role=CROSS_ACCOUNT_ROLE):
    other_session = sts.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"auto_remediate_rds6_{account_id}"
    )
    access_key = other_session['Credentials']['AccessKeyId']
    secret_key = other_session['Credentials']['SecretAccessKey']
    session_token = other_session['Credentials']['SessionToken']
    return boto3.client(
        client_type,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=region
    )


def create_role(iam, role_name, allowed_services):
    """
    Creates a role that lets a list of specified services assume the role.

    :param role_name: The name of the role.
    :param allowed_services: The services that can assume the role.
    :return: The newly created role.
    """
    trust_policy = {
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {'Service': service},
            'Action': 'sts:AssumeRole'
        } for service in allowed_services
        ]
    }

    try:
        role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy))
        logger.info("Created role %s.", role_name)
    except ClientError as error:
        if error.response['Error']['Code'] == 'EntityAlreadyExists':
            print("The Role already exists.")
            return False
        logger.exception("Couldn't create role %s.", role_name)
        raise error
    else:
        return role


def attach_policy(iam, role_name, policy_arn):
    """
    Attaches a policy to a role.

    :param role_name: The name of the role. **Note** this is the name, not the ARN.
    :param policy_arn: The ARN of the policy.
    """
    try:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        logger.info("Attached policy %s to role %s.", policy_arn, role_name)
    except ClientError as error:
        if error.response['Error']['Code'] == 'EntityAlreadyExists':
            print("The policy has already been attached.")
            return False
        logger.exception(
            "Couldn't attach policy %s to role %s.", policy_arn, role_name)
        raise error


# def create_policy(iam, name, description, actions, resource_arn):
#     """
#     Creates a policy that contains a single statement.

#     :param name: The name of the policy to create.
#     :param description: The description of the policy.
#     :param actions: The actions allowed by the policy. These typically take the
#                     form of service:action, such as s3:PutObject.
#     :param resource_arn: The Amazon Resource Name (ARN) of the resource this policy
#                          applies to. This ARN can contain wildcards, such as
#                          'arn:aws:s3:::my-bucket/*' to allow actions on all objects
#                          in the bucket named 'my-bucket'.
#     :return: The newly created policy.
#     """
#     policy_doc = {
#         "Version": "2012-10-17",
#         "Statement": [
#             {
#                 "Effect": "Allow",
#                 "Action": actions,
#                 "Resource": resource_arn
#             }
#         ]
#     }
#     try:
#         policy = iam.create_policy(
#             PolicyName=name, Description=description,
#             PolicyDocument=json.dumps(policy_doc))
#         logger.info("Created policy %s.", name)
#     except ClientError:
#         logger.exception("Couldn't create policy %s.", name)
#         raise
#     else:
#         return policy
