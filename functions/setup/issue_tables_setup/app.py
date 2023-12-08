import os
import boto3
import cfnresponse
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

LOCAL_CONTROL_AUTOREMEDIATION_SUPPRESSIONS_TABLE = os.environ['LOCAL_CONTROL_AUTOREMEDIATION_SUPPRESSIONS_TABLE']
LOCAL_CONTROL_SUPPRESSIONS_TABLE = os.environ['LOCAL_CONTROL_SUPPRESSIONS_TABLE']
LOCAL_INCIDENTS_SUPPRESSIONS_TABLE = os.environ['LOCAL_INCIDENTS_SUPPRESSIONS_TABLE']
REMEDIATABLE_SEC_HUB_CONTROLS_TABLE = os.environ['REMEDIATABLE_SEC_HUB_CONTROLS_TABLE']
SECURITY_ADM_ACCOUNT_ID = os.environ['SECURITY_ADM_ACCOUNT_ID']
ORG_ACCOUNT_ID = os.environ['ORG_ACCOUNT_ID']
AFT_MANAGEMENT_ACCOUNT_ID = os.environ['AFT_MANAGEMENT_ACCOUNT_ID']
LOG_ARCHIVE_ACCOUNT_ID = os.environ['LOG_ARCHIVE_ACCOUNT_ID']

dynamodb = boto3.resource('dynamodb')
LOCAL_CONTROL_AUTOREMEDIATION_SUPPRESSIONS_RESOURCE = dynamodb.Table(LOCAL_CONTROL_AUTOREMEDIATION_SUPPRESSIONS_TABLE)
LOCAL_CONTROL_SUPPRESSIONS_RESOURCE = dynamodb.Table(LOCAL_CONTROL_SUPPRESSIONS_TABLE)
LOCAL_INCIDENTS_SUPPRESSIONS_RESOURCE = dynamodb.Table(LOCAL_INCIDENTS_SUPPRESSIONS_TABLE)
REMEDIATABLE_SEC_HUB_CONTROLS_RESOURCE = dynamodb.Table(REMEDIATABLE_SEC_HUB_CONTROLS_TABLE)


def lambda_handler(event, context):
    try:
        logger.info('Received event: %s', event)

        request_type = event.get('RequestType', '')
        if request_type == 'Create':
            setup_remediatable_sec_hub_controls(REMEDIATABLE_SEC_HUB_CONTROLS_RESOURCE)
            setup_local_incidents_suppressions(LOCAL_INCIDENTS_SUPPRESSIONS_RESOURCE)
            setup_local_control_suppressions(LOCAL_CONTROL_SUPPRESSIONS_RESOURCE)
            setup_local_control_autoremediation_suppressions(LOCAL_CONTROL_AUTOREMEDIATION_SUPPRESSIONS_RESOURCE)

        # Succeed for Create, Update, Delete (but we only do things at Create time)
        cfnresponse.send(event, context, cfnresponse.SUCCESS, {})
        # Add a log statement for successful completion
        logger.info('Function execution completed successfully')

    # If anything at all fails, just fail and return
    except Exception as e:
        logger.error('Error occurred: %s', str(e))
        cfnresponse.send(event, context, cfnresponse.FAILED, 'Error occurred: {}'.format(str(e)))


# ----------------------------------------------------------------
#
# Setup functions for individual tables
#
# ----------------------------------------------------------------

def setup_remediatable_sec_hub_controls(table_resource):
    logger.info('Setting up Remediatable Security Hub Controls table')

    proposed_changes = [
        {'id': 'EC2.2'},
        {'id': 'EC2.4'},
        {'id': 'EC2.6'},
        {'id': 'EC2.7'},
        {'id': 'EC2.12'},
        {'id': 'EC2.13'},
        {'id': 'EC2.14'},
        {'id': 'EC2.15'},
        {'id': 'EC2.22'},
        {'id': 'ECR.1'},
        {'id': 'ECR.2'},
        {'id': 'ECR.3'},
        {'id': 'ECS.2'},
        {'id': 'ECS.12'},
        {'id': 'ELB.1'},
        {'id': 'ELB.4'},
        {'id': 'ELB.5'},
        {'id': 'IAM.8'},
        {'id': 'KMS.4'},
        {'id': 'RDS.2'},
        {'id': 'RDS.4'},
        {'id': 'RDS.6'},
        {'id': 'RDS.9'},
        {'id': 'RDS.11'},
        {'id': 'RDS.13'},
        {'id': 'RDS.17'},
        {'id': 'S3.2'},
        {'id': 'S3.3'},
        {'id': 'S3.10'}
    ]

    logger.info('Proposed changes: %s', proposed_changes)

    if has_existing_items(table_resource):
        logger.info('Table already has existing items. Skipping setup.')
        return
    else:
        write_items_to_table(table_resource, proposed_changes)
        logger.info('Setup completed for Remediatable Security Hub Controls table')


def setup_local_incidents_suppressions(table_resource):
    logger.info('Setting up Local Incidents Suppressions table')

    proposed_changes = [
        {
            'id': 'Effects/Data Exposure/Policy:S3-BucketBlockPublicAccessDisabled',
            'suppress_when': 'account_id != 1'
        }
    ]

    logger.info('Proposed changes: %s', proposed_changes)

    if has_existing_items(table_resource):
        logger.info('Table already has existing items. Skipping setup.')
        return
    else:
        write_items_to_table(table_resource, proposed_changes)
        logger.info('Setup completed for Local Incidents Suppressions table')


def setup_local_control_suppressions(table_resource):
    logger.info('Setting up Local Control Suppressions table')

    proposed_changes = [
        {'id': 'IAM.21', 'suppress_when': 'policy_name = developer-permission-boundary-policy, network-administrator-permission-boundary-policy, security-administrator-permission-boundary-policy'}
    ]

    if LOG_ARCHIVE_ACCOUNT_ID or ORG_ACCOUNT_ID:
        account_ids = []
        if LOG_ARCHIVE_ACCOUNT_ID:
            account_ids.append(LOG_ARCHIVE_ACCOUNT_ID)
        if ORG_ACCOUNT_ID:
            account_ids.append(ORG_ACCOUNT_ID)

        suppress_when = f"account_id = {','.join(account_ids)}"
        proposed_changes.append({'id': 'Kinesis.1', 'suppress_when': suppress_when})

    logger.info('Proposed changes: %s', proposed_changes)

    if has_existing_items(table_resource):
        logger.info('Table already has existing items. Skipping setup.')
        return
    else:
        write_items_to_table(table_resource, proposed_changes)
        logger.info('Setup completed for Local Control Suppressions table')


def setup_local_control_autoremediation_suppressions(table_resource):
    logger.info('Setting up Local Control Autoremediation Suppressions table')

    proposed_changes = []

    if AFT_MANAGEMENT_ACCOUNT_ID or SECURITY_ADM_ACCOUNT_ID:
        account_ids = []
        if AFT_MANAGEMENT_ACCOUNT_ID:
            account_ids.append(AFT_MANAGEMENT_ACCOUNT_ID)
        if SECURITY_ADM_ACCOUNT_ID:
            account_ids.append(SECURITY_ADM_ACCOUNT_ID)

        suppress_when = f"account_id = {','.join(account_ids)}"
        proposed_changes.append({'id': 'EC2.22', 'suppress_when': suppress_when})

    logger.info('Proposed changes: %s', proposed_changes)

    if has_existing_items(table_resource):
        logger.info('Table already has existing items. Skipping setup.')
        return
    else:
        write_items_to_table(table_resource, proposed_changes)
        logger.info('Setup completed for Local Control Autoremediation Suppressions table')


# ----------------------------------------------------------------
#
# Helper functions
#
# ----------------------------------------------------------------

def write_items_to_table(table_resource, items):
    for item in items:
        table_resource.put_item(Item=item)


def has_existing_items(table_resource):
    response = table_resource.scan()
    items = response.get('Items', [])
    return len(items) > 0

