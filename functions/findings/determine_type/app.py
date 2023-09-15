import os

GUARD_DUTY_EC2_TERMINATION_SEVERITIES = os.environ['GUARD_DUTY_EC2_TERMINATION_SEVERITIES'].split(
    ',')

GUARD_DUTY_EC2_NOTIFICATION_SEVERITIES = os.environ['GUARD_DUTY_EC2_NOTIFICATION_SEVERITIES'].split(
    ',')

GUARD_DUTY_IAM_USER_NOTIFICATION_SEVERITIES = os.environ['GUARD_DUTY_IAM_USER_NOTIFICATION_SEVERITIES'].split(
    ',')

GUARD_DUTY_S3_NOTIFICATION_SEVERITIES = os.environ['GUARD_DUTY_S3_NOTIFICATION_SEVERITIES'].split(
    ',')

GUARD_DUTY_EKS_NOTIFICATION_SEVERITIES = os.environ['GUARD_DUTY_EKS_NOTIFICATION_SEVERITIES'].split(
    ',')

GENERIC_NOTIFICATION_SEVERITIES = os.environ['GENERIC_NOTIFICATION_SEVERITIES'].split(
    ',')

SOC_TICKET_SEVERITIES = os.environ['SOC_TICKET_SEVERITIES'].split(',')

IGNORE_PRODUCTS = os.environ['IGNORE_PRODUCTS'].split(',')


def lambda_handler(data, _context):
    print(data)
    finding = data['finding']
    #account_id = finding['AwsAccountId']
    severity = finding['Severity']['Label']
    product_name = finding['ProductFields'].get(
        'aws/securityhub/ProductName', 'N/A')
    generator_id = finding['GeneratorId']
    title = finding['Title']
    description = finding['Description']

    if finding.get('Compliance', False):
        print(f"Suppressing unhandled control for product '{product_name}'.")
        return {
            'suppress': True
        }

    if product_name in IGNORE_PRODUCTS:
        print(f"Suppressing product '{product_name}'.")
        return {
            'suppress': True
        }

    if product_name == 'GuardDuty':
        types = finding['Types']
        for a_type in types:
            if 'EC2-' in a_type:
                terminate = severity in GUARD_DUTY_EC2_TERMINATION_SEVERITIES
                notify = terminate or severity in GUARD_DUTY_EC2_NOTIFICATION_SEVERITIES
                return {
                    'type': 'EC2',
                    'finding_type': a_type,
                    'terminate': terminate,
                    'suppress': not notify,
                    'open_ticket': terminate or severity in SOC_TICKET_SEVERITIES,
                }
            if 'Kubernetes-' in a_type:
                terminate = False  # This might change in future
                notify = terminate or severity in GUARD_DUTY_EKS_NOTIFICATION_SEVERITIES
                return {
                    'type': 'EKS',
                    'finding_type': a_type,
                    'terminate': terminate,
                    'suppress': not notify,
                    'open_ticket': terminate or severity in SOC_TICKET_SEVERITIES,
                }
            if 'IAMUser-' in a_type:
                return {
                    'type': 'IAMUser',
                    'finding_type': a_type,
                    'suppress': severity not in GUARD_DUTY_IAM_USER_NOTIFICATION_SEVERITIES,
                    'open_ticket': severity in SOC_TICKET_SEVERITIES,
                }
            if 'S3-' in a_type:
                return {
                    'type': 'S3',
                    'finding_type': a_type,
                    'suppress': severity not in GUARD_DUTY_S3_NOTIFICATION_SEVERITIES,
                    'open_ticket': severity in SOC_TICKET_SEVERITIES,
                }

    finding_type = finding['Types'][0]

    if generator_id.startswith('CIS-'):
        if 'cis-alarms' in IGNORE_PRODUCTS:
            print(f"Suppressing CIS alarm '{generator_id}'.")
            return {
                'suppress': True
            }
        finding_type = generator_id

    if generator_id == 'aws/access-analyzer':
        if ' allows cross-account access' in title:
            if 'AWSReservedSSO_' in title:
                print(
                    f"Suppressing false positive SSO cross-account role incident '{title}'.")
                return {
                    'suppress': True
                }
            if 'AwsS3Bucket/' in title:
                print(
                    f"Suppressing control-duplicated S3 cross-account role incident '{title}'.")
                return {
                    'suppress': True
                }
            if 'AwsIamRole/' in title and 'Federated' in description:
                print(
                    f"Suppressing IAM cross-account role incident '{title}'.")
                return {
                    'suppress': True
                }
            if 'AwsKmsKey/' in title:
                print(
                    f"Suppressing IAM cross-account KMS key incident '{title}'.")
                return {
                    'suppress': True
                }
            if 'Other/arn:aws:ecr:' in title:
                print(
                    f"Suppressing IAM cross-account ECR repo access '{title}'.")
                return {
                    'suppress': True
                }
        if ' allows public access' in title:
            if 'AwsKmsKey/' in title:
                print(
                    f"Suppressing IAM false positive public KMS key incident '{title}'.")
                return {
                    'suppress': True
                }

    if product_name == 'Macie':
        if finding_type == 'Software and Configuration Checks/AWS Security Best Practices/Policy:IAMUser-S3BucketSharedExternally':
            print("Suppressing Macie S3 cross-account false positive '{title}'.")
            return {
                'suppress': True
            }

    return {
        'type': 'Generic',
        'finding_type': finding_type,
        'suppress': severity not in GENERIC_NOTIFICATION_SEVERITIES,
        'open_ticket': severity in SOC_TICKET_SEVERITIES,
    }
