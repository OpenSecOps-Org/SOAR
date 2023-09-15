

def lambda_handler(data, _context):
    print(data)

    finding = data['finding']

    # severity == ~0.64 for LOW, ~1.0 for MEDIUM, ~1.44 for HIGH, ~2.56 for CRITICAL
    severity = ((finding['Severity']['Normalized'] + 60.0) / 100.0) ** 2.0

    # env_factor == 1.0 in dev, 10.0 in prod, and 2.0 everywhere else
    environment = data['account']['Environment']
    if environment == 'dev':
        env_factor = 1.0
    elif environment == 'staging':
        env_factor = 2.0
    elif environment == 'test':
        env_factor = 2.0
    elif environment == 'qa':
        env_factor = 2.0
    elif environment == 'prod':
        env_factor = 10.0
    else:
        env_factor = 1.0

    # The DynamoDB integration needs this in string format
    return str(severity * env_factor)
