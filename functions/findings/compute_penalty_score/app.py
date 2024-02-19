import os

# Takes the ENV vars DEV_ENVS, STAGING_ENVS, and PROD_ENVS

# Default values for each environment variable string
DEFAULT_DEV_ENVS = "DEV, DEVELOPMENT, DEVINT, DI"
DEFAULT_STAGING_ENVS = "STAGING, STG, PREPROD, PP, TEST, QA, UAT, SIT, SYSTEMTEST, INTEGRATION"
DEFAULT_PROD_ENVS = "PROD, PRD, PRODUCTION, LIVE"


# Function to convert comma-separated string to a set, with a default value if the environment variable is not set
def env_var_to_set(env_var, default):
    return {item.strip().upper() for item in os.getenv(env_var, default).split(',')}


# Read and process environment variables with defaults
DEV_ENVS = env_var_to_set('DEV_ENVS', DEFAULT_DEV_ENVS)
STAGING_ENVS = env_var_to_set('STAGING_ENVS', DEFAULT_STAGING_ENVS)
PROD_ENVS = env_var_to_set('PROD_ENVS', DEFAULT_PROD_ENVS)


def lambda_handler(data, _context):
    print(data)

    finding = data['finding']

    # severity == ~0.64 for LOW, ~1.0 for MEDIUM, ~1.44 for HIGH, ~2.56 for CRITICAL
    severity = ((finding['Severity']['Normalized'] + 60.0) / 100.0) ** 2.0

    # Convert environment to uppercase for case-insensitive comparison
    environment = data['account']['Environment'].upper()

    # Determine env_factor based on environment group membership
    if environment in DEV_ENVS:
        env_factor = 1.0
    elif environment in STAGING_ENVS:
        env_factor = 2.0
    elif environment in PROD_ENVS:
        env_factor = 10.0
    else:
        env_factor = 1.0

    # The DynamoDB integration needs this in string format
    return str(severity * env_factor)
