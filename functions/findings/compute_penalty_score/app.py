"""
SOAR Findings Analysis: Penalty Score Computation

This Lambda function calculates penalty scores for Security Hub findings based on
severity and environment impact. The penalty score is used for prioritization,
reporting, and SLA calculations within the SOAR system.

Penalty Score Calculation:
1. Severity Component: Transform normalized severity (0-100) into weighted factor
2. Environment Component: Apply multiplier based on environment criticality
3. Final Score: severity_factor × environment_factor

Severity Transformation:
- Formula: ((normalized_severity + 60) / 100)²
- LOW (~0.64): Lower impact for informational issues
- MEDIUM (~1.0): Baseline impact for standard issues  
- HIGH (~1.44): Elevated impact for serious issues
- CRITICAL (~2.56): Maximum impact for critical issues

Environment Multipliers:
- Development: 1.0× (learning/testing environments)
- Staging: 2.0× (pre-production validation)
- Production: 10.0× (business-critical systems)

Target Use: Finding prioritization and incident response SLA determination
Integration: SOAR workflow step for findings processing and reporting
"""

import os

# Default environment classifications for penalty score calculation
DEFAULT_DEV_ENVS = "DEV, DEVELOPMENT, DEVINT, DI"
DEFAULT_STAGING_ENVS = "STAGING, STG, PREPROD, PP, TEST, QA, UAT, SIT, SYSTEMTEST, INTEGRATION"
DEFAULT_PROD_ENVS = "PROD, PRD, PRODUCTION, LIVE"


def env_var_to_set(env_var, default):
    """
    Convert comma-separated environment variable to normalized set for comparison.
    
    Args:
        env_var: Environment variable name to read
        default: Default comma-separated string if env var not set
        
    Returns:
        set: Uppercase, trimmed environment names for case-insensitive matching
        
    Purpose:
        Enables flexible environment classification while maintaining consistent
        matching logic regardless of case or spacing variations.
    """
    result_set = {item.strip().upper() for item in os.getenv(env_var, default).split(',')}
    print(f"{env_var} set: {result_set}")
    return result_set


def lambda_handler(data, _context):
    """
    Main Lambda handler for computing penalty scores for Security Hub findings.
    
    Args:
        data: SOAR finding data containing Security Hub finding and account information
        _context: Lambda context (unused)
        
    Returns:
        str: Penalty score as string (required for DynamoDB integration)
        
    Calculation Process:
        1. Extract normalized severity from Security Hub finding
        2. Transform severity using quadratic formula for appropriate weighting
        3. Determine environment classification from account metadata
        4. Apply environment multiplier based on business impact
        5. Return final penalty score for downstream processing
    """
    print(data)

    finding = data['finding']
    normalized_severity = finding['Severity']['Normalized']

    # STEP 1: Transform severity using quadratic formula for appropriate weighting
    # Adds 60 to shift baseline and squares result to emphasize higher severities
    # Result: LOW ~0.64, MEDIUM ~1.0, HIGH ~1.44, CRITICAL ~2.56
    severity = ((normalized_severity + 60.0) / 100.0) ** 2.0

    # STEP 2: Extract and normalize environment for classification
    environment = data['account']['Environment'].upper()

    # STEP 3: Load environment classification sets from configuration
    DEV_ENVS = env_var_to_set('DEV_ENVS', DEFAULT_DEV_ENVS)
    STAGING_ENVS = env_var_to_set('STAGING_ENVS', DEFAULT_STAGING_ENVS)
    PROD_ENVS = env_var_to_set('PROD_ENVS', DEFAULT_PROD_ENVS)

    # Debug output for environment classification
    print(f"Environment: {environment}")
    print(f"DEV_ENVS: {DEV_ENVS}")
    print(f"STAGING_ENVS: {STAGING_ENVS}")
    print(f"PROD_ENVS: {PROD_ENVS}")

    # STEP 4: Determine environment multiplier based on business impact
    if environment in DEV_ENVS:
        env_factor = 1.0    # Development: Lower impact, learning environment
    elif environment in STAGING_ENVS:
        env_factor = 2.0    # Staging: Moderate impact, pre-production validation
    elif environment in PROD_ENVS:
        env_factor = 10.0   # Production: High impact, business-critical systems
    else:
        env_factor = 1.0    # Unknown: Default to development-level impact

    # STEP 5: Calculate final penalty score
    penalty_score = severity * env_factor

    print(f"Normalized severity: {normalized_severity}, calculated severity: {severity}, env factor: {env_factor}, penalty score: {penalty_score}")

    # Return as string for DynamoDB storage compatibility
    return str(penalty_score)
