"""
ASFF (AWS Security Finding Format) data structure helpers for testing.

Based on the structure created by the ASFF processor state machine (asff_processor.asl.yaml)
that gets passed to auto-remediation functions.

## When to Use ASFF Structure vs Simple Fixtures

**Use ASFF Structure (`prepare_rds_test_data`) when:**
- Tests call the actual `lambda_handler` function
- Testing complete auto-remediation workflows
- Need to validate `messages` or `actions` modifications
- Integration-style testing

**Use Simple Fixtures (e.g., `get_rds2_postgres_finding`) when:**
- Testing data structure validation only
- Testing helper functions that don't need full context
- Pure unit tests of parsing logic
- Focused tests that don't need ASFF overhead

**Current Status:**
- RDS.4 tests: Use ASFF structure (call lambda_handler)
- Other RDS tests: Use simple fixtures (data validation only)
"""

def create_asff_test_data(finding_data):
    """
    Create proper ASFF processor test data structure.
    
    This matches the structure created in asff_processor.asl.yaml lines 14-29
    and passed to auto-remediation functions at lines 305-315.
    
    Args:
        finding_data: The Security Hub finding data
        
    Returns:
        Complete ASFF data structure expected by auto-remediation functions
    """
    return {
        'account': {},                    # Account information from GetAccountDataFunction
        'finding': finding_data,          # Security Hub finding from $.detail.findings[0]
        'tags': {},                      # Tagging information
        'actions': {                     # Action control flags
            'suppress_finding': False,
            'autoremediation_not_done': False,
            'reconsider_later': False
        },
        'messages': {                    # Message reporting structure
            'actions_taken': 'None.',
            'actions_required': 'Please update your infrastructural code to prevent this security issue from arising again at the next deployment.',
            'ai': {
                'plaintext': '',
                'html': ''
            }
        },
        'db': {}                         # Database lookup results
    }


def prepare_rds_test_data(finding_function):
    """
    Helper specifically for RDS auto-remediation tests.
    
    Args:
        finding_function: Function that returns RDS finding fixture
        
    Returns:
        ASFF data structure with RDS finding embedded
    """
    finding_fixture = finding_function()
    finding_data = finding_fixture['finding']
    return create_asff_test_data(finding_data)


def prepare_ec2_test_data(finding_function):
    """
    Helper specifically for EC2 auto-remediation tests.
    
    Args:
        finding_function: Function that returns EC2 finding fixture
        
    Returns:
        ASFF data structure with EC2 finding embedded
    """
    finding_fixture = finding_function()
    finding_data = finding_fixture['finding']
    return create_asff_test_data(finding_data)