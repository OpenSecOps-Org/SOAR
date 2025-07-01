# SOAR Testing Guide

**🔑 KEY: SOAR uses universal OpenSecOps testing patterns + ASFF/workflow additions**

**📚 For comprehensive testing architecture and standards, see [TESTING.md](../TESTING.md)**

## Current Status

**✅ Auto-Remediation Testing: COMPLETE**
- **30/30 functions** tested with 428 comprehensive tests
- **100% coverage** across 9 AWS services (RDS, EC2, S3, IAM, ELB, ECR, ECS, KMS, DynamoDB)
- **Performance target**: <0.1 seconds per test (achieved)
- **Zero AWS costs** guaranteed through comprehensive mocking

**⏳ Workflow Functions: IN PROGRESS**
- **43 functions** remaining for testing
- **Next priority**: Core orchestration functions (`get_ticket_and_decide`, `get_account_data`, `suppress_finding`)

## SOAR Additions to Universal Patterns

### ASFF Test Data Creation

```python
# Use centralized ASFF creation (tests/fixtures/asff_data.py)
def create_asff_event(service, control_id, resource_id, account_id="123456789012"):
    return {
        "version": "0",
        "detail": {
            "findings": [{
                "SchemaVersion": "2018-10-08",
                "GeneratorId": f"aws-foundational-security-standard/v/1.0.0/{control_id}",
                "Resources": [{"Type": f"Aws{service}", "Id": resource_id}]
            }]
        }
    }

# Service-specific helpers
create_rds_asff_event("RDS.1", "db-instance-id")
create_ec2_asff_event("EC2.15", "i-1234567890")
create_s3_asff_event("S3.8", "bucket-name")
```

### Auto-Remediation Test Template

```python
class TestAutoRemediation:
    def test_successful_remediation(self):
        event = create_asff_event("RDS", "RDS.1", "test-resource")
        result = lambda_handler(event, None)
        
        assert result['actions']['autoremediation_not_done'] is False
        assert 'successfully' in result['messages']['actions_taken']
    
    def test_resource_not_found_suppression(self):
        # Test graceful handling when resource doesn't exist
        assert result['actions']['autoremediation_not_done'] is True
    
    def test_tag_based_exemption(self):
        with patch.dict(os.environ, {'TAG': 'exemption-tag'}):
            # Should skip remediation gracefully
            assert 'exemption' in result['messages']['actions_taken'].lower()
```

### Workflow Function Testing (Scratchpad Pattern)

```python
class TestWorkflowFunction:
    def test_scratchpad_manipulation(self):
        scratchpad = {
            'account_data': {'account_id': '123456789012'},
            'finding_data': {'finding_id': 'test-finding'},
            'action_flags': {'auto_remediation_enabled': True}
        }
        
        result = lambda_handler(scratchpad, None)
        
        # Verify scratchpad data flow
        assert result['account_data']['account_id'] == '123456789012'
        assert 'processed' in result['action_flags']
```

## Next Steps

### Immediate Priority (Current Sprint)

1. **Begin core workflow testing**:
   - `get_ticket_and_decide` - Central orchestration function
   - `get_account_data` - Account metadata provider
   - `suppress_finding` - Security Hub status updates

2. **Apply Foundation patterns**:
   - Implement global mocking strategy for better performance
   - Use data-driven mock configuration for DynamoDB, Security Hub, SES

### Current Testing Infrastructure

```bash
# Quick start
cd SOAR/
cp .env.test.example .env.test
pip install pytest pytest-xdist pytest-cov "moto[all]" boto3 python-dotenv

# Run tests
pytest tests/unit/                           # All unit tests
pytest tests/unit/auto_remediations/rds/     # RDS auto-remediation
pytest tests/unit/workflow/                  # Workflow functions (in development)

# With coverage
pytest tests/unit/ --cov=functions --cov-report=html
```

## Testing Environment

**Automatic Environment Loading**: Tests load `.env.test` automatically via `conftest.py`

**Key Environment Variables**:
```bash
AWS_DEFAULT_REGION=us-east-1
AWS_ACCESS_KEY_ID=test
AWS_SECRET_ACCESS_KEY=test
TAG=exemption-tag
```

## Performance Standards

- **Per-test target**: <0.1 seconds
- **Total suite target**: <43 seconds for 428 tests
- **Success rate**: 100% (all tests must always pass)
- **AWS costs**: Zero (comprehensive mocking prevents all real API calls)

## Resources

- **📚 [TESTING.md](../TESTING.md)**: Complete testing architecture and standards
- **🏗️ [SOAR/ARCHITECTURE.md](../ARCHITECTURE.md)**: SOAR architecture with state machine analysis
- **📋 [CLAUDE.md](../CLAUDE.md)**: Essential testing patterns and anti-patterns

---

**Current Focus**: Workflow function testing to complete SOAR's comprehensive test coverage