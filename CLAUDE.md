# SOAR Account Reassignment Preprocessor

## CRITICAL IMPLEMENTATION RULES

**⚠️ SECURITY SOFTWARE - NO UNAUTHORIZED CHANGES ⚠️**

**🚨 CRITICAL GIT WARNING 🚨**
**NEVER USE `git checkout` OR ANY DESTRUCTIVE GIT COMMANDS WITHOUT ASKING FIRST!**
- **NO `git checkout`** - Can destroy uncommitted work
- **NO `git reset`** - Can destroy commit history  
- **NO `git rebase`** - Can rewrite history
- **NO `git clean`** - Can delete files permanently
- **ALWAYS ASK FIRST** before any git operation that could lose data

**ABSOLUTE RULE**: NEVER rush ahead with implementation without explicit user permission. This is security software and unauthorized changes are STRICTLY FORBIDDEN.

**REQUIRED WORKFLOW**:
1. Complete assigned task ONLY
2. STOP and ask for permission before any additional changes
3. Wait for explicit user direction
4. No assumptions about "next logical steps"
5. No "helpful" additional modifications

## Problem Statement

AWS Security Hub delegated administration architecture creates account routing mismatches for certain security services (IAM Access Analyzer, GuardDuty, Inspector, Detective). These services generate findings that appear to originate from the Security-Adm account but actually concern resources in member accounts.

**Business Impact**: Security teams in member accounts never receive notifications about their resource issues because findings are attributed to the wrong account.

**📚 Related Documentation**:
- [ARCHITECTURE.md](ARCHITECTURE.md): Complete SOAR system architecture
- [../CLAUDE.md](../CLAUDE.md): OpenSecOps component guidelines and patterns
- [../TESTING.md](../TESTING.md): Testing standards and architecture for all components

## Solution Architecture

**Core Issue**: AWS `BatchUpdateFindings` API cannot modify the `AwsAccountId` field - it is immutable.

**Solution**: Create new finding in correct account + suppress original finding pattern:
1. Detect findings requiring account routing correction
2. Create new ASFF finding in correct account using `BatchImportFindings`
3. Set `actions.suppress_finding = True` to trigger state machine suppression of original finding
4. New finding triggers fresh SOAR processing naturally through Security Hub event flow

**Key Benefits**:
- **Correct Team Notification**: Target account teams receive proper notifications
- **Graceful Degradation**: Failures result in status quo rather than system breakage
- **Proven Pattern**: Follows established SOAR cross-account finding creation patterns
- **State Machine Integration**: Uses existing `actions.suppress_finding` routing logic

## Implementation Status

### ✅ Phase 1 Complete: Decision Logic
- **Function**: `must_recreate_in_other_account()` with two-tier account detection
- **Optimization**: Skip processing for findings not in security-adm account  
- **Error Handling**: Robust dictionary access and critical error logging
- **Testing**: 17 comprehensive TDD tests covering all scenarios
- **Status**: Production-ready decision logic deployed (547/547 tests passing)

### ✅ Phase 2 Complete: TDD Structure & Lambda Handler Integration
**COMPLETED**: Lambda handler now properly integrates with `recreate_asff_finding()` function with graceful error handling.

**Implemented TDD Structure**:
- ✅ `recreate_asff_finding(account_id, data)` function with proper signature
- ✅ Lambda handler calls `recreate_asff_finding` before setting suppress_finding flag
- ✅ Comprehensive TDD tests for True/False return paths
- ✅ Graceful degradation: suppress_finding only set when recreation succeeds
- ✅ All 22 tests passing with proper error handling logic

**Current Behavior**:
- ✅ Lambda handler detects account reassignment needs
- ✅ Calls `recreate_asff_finding(target_account, data)` 
- ✅ Sets `actions.suppress_finding = True` ONLY if recreation succeeds
- ✅ Graceful failure: original finding continues if recreation fails

### ✅ Phase 3 Complete: BatchImportFindings Implementation
**COMPLETED**: Full production-ready implementation with proper ASFF structure and comprehensive error handling.

**Implemented Features**:
- ✅ `BatchImportFindings` for cross-account finding creation following AWS documentation
- ✅ Cross-account Security Hub client creation using established SOAR patterns
- ✅ Proper ASFF structure with required fields (SchemaVersion, CreatedAt, UpdatedAt, etc.)
- ✅ Unique ID generation for target accounts (`{original-id}-reassigned-{account-id}`)
- ✅ Comprehensive AWS API error handling with graceful degradation
- ✅ Timezone-aware datetime handling to eliminate deprecation warnings
- ✅ Complete TDD test coverage (25 tests passing including BatchImportFindings scenarios)

## Test Data

### Test Fixtures Location
[tests/fixtures/preprocessing_test_data.py](tests/fixtures/preprocessing_test_data.py)

### Available Test Cases

1. **`get_guardduty_finding_no_correction()`**
   - GuardDuty finding with resource in same account as finding
   - Expected: No correction needed

2. **`get_access_analyzer_finding_needs_correction_1()`**
   - IAM Access Analyzer finding with ResourceOwnerAccount field
   - Resource in account 222222222222, finding in 111111111111
   - Expected: Correction needed

3. **`get_access_analyzer_finding_needs_correction_2()`**
   - IAM Access Analyzer finding with ResourceOwnerAccount field
   - Resource in account 333333333333, finding in 111111111111
   - Expected: Correction needed

4. **`get_access_analyzer_finding_needs_correction_3()`**
   - IAM Access Analyzer finding with ResourceOwnerAccount field  
   - Resource in account 444444444444, finding in 111111111111
   - Expected: Correction needed

5. **`get_finding_not_in_security_adm_account()`**
   - EC2 Security Group finding in account 555555555555
   - Expected: Should be skipped by optimization logic

## State Machine Integration

**Pattern**: Account Reassignment Preprocessor is positioned after AWS Health Reclassifier with proper Choice node routing (see [ARCHITECTURE.md](ARCHITECTURE.md) for complete flow):

```yaml
Account Reassignment Preprocessor:
  Next: Should Suppress Finding After Account Reassignment?

Should Suppress Finding After Account Reassignment?:
  Type: Choice
  Choices:
    - Variable: $.actions.suppress_finding
      BooleanEquals: true
      Next: Suppress Finding  # Existing suppression node
  Default: Handle Incident  # Normal workflow continues
```

**Benefits**:
- Reuses existing suppression functionality
- Clean separation: Lambda handles creation, state machine handles suppression
- Follows established SOAR preprocessor patterns

## Phase 2 Implementation Plan

### Goal: Complete AWS Security Hub Operations

**Required Implementation**:
1. **Create new finding in target account** using `BatchImportFindings`
2. **Add comprehensive error handling** for AWS API failures
3. **Implement cross-account client creation** using existing SOAR patterns
4. **Only set `actions.suppress_finding = True`** AFTER successful finding creation

### Implementation Pattern
```python
def lambda_handler(data, context):
    # Phase 1: Decision logic (IMPLEMENTED)
    target_account = must_recreate_in_other_account(data)
    if target_account:
        # Phase 2: Security Hub operations (NEEDS IMPLEMENTATION)
        try:
            # Create new finding in target account
            create_finding_in_target_account(data['finding'], target_account)
            
            # Only set suppression flag after successful creation
            data['actions']['suppress_finding'] = True
            print(f"Account reassignment complete: {target_account}")
            
        except Exception as e:
            print(f"Failed to create finding in target account: {e}")
            # Graceful failure - continue with original finding
    
    return data
```

### Cross-Account Finding Creation Pattern
```python
def create_finding_in_target_account(original_finding, target_account):
    """Create new finding in target account with corrected AwsAccountId."""
    # Create corrected finding with target account ID
    corrected_finding = original_finding.copy()
    corrected_finding['AwsAccountId'] = target_account
    
    # Get cross-account Security Hub client
    client = get_client('securityhub', target_account)
    
    # Create new finding in target account
    response = client.batch_import_findings(Findings=[corrected_finding])
    
    if response['FailedCount'] > 0:
        raise Exception(f"Failed to create finding: {response['FailedFindings']}")
    
    print(f"Created corrected finding in account {target_account}")
```

### Account Detection Logic

The decision logic uses a two-tier approach:

1. **Priority 1**: Check `ProductFields.ResourceOwnerAccount` field
2. **Priority 2**: Parse account from resource ARN (arn:aws:service:region:account:resource)

```python
def must_recreate_in_other_account(data):
    """
    Determine if finding requires account reassignment correction.
    
    Returns:
        False: No correction needed
        str: Target account ID if correction is needed
    """
    # Implementation already complete in Phase 1
```

## Testing Strategy

### Current Testing Status
- **✅ 555/555 tests passing** (100% success rate across entire SOAR codebase)
- **✅ Phase 1 Decision Logic**: 17 comprehensive TDD tests
- **✅ Phase 2 TDD Structure**: 22 comprehensive tests including lambda_handler integration
- **✅ Phase 3 BatchImportFindings**: 25 comprehensive tests including complete implementation
- **✅ State Machine Integration**: Comprehensive connectivity validation
- **✅ Production Ready**: Zero regressions in full test suite

### Complete Test Coverage
- ✅ Cross-account `BatchImportFindings` operations with proper ASFF structure
- ✅ AWS API error handling scenarios within recreate_asff_finding  
- ✅ Security Hub client creation using global mocking strategy
- ✅ Finding creation success/failure scenarios with comprehensive edge cases
- ✅ End-to-end account reassignment flow with graceful degradation testing

### Testing Architecture
- **Global mocking strategy** prevents all AWS API calls (zero cost guarantee)
- **Data-driven SERVICE_MOCK_CONFIGS** for maintainable service simulation
- **ASFF test data standardization** using established patterns
- **Performance target**: <0.1 seconds per test

**📚 Testing Documentation**:
- [../TESTING.md](../TESTING.md): Complete testing architecture and standards
- [tests/README.md](tests/README.md): SOAR-specific testing guide with patterns
- [../CLAUDE.md](../CLAUDE.md): Critical testing rules and anti-patterns

## TDD Development Approach

**✅ Phase 3 Complete - All Steps Accomplished**:
1. ✅ Written comprehensive failing tests for `recreate_asff_finding` with BatchImportFindings
2. ✅ Implemented cross-account Security Hub client creation using SOAR patterns
3. ✅ Implemented proper ASFF finding correction logic with unique ID generation
4. ✅ Added comprehensive AWS API error handling with graceful degradation
5. ✅ Implemented actual BatchImportFindings operation following AWS documentation
6. ✅ Added integration tests for complete end-to-end flow with 100% test coverage

**Production Status**: Account Reassignment Preprocessor is fully implemented and production-ready with all 25 tests passing and zero regressions in the complete SOAR test suite (555/555 tests passing).

**Testing Rules** (see [../TESTING.md](../TESTING.md) for complete details):
- ✅ **ABSOLUTE RULE #1**: NO REAL AWS API CALLS IN TESTS
- ✅ **ABSOLUTE RULE #2**: NO REAL DATA IN TESTS
- ✅ **ABSOLUTE RULE #3**: ALL TESTS MUST ALWAYS PASS
- ✅ **ABSOLUTE RULE #4**: ZERO AWS COSTS DURING TESTING

## Environment Configuration

**Lambda Function**: `AccountReassignmentPreprocessorFunction`
**Environment Variables**:
- `SECURITY_ADM_ACCOUNT`: Security-Adm account ID (111111111111)
- `CROSS_ACCOUNT_ROLE`: Role for cross-account access
- `PRODUCT_NAME`: Product name for finding metadata

**Required Permissions**:
- `securityhub:BatchImportFindings`: Create findings in target accounts
- `organizations:DescribeAccount`: Get account names for logging
- `sts:AssumeRole`: Cross-account access

**📚 Configuration References**:
- [template.yaml](template.yaml): Lambda function configuration and permissions
- [../CLAUDE.md](../CLAUDE.md): OpenSecOps environment and deployment standards