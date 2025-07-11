# SOAR Preprocessing Pipeline Implementation Plan

## CRITICAL IMPLEMENTATION RULES

**⚠️ SECURITY SOFTWARE - NO UNAUTHORIZED CHANGES ⚠️**

**ABSOLUTE RULE**: NEVER rush ahead with implementation without explicit user permission. This is security software and unauthorized changes are STRICTLY FORBIDDEN.

**REQUIRED WORKFLOW**:
1. Complete assigned task ONLY
2. STOP and ask for permission before any additional changes
3. Wait for explicit user direction
4. No assumptions about "next logical steps"
5. No "helpful" additional modifications

**VIOLATION = CRITICAL SECURITY FAILURE**

## CRITICAL REGRESSION ANALYSIS

**REGRESSION INCIDENT**: Health Reclassifier was incorrectly added to state machine, breaking stable ASFF handling logic for clients globally.

**ROOT CAUSE**: 
- Original stable structure: `Setup, Get Ticket and Decide → Branch on Decision`
- Incorrect implementation added Health Reclassifier with race condition logic
- Health Reclassifier ran before decisions were properly routed, causing workflow failures
- All complex workflows (`failed_control`, `incident`, `close_ticket`) were affected

**IMPACT**: 
- Global client deployments with dysfunctional ASFF processing
- Security findings not properly routed or processed
- Production security workflows broken

**RESOLUTION**:
- Reverted to stable baseline structure
- Reintroduced Health Reclassifier in targeted location (incident workflow only)
- Eliminated race conditions through proper positioning

## MANDATORY TESTING REQUIREMENTS

**ABSOLUTE REQUIREMENT**: Comprehensive state machine tests to prevent future regressions.

**Required Test Coverage**:
1. **State machine flow tests** - verify each decision path routes correctly
2. **Integration tests** - end-to-end workflow validation for all decision types  
3. **Regression tests** - prevent structural changes from breaking existing flows
4. **Health Reclassifier tests** - verify targeted insertion doesn't affect other workflows
5. **Termination flag tests** - verify proper execution ending when terminate_for_reprocessing is set

**Test Implementation Strategy**:
- Mock all Lambda functions and external dependencies
- Test each ASFF_decision path independently
- Verify account data retrieval happens at correct points
- Validate no cross-workflow interference
- Automated tests must run before any state machine deployment

**FAILURE PREVENTION**: These tests must be implemented before any future preprocessing additions.

## Project Overview

### Problem Statement
AWS Security Hub delegated administration architecture creates account routing mismatches for certain security services (IAM Access Analyzer, GuardDuty, Inspector, Detective). These services generate findings that appear to originate from the Security-Adm account but actually concern resources in member accounts.

### Solution Architecture
**CRITICAL DISCOVERY**: AWS `BatchUpdateFindings` API cannot modify the `AwsAccountId` field - it is immutable. The original mutation-and-consolidation approach is not viable for account routing correction.

**ARCHITECTURAL EVOLUTION**: The create-and-suppress pattern represents an evolution from the documented mutation approach, necessitated by AWS API constraints. This is not a deviation from architecture - it's an adaptation to technical reality.

**NEW APPROACH**: Create new finding + suppress original + terminate pattern:
1. Detects findings requiring account routing correction
2. Creates new ASFF finding in correct account using `BatchImportFindings`
3. Suppresses original finding in Security-Adm account using `BatchUpdateFindings`
4. Sets termination flag to prevent further processing of original finding
5. New finding triggers fresh SOAR processing naturally through Security Hub event flow

### Key Architectural Pattern
- **Create new finding in correct account** → **Suppress original finding** → **Set termination flag** → **Terminate current processing**
- **New finding triggers fresh SOAR processing** naturally through Security Hub event flow
- This follows the proven pattern established by other SOAR components that create cross-account findings
- **No in-memory mutation required** - we create a completely new finding rather than modifying existing one
- **Similar to Health Reclassifier pattern** - both set termination flag to prevent further processing, but Health modifies while Account creates new

### Architectural Rationale
This approach is justified because:
1. **AWS API Constraints**: `AwsAccountId` field is immutable via `BatchUpdateFindings`
2. **Business Objective**: Getting the right information to the right team is more important than maintaining single finding lifecycle
3. **Operational Environment**: Full permissions environment eliminates cross-account permission complexity
4. **Graceful Degradation**: Failures result in status quo (finding stays in Security-Adm) rather than system breakage
5. **Proven Pattern**: Multiple existing SOAR components already use cross-account `BatchImportFindings` operations

## Implementation Strategy

**MAJOR COURSE CHANGE**: After discovering AWS BatchUpdateFindings limitations and examining existing SOAR components, the approach is completely different:

### Single Phase Implementation
**Goal**: Implement Account Routing Preprocessor with create + suppress pattern

1. **Create Account Routing Preprocessor Lambda**
   - Implement account routing detection logic
   - Extract resource account from ResourceOwnerAccount field or ARN parsing
   - **Create new finding** in correct account using `BatchImportFindings`
   - **Suppress original finding** in Security-Adm using `BatchUpdateFindings`
   - Set termination flag to prevent further processing of original

2. **Insert Account Routing Preprocessor into State Machine**
   - Add after AWS Health Reclassifier (keep existing health logic unchanged)
   - Add before GetAccountData step

3. **Update Lambda Permissions**
   - Add `securityhub:BatchImportFindings` permission (following pattern from other repos)
   - Keep existing `securityhub:BatchUpdateFindings` permission
   - Add cross-account role assumption capabilities

4. **Verify Complete Implementation**
   - Test account routing correction with create + suppress pattern
   - Ensure no regression in existing functionality
   - Verify new finding processed correctly in target account

### AWS Health Reclassifier Status
- ✅ **Health Reclassifier reintroduced** in targeted location within incident workflow only
- ✅ **Positioned between Get Account Data For Incident and Handle Incident**
- ✅ **Single termination check** after Health Reclassifier prevents race conditions
- **Health Reclassifier pattern**: Modify finding → Set termination flag → End execution if terminated
- **Account Routing pattern** (future): Create new finding → Suppress original → Set termination flag → End execution if terminated
- Each preprocessor handles its own Security Hub operations independently
- Different types of corrections require different approaches:
  - **Health corrections**: Use `BatchUpdateFindings` to modify severity (field is mutable), terminate current execution, reprocessing triggered by Security Hub event
  - **Account routing corrections**: Use `BatchImportFindings` + `BatchUpdateFindings` (AwsAccountId is immutable), new finding triggers fresh processing

### Architectural Consistency
Both approaches serve the same business objective through different technical means:
- **Health Reclassifier** (implemented): Modifies severity via `BatchUpdateFindings`, sets termination flag, ends current execution, reprocessing triggered by Security Hub event
- **Account Routing Preprocessor** (future): Creates new finding via `BatchImportFindings`, suppresses original via `BatchUpdateFindings`, sets termination flag, ends current execution
- **Common Pattern**: Both set termination flag to immediately end current execution thread
- **Fresh Processing**: Both trigger new SOAR processing (Health: reprocessing modified finding via Security Hub event, Account: processing new finding via Security Hub event)

### Processing Flow Logic (Current Implementation)
**Current Incident Workflow:**
1. **Setup, Get Ticket and Decide** - makes initial routing decision (`'incident'`)
2. **Get Account Data For Incident** - retrieves account metadata  
3. **AWS Health Reclassifier** - processes Health-related severity corrections (incidents only)
4. **Should Terminate After Health?** - immediate termination check for Health processing
5. **Handle Incident** - continues with incident processing only if not terminated

**Key Implementation Details:**
- **Targeted scope**: Health Reclassifier only runs for incidents (where Health issues actually occur)
- **Clean termination**: If Health Reclassifier sets `terminate_for_reprocessing`, execution ends immediately  
- **No cross-workflow impact**: Controls and ticket closing workflows remain untouched
- **Race condition eliminated**: Health processing happens at the correct point in incident workflow
- **Future extensible**: Account Routing Preprocessor can be added similarly to other workflows

**Critical Principle**: **Health Reclassifier positioned after account data retrieval ensures all necessary context is available for processing**

## Test Data

### Test Fixtures Location
`/Users/pjotr/ProjectCode/AWS/OPENSECOPS-DEV/SOAR/tests/fixtures/preprocessing_test_data.py`

### Available Test Cases

#### 1. `get_guardduty_finding_no_correction()`
- **Type**: GuardDuty finding
- **Account**: 111111111111 (Security-Adm)
- **Resource**: IAM Access Key in same account
- **Expected**: No correction needed (resource account matches finding account)

#### 2. `get_access_analyzer_finding_needs_correction_1()`
- **Type**: IAM Access Analyzer - UnusedIAMRole
- **Account**: 111111111111 (Security-Adm)
- **Resource**: IAM Role in account 222222222222
- **ResourceOwnerAccount**: 222222222222
- **Expected**: Correction needed (AwsAccountId should be 222222222222)

#### 3. `get_access_analyzer_finding_needs_correction_2()`
- **Type**: IAM Access Analyzer - External Access
- **Account**: 111111111111 (Security-Adm)
- **Resource**: IAM Role in account 333333333333
- **ResourceOwnerAccount**: 333333333333
- **Expected**: Correction needed (AwsAccountId should be 333333333333)

#### 4. `get_access_analyzer_finding_needs_correction_3()`
- **Type**: IAM Access Analyzer - External Access
- **Account**: 111111111111 (Security-Adm)
- **Resource**: IAM Role in account 444444444444
- **ResourceOwnerAccount**: 444444444444
- **Expected**: Correction needed (AwsAccountId should be 444444444444)

### Scratchpad Structure
All test fixtures include complete scratchpad structure with:
- SOAREnabled, DeferIncidents, DeferAutoRemediations, DeferTeamFixes, DiskForensicsInvoke
- `account: {}` (empty - populated after preprocessing)
- `finding: {}` (complete ASFF finding)
- `tags: {}`, `actions: {}`, `messages: {}`, `db: {tickets: {}}`
- `ASFF_decision` and `ASFF_decision_reason`

## Detailed TDD Test Plan

### Account Routing Preprocessor Lambda Tests

#### Test 1: `test_should_correct_account_routing_guardduty_no_correction`
- **Given**: GuardDuty finding where resource account matches finding account
- **When**: Call `should_correct_account_routing(scratchpad)`
- **Then**: Should return `False` (no correction needed)
- **Fixture**: `get_guardduty_finding_no_correction()`

#### Test 2: `test_should_correct_account_routing_access_analyzer_needs_correction`
- **Given**: IAM Access Analyzer finding where ResourceOwnerAccount differs from AwsAccountId
- **When**: Call `should_correct_account_routing(scratchpad)`
- **Then**: Should return `True` (correction needed)
- **Fixture**: `get_access_analyzer_finding_needs_correction_1()`

#### Test 3: `test_extract_resource_account_from_resource_owner_account_field`
- **Given**: Finding with ProductFields.ResourceOwnerAccount
- **When**: Call `extract_resource_account(finding)`
- **Then**: Should return the ResourceOwnerAccount value
- **Fixture**: `get_access_analyzer_finding_needs_correction_1()`

#### Test 4: `test_extract_resource_account_from_arn_parsing`
- **Given**: Finding without ResourceOwnerAccount but with resource ARN
- **When**: Call `extract_resource_account(finding)`
- **Then**: Should extract account from ARN
- **Fixture**: Modified version of GuardDuty finding

#### Test 5: `test_extract_resource_account_returns_none_when_unavailable`
- **Given**: Finding with no ResourceOwnerAccount and malformed ARN
- **When**: Call `extract_resource_account(finding)`
- **Then**: Should return `None`
- **Fixture**: Create test data with invalid ARN

#### Test 6: `test_lambda_handler_creates_new_finding_suppresses_original_and_terminates`
- **Given**: Scratchpad with finding needing correction
- **When**: Call `lambda_handler(scratchpad, context)`
- **Then**: Should create new finding in target account, suppress original, and set termination flag
- **Fixture**: `get_access_analyzer_finding_needs_correction_1()`
- **Mocks**: Security Hub clients for both create and suppress operations
- **Verify**: `terminate_for_reprocessing` flag is set to `True`

#### Test 7: `test_lambda_handler_no_correction_needed`
- **Given**: Scratchpad with finding not needing correction
- **When**: Call `lambda_handler(scratchpad, context)`
- **Then**: Should return scratchpad unchanged (no termination flag set)
- **Fixture**: `get_guardduty_finding_no_correction()`
- **Verify**: `terminate_for_reprocessing` flag is not set or `False`

#### Test 8: `test_lambda_handler_handles_extraction_failure`
- **Given**: Scratchpad with finding where account extraction fails
- **When**: Call `lambda_handler(scratchpad, context)`
- **Then**: Should return scratchpad unchanged (graceful failure)
- **Fixture**: Create test data with extraction failure scenario

#### Test 9: `test_lambda_handler_handles_security_hub_create_failure`
- **Given**: Scratchpad with finding needing correction, but BatchImportFindings fails
- **When**: Call `lambda_handler(scratchpad, context)`
- **Then**: Should log error and return scratchpad unchanged (graceful failure)
- **Fixture**: `get_access_analyzer_finding_needs_correction_1()`
- **Mock**: Security Hub client with BatchImportFindings error

#### Test 10: `test_lambda_handler_handles_security_hub_suppress_failure`
- **Given**: Scratchpad with finding needing correction, create succeeds but suppress fails
- **When**: Call `lambda_handler(scratchpad, context)`
- **Then**: Should log error but still set termination flag (new finding created successfully)
- **Fixture**: `get_access_analyzer_finding_needs_correction_1()`
- **Mock**: Security Hub client with BatchUpdateFindings error
- **Verify**: `terminate_for_reprocessing` flag is still set to `True`

## Technical Implementation Details

### Account Routing Detection Logic
```python
def should_correct_account_routing(scratchpad):
    """
    Determine if finding requires account routing correction.
    
    Correction needed when:
    1. ResourceOwnerAccount field exists and differs from AwsAccountId
    2. Resource ARN contains different account than AwsAccountId
    """
    finding = scratchpad['finding']
    finding_account = finding['AwsAccountId']
    resource_account = extract_resource_account(finding)
    
    return resource_account is not None and resource_account != finding_account
```

### Resource Account Extraction
```python
def extract_resource_account(finding):
    """
    Extract the actual resource account from finding.
    
    Priority order:
    1. ProductFields.ResourceOwnerAccount (IAM Access Analyzer)
    2. Parse from first resource ARN
    3. Return None if cannot determine
    """
    # Check ResourceOwnerAccount field first
    resource_owner_account = finding.get('ProductFields', {}).get('ResourceOwnerAccount')
    if resource_owner_account:
        return resource_owner_account
    
    # Parse from resource ARN
    resources = finding.get('Resources', [])
    if resources:
        resource_id = resources[0].get('Id', '')
        # Parse ARN: arn:aws:service:region:account:resource
        if resource_id.startswith('arn:aws:'):
            parts = resource_id.split(':')
            if len(parts) >= 5:
                return parts[4]
    
    return None
```

### Account Routing Preprocessor Pattern
```python
def lambda_handler(scratchpad, context):
    """
    Account routing preprocessor main handler.
    
    Creates new finding in correct account and suppresses original when correction needed.
    """
    if should_correct_account_routing(scratchpad):
        finding = scratchpad['finding']
        resource_account = extract_resource_account(finding)
        
        try:
            # Create new finding in correct account
            create_corrected_finding(finding, resource_account)
            
            # Suppress original finding in Security-Adm
            suppress_original_finding(finding)
            
            # Set termination flag to prevent further processing of original finding
            scratchpad['terminate_for_reprocessing'] = True
            
            print(f"Account routing corrected: {finding['Id']} -> {resource_account}")
            print(f"Original finding suppressed, new finding created, terminating current processing")
            
        except Exception as e:
            print(f"Error correcting account routing: {e}")
            # Return unchanged scratchpad on error (graceful failure)
    
    return scratchpad
```

### Cross-Account Finding Creation Pattern
```python
def create_corrected_finding(original_finding, target_account):
    """
    Create new finding in target account with corrected AwsAccountId.
    
    Follows pattern from SOAR-all-alarms-to-sec-hub and other components.
    """
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

def suppress_original_finding(finding):
    """
    Suppress original finding in Security-Adm account.
    
    Uses existing SOAR pattern for finding suppression.
    """
    # Get Security Hub client for finding's current account
    client = get_client('securityhub', finding['AwsAccountId'])
    
    # Suppress original finding
    response = client.batch_update_findings(
        FindingIdentifiers=[{
            'Id': finding['Id'],
            'ProductArn': finding['ProductArn']
        }],
        Workflow={'Status': 'SUPPRESSED'},
        Note={
            'Text': 'Suppressed - corrected finding created in resource account',
            'UpdatedBy': 'SOAR Account Routing Preprocessor'
        }
    )
    
    if response['UnprocessedFindings']:
        raise Exception(f"Failed to suppress finding: {response['UnprocessedFindings']}")
    
    print(f"Suppressed original finding in Security-Adm")
```

## State Machine Integration

### Current Flow (Problematic - Race Condition)
1. **Setup, Get Ticket and Decide** → (sets ASFF_decision)
2. **AWS Health Reclassifier** → (always runs, may terminate)
3. **Should Terminate for Reprocessing?** → (single termination check)
4. **Branch on Decision** → (processes based on ASFF_decision)

**CRITICAL RACE CONDITION**: Preprocessors run after decisions are made, but suppression happens too late to prevent processing.

### Phase 1 Flow (Two Termination Checks)
1. **Setup, Get Ticket and Decide** → (sets ASFF_decision but doesn't commit to processing)
2. **Should Terminate After Setup?** → (CHECK #1 - immediate termination check)
3. **AWS Health Reclassifier** → (only if continuing)
4. **Should Terminate After Health?** → (CHECK #2 - immediate termination check)
5. **Branch on Decision** → (only if no termination occurred)

**RACE CONDITION FIXED**: Health Reclassifier only runs when appropriate, preventing unnecessary processing.

### Phase 2 Flow (Three Termination Checks - Future)
1. **Setup, Get Ticket and Decide** → (sets ASFF_decision but doesn't commit to processing)
2. **Should Terminate After Setup?** → (CHECK #1 - immediate termination check)
3. **AWS Health Reclassifier** → (only if continuing)
4. **Should Terminate After Health?** → (CHECK #2 - immediate termination check)
5. **Account Routing Preprocessor** → (only if continuing - create + suppress pattern)
6. **Should Terminate After Account Routing?** → (CHECK #3 - immediate termination check) 
7. **Branch on Decision** → (only if no termination occurred)

**COMPLETE RACE CONDITION ELIMINATION**: Each step that can set `terminate_for_reprocessing` is immediately followed by a termination check. No subsequent operations occur on findings that should terminate processing.

## File Structure

### New Files to Create
- `functions/findings/account_routing_preprocessor/app.py`
- `tests/unit/test_account_routing_preprocessor.py`

### Files to Modify
- `statemachines/asff_processor.asl.yaml` (CRITICAL - restructure to eliminate race condition)
- `template.yaml` (add new Lambda function definition with dual Security Hub permissions)

### State Machine Changes Required
**CRITICAL ARCHITECTURAL FIX**: The current state machine has a fundamental race condition where preprocessors run after decisions are made.

**Required Changes:**
1. **Add early termination check** after `Setup, Get Ticket and Decide`
2. **Add conditional checks after each preprocessor** to prevent unnecessary processing
3. **Restructure flow** to prevent race conditions between preprocessing and decision branching

**Phase 1 State Machine Structure:**
```yaml
# Current problematic structure
Setup, Get Ticket and Decide → AWS Health Reclassifier → Should Terminate for Reprocessing? → Branch on Decision

# Phase 1 structure with TWO termination checks
Setup, Get Ticket and Decide → Should Terminate After Setup? → AWS Health Reclassifier → Should Terminate After Health? → Branch on Decision
```

**Phase 1 State Machine Flow:**
```yaml
Setup, Get Ticket and Decide:
    Next: Should Terminate After Setup?

Should Terminate After Setup?:               # CHECK #1
    Type: Choice
    Choices:
        - Variable: $.terminate_for_reprocessing
          BooleanEquals: true
          Next: Do Nothing
    Default: AWS Health Reclassifier

AWS Health Reclassifier:
    Next: Should Terminate After Health?

Should Terminate After Health?:              # CHECK #2
    Type: Choice
    Choices:
        - Variable: $.terminate_for_reprocessing
          BooleanEquals: true
          Next: Do Nothing
    Default: Branch on Decision

Branch on Decision:
    # Existing logic continues...
```

**Phase 2 State Machine Structure (Future):**
```yaml
# Phase 2 structure with THREE termination checks
Setup, Get Ticket and Decide → Should Terminate After Setup? → AWS Health Reclassifier → Should Terminate After Health? → Account Routing Preprocessor → Should Terminate After Account Routing? → Branch on Decision
```

## Environment Variables

### New Environment Variables Needed
- `CROSS_ACCOUNT_ROLE` - Role name for cross-account access (follows existing pattern)
- `PRODUCT_NAME` - Product name for finding metadata (follows existing pattern)
- Any service-specific configuration for account routing detection

## Error Handling Strategy

### Account Routing Preprocessor Function
**CRITICAL REQUIREMENT**: Perfect error handling that never breaks the workflow cycle.

**Error Handling Philosophy**: Graceful degradation - failures result in status quo rather than system breakage.

**Detailed Error Handling**:
- **Should never fail the workflow** - all exceptions must be caught and handled
- **Log errors comprehensively** but continue processing
- **Return scratchpad unchanged on failure** - original finding continues normal processing
- **Graceful handling of cross-account permission issues** (not a concern in full permissions environment)
- **Partial failure handling**: If create succeeds but suppress fails, still set termination flag (new finding was created successfully and will be processed independently)

**Failure Scenarios and Responses**:
1. **Account extraction failure**: Log error, return unchanged scratchpad
2. **Cross-account role assumption failure**: Log error, return unchanged scratchpad  
3. **BatchImportFindings failure**: Log error, return unchanged scratchpad
4. **BatchUpdateFindings failure**: Log error, but still set termination flag if create succeeded
5. **Unknown exceptions**: Catch all, log comprehensively, return unchanged scratchpad

**Worst Case Outcome**: Finding remains in Security-Adm account and gets processed there - system continues functioning, team still gets notified (just not the optimal team).

## Testing Strategy

### Unit Tests
- Follow OpenSecOps testing standards (TESTING.md)
- Use comprehensive mocking (no real AWS calls)
- Test all edge cases and error conditions

### Integration Tests
- Test complete account routing correction flow
- Verify state machine flow with new step
- Test create + suppress pattern across accounts

### Performance Requirements
- Account routing correction should add minimal latency
- Cross-account operations should be efficient
- Follow existing SOAR performance patterns

## Deployment Strategy

### Incremental Deployment (Two Phases)

#### Phase 1: Fix Race Condition (Two Termination Checks)
1. **Add early termination check** after "Setup, Get Ticket and Decide"
2. **Rename existing termination check** to "Should Terminate After Health?"
3. **Update state machine flow** to route through both checks
4. **Deploy and test** to verify race condition is fixed
5. **Verify Health Reclassifier** only runs when appropriate

**Phase 1 Target Structure:**
```
Setup, Get Ticket and Decide → Should Terminate After Setup? → AWS Health Reclassifier → Should Terminate After Health? → Branch on Decision
```

#### Phase 2: Add Account Routing (Three Termination Checks)
1. Deploy account routing preprocessor Lambda with dual Security Hub permissions
2. Add Account Routing Preprocessor step to state machine
3. Add third termination check after Account Routing
4. Verify complete implementation with test cases
5. Monitor for any issues with cross-account operations

**Phase 2 Target Structure:**
```
Setup, Get Ticket and Decide → Should Terminate After Setup? → AWS Health Reclassifier → Should Terminate After Health? → Account Routing Preprocessor → Should Terminate After Account Routing? → Branch on Decision
```

### Incremental Deployment Benefits
- **Validate each step** before adding complexity
- **Isolate issues** to specific changes
- **Maintain system stability** throughout deployment
- **Easier rollback** if issues arise
- **Confidence building** with proven incremental success

## Rollback Plan

### If Implementation Issues
- Remove account routing preprocessor from state machine
- Restore original workflow (minimal changes required)
- Investigate and fix account routing logic
- AWS Health Reclassifier remains unchanged throughout

## Success Criteria

### Implementation Success
- [ ] IAM Access Analyzer findings correctly routed to resource accounts
- [ ] New findings created in target accounts are processed correctly by SOAR
- [ ] Original findings properly suppressed in Security-Adm account
- [ ] GuardDuty findings remain unchanged (no false positives)
- [ ] No regression in existing functionality
- [ ] All tests pass
- [ ] Zero AWS costs during testing

## Response to Architectural Concerns

### Addressing the Mutation vs Create-Suppress Debate

**The documented mutation-and-consolidation pattern is not universally applicable**. It works for mutable fields like severity, but fails for immutable fields like `AwsAccountId`.

**This is not architectural deviation - it's architectural adaptation**. When AWS API constraints prevent the ideal approach, we must adapt while maintaining the same business objectives.

**The create-and-suppress pattern is already proven in the OpenSecOps ecosystem**. Multiple existing components create cross-account findings, demonstrating this is an accepted architectural pattern.

### Permission Complexity Response
**Not a concern in this environment**: Full permissions eliminate cross-account permission complexity concerns.

### Finding Lifecycle Management Response
**Graceful degradation is the correct approach**: If suppression fails after creation succeeds, the new finding still achieves the business objective (correct team gets notified). The orphaned suppressed finding in Security-Adm is irrelevant. **Critical**: The termination flag prevents dual processing - only one version gets processed by SOAR.

### Audit Trail Fragmentation Response
**Business objective over audit aesthetics**: Getting the right information to the right team is more important than maintaining single finding lifecycle. Security teams need actionable information, not perfect audit trails.

## OpenSecOps Component Examples

### Components Using BatchImportFindings
Evidence of existing cross-account finding creation pattern (proving this is accepted architecture):

1. **SOAR-all-alarms-to-sec-hub**
   - Creates CloudWatch alarm findings cross-account
   - Uses `get_client('securityhub', account_id, region)` pattern
   - Permission: `securityhub:BatchImportFindings`

2. **SOAR-detect-log-buckets**
   - Creates S3 log bucket incidents cross-account
   - Uses `get_client('securityhub', account_id)` pattern
   - Permission: `securityhub:BatchImportFindings`

3. **SOAR-detect-stack-drift**
   - Creates stack drift incidents (2 functions)
   - Uses `securityhub:BatchImportFindings` permission
   - Follows established cross-account patterns

4. **SOAR-soc-incident-when-s3-tag-applied**
   - Creates S3 tag-based incidents cross-account
   - Uses `get_client('securityhub', account_id)` pattern
   - Permission: `securityhub:BatchImportFindings`

### Permission Pattern
All components follow the same IAM pattern:
```yaml
Policies:
  - Statement:
      - Sid: AssumeTheRole
        Effect: Allow
        Action:
          - sts:AssumeRole
        Resource: !Sub 'arn:aws:iam::*:role/${CrossAccountRole}'
      - Sid: SecHubPermissions
        Effect: Allow
        Action:
          - securityhub:BatchImportFindings
        Resource: '*'
```

### Account Routing Preprocessor Will Use
```yaml
Policies:
  - Statement:
      - Sid: AssumeTheRole
        Effect: Allow
        Action:
          - sts:AssumeRole
        Resource: !Sub 'arn:aws:iam::*:role/${CrossAccountRole}'
      - Sid: SecHubPermissions
        Effect: Allow
        Action:
          - securityhub:BatchImportFindings  # Create new finding
          - securityhub:BatchUpdateFindings  # Suppress original
        Resource: '*'
```

## Current Status

### Completed
- [x] Test fixtures created with complete scratchpad structure
- [x] Problem analysis and solution architecture defined
- [x] Implementation plan documented
- [x] AWS BatchUpdateFindings limitation discovered (AwsAccountId immutable)
- [x] Alternative create + suppress pattern identified
- [x] OpenSecOps cross-account finding creation patterns analyzed
- [x] Permission requirements and IAM patterns defined
- [x] Architectural concerns addressed and rationale documented
- [x] Error handling strategy defined for perfect workflow reliability
- [x] **CRITICAL**: State machine race condition identified and solution defined

### Current Status

#### Emergency Release Required ⚠️
**CRITICAL**: Global client regression requires immediate release with restored functionality.

**Release Process:**
1. ✅ **State machine regression fixed** - Health Reclassifier properly repositioned
2. **TODO**: Commit state machine changes to preprocessing-pipeline branch (exclude IMPLEMENTATION_PLAN.md)
3. **TODO**: Merge preprocessing-pipeline branch to main 
4. **TODO**: Create emergency release with restored ASFF handling
5. **TODO**: Switch back to preprocessing-pipeline branch
6. **TODO**: Implement comprehensive state machine tests (mandatory before any future changes)
7. **TODO**: Proceed with account routing preprocessor implementation

**CRITICAL NOTE**: IMPLEMENTATION_PLAN.md must remain local only - never committed to git, but preserved throughout all work.

#### State Machine Implementation Complete ✅
1. ✅ **Health Reclassifier completely removed** from state machine
2. ✅ **Reverted to stable baseline structure** that existed before Health Reclassifier was incorrectly added
3. ✅ **Verified against multiple git commits** - this structure was stable for a long time
4. ✅ **Analyzed dispatching logic** - confirmed proper routing patterns
5. ✅ **Confirmed separate Get Account Data nodes** - correct architectural decision for clarity
6. ✅ **Health Reclassifier reintroduced in targeted location** - only affects incident workflow
7. ✅ **Single termination check added** - clean termination handling for Health processing

**Current Optimized State Machine Structure:**
```
Setup, Get Ticket and Decide → Branch on Decision
```

**Dispatching Analysis:**
- `'do_nothing'` → Do Nothing (terminal)
- `'suppress_finding'` → Suppress Finding (terminal) 
- `'close_ticket'` → Get Account Data for Closing → [closing workflow]
- `'failed_control'` → Failed Control → Get Account Data For Control → [control workflow]
- `'incident'` → Get Account Data For Incident → **AWS Health Reclassifier → Should Terminate After Health?** → Handle Incident
- Default → Nonexistent Decision (Fail state)

**Key Architectural Insights:**
- All complex workflows require account data first
- Separate Get Account Data nodes maintain clarity (same Lambda, different routing)
- **Health Reclassifier targeted insertion** - only processes incidents (where Health issues actually occur)
- **Single termination check** - if Health Reclassifier sets `terminate_for_reprocessing`, execution ends via Do Nothing
- **No cross-workflow complexity** - controls and ticket closing remain untouched
- **Realistic scope** - Health issues are always incidents, never controls

#### Phase 2 (After Phase 1 Success)
1. Begin TDD implementation of Account Routing Preprocessor
2. Create Lambda function with dual Security Hub permissions
3. Add Account Routing Preprocessor step to state machine
4. Add third termination check after Account Routing
5. Verify complete implementation with test cases
6. Monitor cross-account operations and error handling

### Final Architecture Summary
**This implementation represents an evolution of SOAR architecture, not a deviation**. The create-and-suppress pattern is necessitated by AWS API constraints and proven by existing OpenSecOps components. **CRITICAL**: The state machine race condition fix is essential for system reliability - it affects all preprocessing, not just account routing. The approach prioritizes business objectives (correct team notification) over architectural purity, with perfect error handling ensuring system reliability.