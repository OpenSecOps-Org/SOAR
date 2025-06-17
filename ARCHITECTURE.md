# SOAR Architecture

This document provides a comprehensive technical overview of the OpenSecOps Security Orchestration, Automation, and Response (SOAR) architecture, including detailed workflow analysis, data structures, error handling patterns, and testing strategies.

## System Overview

OpenSecOps SOAR is a serverless AWS-native security automation platform that processes security findings, automates remediation, manages tickets for manual intervention, and generates AI-powered security reports. The system operates across an AWS Organization, providing centralized security management for all accounts.

## Core Architecture Components

### 1. State Machine Workflows

The system is built around AWS Step Functions state machines that orchestrate complex security workflows:

#### SOARASFFProcessor (Main Orchestrator)
- **File**: `statemachines/asff_processor.asl.yaml`
- **Purpose**: Central orchestrator that processes all Security Hub findings
- **Key Functions**: 
  - Sets up standardized "scratchpad" data structure
  - Determines workflow routing (suppress, auto-remediate, incident, ticket)
  - Manages Security Hub finding status updates
  - Handles email notifications and ticket management

#### SOARAutoRemediations
- **File**: `statemachines/autoremediations.asl.yaml`
- **Purpose**: Executes automated fixes for 30+ security controls
- **Coverage**: EC2, S3, RDS, IAM, ELB, ECS, ECR, KMS, DynamoDB
- **Status**: 100% tested (30/30 functions, 428 tests)

#### SOARIncidents
- **File**: `statemachines/incidents.asl.yaml`
- **Purpose**: Handles security incidents requiring immediate response
- **Capabilities**: 
  - GuardDuty finding processing (EC2, IAM, S3, EKS)
  - Instance termination and forensic data collection
  - Incident classification and escalation

#### SOARSyncEnabledControlsTable
- **File**: `statemachines/sync_enabled_controls_table.asl.yaml`
- **Purpose**: Synchronizes enabled security controls across accounts

#### SOARHourlyTasks
- **File**: `statemachines/hourly_tasks.asl.yaml`
- **Purpose**: Performs hourly maintenance tasks including overdue ticket processing

#### SOARWeeklyAIReport
- **File**: `statemachines/weekly_ai_report.asl.yaml`
- **Purpose**: Generates AI-powered weekly security reports

### 2. Standard Data Structure (Scratchpad)

All functions operate on a standardized data structure established by the ASFF Processor:

```json
{
  "account": {},              // Account metadata from GetAccountDataFunction
  "finding": {},              // Complete ASFF Security Hub finding data
  "tags": {},                 // Resource tags for context
  "actions": {               // Control flags set by processing functions
    "suppress_finding": false,
    "autoremediation_not_done": false,
    "reconsider_later": false
  },
  "messages": {              // Communication templates
    "actions_taken": "None.",
    "actions_required": "...",
    "ai": {
      "plaintext": "",
      "html": ""
    }
  },
  "db": {}                   // DynamoDB lookup results and cached data
}
```

### 3. Error Handling and Retry Patterns

The system implements consistent error handling across all state machines:

#### Standard Retry Configuration
- **Interval**: 3 seconds
- **Backoff Rate**: 3.0 (exponential backoff)
- **Max Attempts**: 10-100 (varies by function criticality)

#### Error Type Handling
- **Lambda.ServiceException**: Standard retry with exponential backoff
- **Lambda.AWSLambdaException**: Extended retry for AWS service issues
- **DynamoDB.ProvisionedThroughputExceededException**: Specialized retry for database throttling
- **States.TaskFailed**: Catch-all for general task failures
- **States.ALL**: Comprehensive catch-all for any unhandled exceptions

#### Fallback-to-Ticketing Error Handling (v2.2.1+)
- **Comprehensive Coverage**: All 30+ autoremediation functions protected by state machine catch-all error handling
- **Centralized Error Handler**: `SetAutoremediationNotDone` state sets `actions.autoremediation_not_done = true` for any unhandled failures
- **Data Preservation**: Pure ASL implementation preserves all original scratchpad data while adding error flag
- **Workflow Integration**: Failed autoremediations automatically route to ticketing system for manual intervention
- **Zero Silent Failures**: Eliminates workflow failures from unhandled Lambda exceptions or API errors

#### AI Function Special Handling
- **Timeout**: 600 seconds (10 minutes)
- **Throttling Protection**: Extended retry intervals
- **Memory Allocation**: Higher memory limits for AI processing

## Function Architecture (76 Total Lambda Functions)

### Auto-Remediation Functions (30 functions - 100% tested)
- **Status**: Complete test coverage (428 tests)
- **Services**: RDS, EC2, S3, IAM, ELB, ECR, ECS, KMS, DynamoDB
- **Pattern**: Standardized ASFF processing with comprehensive error handling
- **Error Resilience**: State machine catch-all error handling ensures 100% fallback-to-ticketing coverage (v2.2.1+)

### Core Workflow Functions (46 functions - Next Testing Priority)

#### Category 1: Core Workflow (5 functions) - CRITICAL
1. **get_ticket_and_decide** - Central decision maker for all workflow routing
2. **get_account_data** - Loads account metadata used throughout system
3. **suppress_finding** - Updates Security Hub finding status to SUPPRESSED
4. **suppress_locally** - Applies local suppression rules
5. **update_remediated_finding** - Marks findings as RESOLVED

#### Category 2: Finding Processing (8 functions) - HIGH PRIORITY
1. **compute_penalty_score** - Risk scoring algorithm
2. **update_ticketed_finding** - Marks findings as NOTIFIED
3. **get_findings_for_account** - Retrieves Security Hub findings
4. **get_findings_for_all_accounts** - Cross-account finding aggregation
5. **get_findings_for_weekly_report** - Report data preparation
6. **get_recent_findings** - Recent activity tracking
7. **get_findings_count** - Statistical counting
8. **get_findings_count_for_account** - Account-specific statistics

#### Category 3: Incident Response (3 functions) - HIGH PRIORITY
1. **determine_type** - Incident classification (EC2, IAM, S3, EKS, Generic)
2. **terminate_instance** - Compromised EC2 instance termination
3. **call_disk_forensics_collection** - Forensic data collection trigger

#### Category 4: Communication (15 functions) - MEDIUM PRIORITY
- Email formatting (9 functions)
- Ticketing system integration (6 functions)

#### Category 5: Reporting & Analytics (15 functions) - MEDIUM PRIORITY
- AI report generation (7 functions)
- Statistics and metrics (4 functions)
- Account management (3 functions)
- System setup (3 functions)

### 4. Security Finding Processing Workflow

When security findings are detected:

1. **Ingestion**: ASFF Processor receives Security Hub findings
2. **Enrichment**: Account data and context added via GetAccountDataFunction
3. **Scoring**: Penalty scores calculated based on severity and environment
4. **Decision**: GetTicketAndDecideFunction determines workflow path:
   - **Auto-remediate**: Route to SOARAutoRemediations state machine
   - **Incident Response**: Route to SOARIncidents state machine
   - **Manual Intervention**: Create ticket and notify teams
   - **Suppress**: Apply suppression rules and update finding status
5. **Execution**: Appropriate actions taken based on decision
6. **Tracking**: Results recorded in DynamoDB and Security Hub updated

### 5. Automated Remediation Architecture

The system includes 30 specialized Lambda functions for remediating specific AWS security controls:

#### Service Coverage
- **RDS** (9 controls): Database encryption, snapshot settings, security configurations
- **EC2** (6 controls): Security group configurations, unnecessary ports, instance settings
- **S3** (5 controls): Bucket permissions, encryption settings, public access
- **IAM** (3 controls): Excessive permissions, policy compliance
- **ELB** (2 controls): Load balancer security settings
- **ECR** (2 controls): Container registry security
- **ECS** (1 control): Container service security
- **KMS** (1 control): Key management settings
- **DynamoDB** (1 control): Database encryption

#### Standardized Remediation Pattern
1. **ASFF Validation**: Verify finding format and required fields
2. **Resource Validation**: Confirm resource exists and is accessible
3. **Cross-Account Access**: Assume appropriate role in target account
4. **Remediation Logic**: Implement AWS-specific security fix
5. **Verification**: Confirm remediation was successful
6. **Response Formatting**: Return standardized success/failure response
7. **Error Handling**: Comprehensive error catching and reporting

#### Lambda Layer Architecture
- **aws_utils Layer**: Cross-account client creation and AWS service utilities
- **rds_remediation Layer**: Specialized RDS remediation functions
- **Shared Dependencies**: Common libraries and utilities across functions

### 4. Ticketing and Notification System

For issues requiring human intervention:

1. Tickets are created with detailed information
2. Email notifications are sent to appropriate teams
3. Reminder system tracks overdue tickets
4. Resolution process is monitored and recorded

The system uses specialized formatters for different issue types (GuardDuty findings, general compliance issues, etc.).

### 5. Multi-Account Management

SOAR operates across an AWS Organization:

- **Organization Admin Account**: Hosts the SOAR application and centralized security operations
- **Security Account**: Used for managing the security posture and setting security controls
- **Member Accounts**: Where findings are detected and remediated

Cross-account access is managed via IAM roles with least privilege principles.

### 6. AI Integration

AI capabilities enhance the security operations:

- **Weekly Security Reports**: AI-generated analysis of security posture
- **Recommendations**: Contextual security improvement suggestions
- **Incident Analysis**: AI-assisted investigation of security incidents

### 7. Reporting and Analytics

The system maintains historical data for:

- Auto-remediation effectiveness
- Incident trends
- Ticket resolution times
- Account security posture over time

## Technical Architecture

### Serverless Infrastructure

- **Lambda Functions**: 76 total functions, Python 3.12 runtime
  - 30 auto-remediation functions (100% tested)
  - 46 workflow/support functions (next testing target)
- **Lambda Layers**: Shared code libraries for common functionality
- **DynamoDB**: Stores findings, ticketing data, and configuration
- **EventBridge**: Custom event bus coordinates asynchronous processing
- **Step Functions**: 5 state machines orchestrate complex workflows
- **Simple Email Service**: Handles notifications and alerts
- **IAM Roles**: Manages cross-account permissions with least privilege
- **Security Hub**: Central finding repository and status management
- **GuardDuty**: Threat detection and incident generation

### Detailed Data Flow

1. **Finding Ingestion**:
   - Security Hub findings trigger SOARASFFProcessor
   - GuardDuty findings processed through incident workflows
   - EventBridge routes findings to appropriate state machines

2. **Data Enrichment**:
   - GetAccountDataFunction loads account metadata
   - Tags and resource context added to scratchpad
   - Penalty scoring applied based on environment and severity

3. **Decision Processing**:
   - GetTicketAndDecideFunction analyzes finding characteristics
   - Suppression rules evaluated via SuppressLocallyFunction
   - Workflow routing determined (auto-remediate, incident, ticket, suppress)

4. **Action Execution**:
   - Auto-remediation: SOARAutoRemediations state machine
   - Incidents: SOARIncidents state machine with forensics
   - Ticketing: Email notifications and external ticket creation
   - Suppression: Security Hub status update to SUPPRESSED

5. **Result Tracking**:
   - DynamoDB stores all actions and outcomes
   - Security Hub findings updated with resolution status
   - Statistics collected for reporting and analytics

### State Machine Integration Points

#### ASFF Processor → Auto-Remediation
- **Trigger**: `actions.suppress_finding` = false AND auto-remediation applicable
- **Data**: Complete scratchpad with finding and account context
- **Response**: Remediation success/failure status

#### ASFF Processor → Incidents
- **Trigger**: GuardDuty findings or high-severity security events
- **Data**: Incident-specific context and response requirements
- **Response**: Incident handling results and forensic data

#### Cross-State Machine Error Handling
- **Retry Logic**: Consistent 3-second intervals with exponential backoff
- **Error Propagation**: Structured error responses maintain workflow state
- **Fallback Mechanisms**: Graceful degradation when services unavailable

### Deployment Model

- **AWS SAM**: Defines infrastructure as code
- **CloudFormation**: Manages resource provisioning
- **Multi-region**: Supports deployment across regions
- **Versioned Releases**: Tracked via git tags and CHANGELOG

## Security and Compliance Considerations

- **Least Privilege**: Minimal IAM permissions for operations
- **Environment-based Prioritization**: Higher security standards for production
- **Audit Trail**: Records all remediation actions and decisions
- **Cross-account Security**: Controlled access between accounts

## Scalability

- **Serverless Architecture**: Scales with security finding volume
- **Stateless Processing**: Allows horizontal scaling
- **Account Parallelism**: Processes multiple accounts concurrently

## Operational Model

- **Infrastructure as Code**: All resources defined in template.yaml
- **Automated Deployment**: Via deploy script
- **CI/CD Ready**: Structured for pipeline integration
- **Configuration Management**: Via parameters and environment variables

## Event-Driven Architecture Pattern

SOAR follows an established **"API Update → Event Trigger → Reprocessing"** pattern for state transitions:

### Update-and-Reprocess Workflow
1. **State Change**: Lambda function calls Security Hub `batch_update_findings` API
2. **Event Generation**: Security Hub automatically generates new finding event with updated status
3. **Fresh Processing**: SOAR processes the new event with corrected data from the beginning
4. **Clean Logic**: All workflow decisions use the updated finding state

### Established Use Cases
- **Auto-Remediation Completion**: Sets `Workflow.Status: 'RESOLVED'` → Triggers ticket closure workflow
- **Finding Suppression**: Sets `Workflow.Status: 'SUPPRESSED'` → Triggers cleanup actions
- **Severity Reclassification**: Updates `Severity.Label` → Triggers reprocessing with correct severity

### Benefits
- **Consistent Processing**: All workflows use the same updated finding data
- **Audit Trail**: Security Hub maintains complete state change history
- **Downstream Integration**: Other Security Hub consumers see corrected data
- **Loop Prevention**: Updates are unidirectional (e.g., HIGH → INFORMATIONAL only)

This pattern enables the SOAR to maintain clean separation between decision logic and state management while ensuring all systems have consistent, up-to-date finding information.

## Integration Points

- **Security Hub**: Primary source of findings
- **GuardDuty**: Threat detection integration
- **External Ticketing**: Can connect to external systems
- **Microsoft Sentinel**: Optional integration for enterprise SOC environments

## Future Extensibility

The modular architecture allows for:

- **Auto-Remediation Expansion**: Adding new security controls and services
- **Security Service Integration**: Additional AWS security services
- **AI Enhancement**: Advanced threat analysis and response recommendations
- **Custom Playbooks**: Organization-specific incident response procedures
- **Third-Party Integrations**: SIEM, SOAR, and ticketing system connectors

