# SOAR Architecture

This document provides a detailed overview of the Delegat Security Orchestration, Automation, and Response (SOAR) architecture.

## System Overview

Delegat SOAR is a serverless AWS-native security automation platform that processes security findings, automates remediation, manages tickets for manual intervention, and generates AI-powered security reports. The system operates across an AWS Organization, providing centralized security management for all accounts.

## Core Components

### 1. State Machine Workflows

The system is built around AWS Step Functions state machines that orchestrate complex security workflows:

- **ASFF Processor**: Processes AWS Security Finding Format entries from Security Hub
- **Auto-remediation**: Executes automated fixes for common security issues
- **Incidents**: Manages security incident handling and escalation
- **Hourly Tasks**: Performs regular maintenance and monitoring functions
- **Weekly AI Report**: Generates comprehensive security summaries

### 2. Security Finding Processing

When security findings are detected:

1. Findings are normalized and assigned a severity score
2. Penalty scores are calculated based on severity and environment importance
3. Findings are categorized for appropriate handling
4. System determines whether to:
   - Auto-remediate
   - Create a ticket for manual intervention
   - Suppress the finding (based on rules)

### 3. Automated Remediation

The system includes 30+ specialized Lambda functions for remediating specific AWS security findings:

- **EC2**: Security group configurations, unnecessary ports, etc.
- **S3**: Bucket permissions, encryption settings, public access
- **RDS**: Database encryption, snapshot settings, security configurations
- **IAM**: Excessive permissions, policy compliance
- **ELB/ECS/ECR**: Container and load balancer security settings
- **KMS**: Key management and rotation settings
- **DynamoDB**: Encryption and backup settings

Each remediation function follows a pattern of:
1. Validating the finding
2. Implementing the required security fix
3. Reporting the remediation outcome

### 4. Ticketing and Notification System

For issues requiring human intervention:

1. Tickets are created with detailed information
2. Email notifications are sent to appropriate teams
3. Reminder system tracks overdue tickets
4. Resolution process is monitored and recorded

The system uses specialized formatters for different issue types (GuardDuty findings, general compliance issues, etc.).

### 5. Multi-Account Management

SOAR operates across an AWS Organization:

- **Security Account**: Hosts the SOAR application and centralized monitoring
- **Organization Admin Account**: Used for organization-wide operations
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

- **Lambda Functions**: Python 3.12 runtime, organized by security domain
- **DynamoDB**: Stores findings, ticketing data, and configuration
- **EventBridge**: Custom event bus coordinates asynchronous processing
- **Step Functions**: Orchestrates complex workflows
- **Simple Email Service**: Handles notifications
- **IAM Roles**: Manages cross-account permissions

### Data Flow

1. Security findings are ingested from Security Hub and GuardDuty
2. Findings are enriched with account context and severity information
3. Processing logic determines appropriate action paths
4. Actions are executed (remediation, ticketing, suppression)
5. Results are recorded and tracked

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

## Integration Points

- **Security Hub**: Primary source of findings
- **GuardDuty**: Threat detection integration
- **External Ticketing**: Can connect to external systems
- **Microsoft Sentinel**: Optional integration for enterprise SOC environments

## Future Extensibility

The modular architecture allows for:

- Adding new auto-remediation functions
- Integrating additional security services
- Enhancing AI capabilities
- Extending to additional AWS services