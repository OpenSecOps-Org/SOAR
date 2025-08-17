# SOAR Library Version Management

## Overview

OpenSecOps SOAR uses a **selective version pinning** strategy across its 69 Lambda functions. This approach balances security, stability, and maintainability while leveraging AWS Lambda's managed runtime capabilities.

## Versioning Principles

### 1. Risk-Based Categorization

We pin library versions based on their risk profile and impact on system security and stability:

| Risk Level | Pinning Strategy | Rationale |
|------------|------------------|-----------|
| 🔴 **CRITICAL** | Tight pinning (`>=x.y.z,<x.y+1.0`) | Known security vulnerabilities require specific versions |
| 🟡 **HIGH** | Range pinning (`>=x.y.z,<x+1.0.0`) | External APIs with frequent breaking changes |
| 🟢 **MEDIUM** | Range pinning (`>=x.y.z,<x+1.0.0`) | Parsing libraries with moderate stability risk |
| 🟢 **LOW** | Range pinning (`>=x.y.z,<x+1.0.0`) | Utility libraries with stable APIs |
| ❌ **AWS MANAGED** | No pinning | AWS Lambda runtime provides optimal versions |

### 2. Core Guidelines

- **Security First**: Always pin libraries with known CVEs
- **AWS Integration**: Never pin boto3/botocore - let AWS manage these optimally  
- **API Stability**: Pin external service libraries to prevent breaking changes
- **Selective Approach**: Only pin when there's clear benefit
- **Range Pinning**: Allow patches while blocking major version changes

## Current Library Versions

### Critical Security Libraries

| Library | Version | Used In | Security Notes |
|---------|---------|---------|----------------|
| **requests** | `>=2.32.4,<2.33.0` | AI, Ticketing, Sentinel | CVE-2024-35195 fix |
| **urllib3** | `>=1.26.20,<1.27.0` | AI, Ticketing, Sentinel | CVE-2024-37891 fix |

### External Service APIs

| Library | Version | Used In | Purpose |
|---------|---------|---------|---------|
| **openai** | `>=1.99.0,<2.0.0` | AI Query | Prevents v2 breaking changes |
| **jira** | `>=3.10.0,<4.0.0` | Ticketing | Proven stable integration |

### Parsing & Processing Libraries

| Library | Version | Used In | Purpose |
|---------|---------|---------|---------|
| **beautifulsoup4** | `>=4.13.0,<5.0.0` | AI, Reports | HTML parsing consistency |
| **html2text** | `>=2025.4.0,<2026.0.0` | Email, Reports | HTML to text conversion |
| **pyyaml** | `>=6.0.2,<7.0.0` | Email Templates | YAML processing consistency |

### Data Processing Libraries  

| Library | Version | Used In | Purpose |
|---------|---------|---------|---------|
| **numpy** | `>=1.26.0,<2.0` | Reports | Data analysis |
| **pandas** | `>=2.0.0,<2.4.0` | Reports | Data manipulation |
| **humanize** | `>=4.12.0,<5.0.0` | Reports, Ticketing | Human-readable formatting |

### Utility Libraries

| Library | Version | Used In | Purpose |
|---------|---------|---------|---------|
| **charset_normalizer** | `>=3.4.0,<4.0.0` | Ticketing | Text encoding |
| **python-dateutil** | `>=2.9.0,<3.0.0` | CloudWatch Context | Date parsing |
| **unidecode** | `>=1.3.8,<2.0.0` | Reports | Unicode normalization |

### AWS Managed (Unpinned)

These libraries are managed by the AWS Lambda runtime and should never be pinned:
- **boto3** - AWS SDK
- **botocore** - AWS SDK core  
- **cfnresponse** - CloudFormation response utility

## Function Distribution

### By Library Usage

- **HTTP Libraries**: 6 functions (AI, Ticketing, Sentinel)
- **YAML Processing**: 9 functions (Email formatting)
- **HTML/Text Processing**: 6 functions (AI, Email, Reports)  
- **Data Analysis**: 3 functions (Reports)
- **External APIs**: 3 functions (AI, Ticketing)

### Function Categories

- **AI Functions**: 2 functions using OpenAI, requests, parsing libraries
- **Ticketing Functions**: 5 functions using JIRA, HTTP libraries
- **Email Functions**: 9 functions using YAML processing
- **Report Functions**: 6 functions using data analysis and text processing
- **Auto-remediation Functions**: 39 functions using only AWS managed libraries

## Deployment Architecture

**SAM Build Process**: Resolves and packages all requirements.txt dependencies during build
**AWS Lambda Runtime**: Provides boto3, botocore, and Python standard library
**Function Packages**: Include pinned third-party libraries as specified in requirements.txt

## Maintenance Approach

### Quarterly Reviews

1. **Security Audit**: Scan pinned versions against CVE databases
2. **Version Assessment**: Compare current pins with latest stable releases
3. **Compatibility Testing**: Validate proposed updates against full test suite
4. **Coordinated Updates**: Deploy version changes across all affected functions

### Emergency Security Updates

Critical vulnerabilities trigger immediate version updates with expedited testing and deployment.

### Version Update Process

1. Identify libraries requiring updates
2. Update version constraints in affected requirements.txt files
3. Run `sam build` to verify dependency resolution
4. Execute full test suite to ensure no regressions
5. Deploy and monitor for issues

## Testing Integration

All version changes must pass:
- Complete unit test suite (546+ tests)
- SAM build process for all functions  
- Integration testing for affected services
- No functional regressions in deployed Lambda functions

## Version Syntax Examples

```txt
# Critical security libraries (tight pinning)
requests>=2.32.4,<2.33.0
urllib3>=1.26.20,<1.27.0

# External APIs (major version pinning)
openai>=1.99.0,<2.0.0
jira>=3.10.0,<4.0.0

# Utility libraries (major version pinning)
beautifulsoup4>=4.13.0,<5.0.0
pyyaml>=6.0.2,<7.0.0

# AWS managed libraries (no pinning)
# boto3 - provided by AWS Lambda runtime
# botocore - provided by AWS Lambda runtime
```

## References

- [AWS Lambda Python 3.12 Runtime Documentation](https://docs.aws.amazon.com/lambda/latest/dg/lambda-python.html)
- [Python Security Vulnerabilities Database](https://python-security.readthedocs.io/vulnerabilities.html)
- [OpenSecOps Testing Standards](../TESTING.md)
- [OpenSecOps Development Guidelines](../CLAUDE.md)

---

**Last Updated**: August 17, 2025  
**Next Review**: November 2025