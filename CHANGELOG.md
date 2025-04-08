# Change Log

## v2.0.1
    * Updated GitHub remote references in publish.zsh script to use only OpenSecOps-Org, removed Delegat-AB
    * Updated comment in get_overdue_tickets from 'DelegatSOAR' to 'OpenSecOpsSOAR'

## v2.0.0
    * Further replacements and parametrisations of the product name. Breaking change of
      dashboard statistics data point naming in CloudWatch, hence the major version upgrade. 
      Nothing will break and no special procedures need to be observed, but these statistics 
      will start to accumulate from scratch again. This should not be critical.

## v1.25.0
    * Upped the version number.

## v1.24.4
    * Parametrised the SOAR product name in the email sending function.

## v1.24.3
    * Updated GitHub organization name from CloudSecOps-Org to OpenSecOps-Org.
    * Updated references to CloudSecOps-Installer to Installer.

## v1.24.2
    * File paths corrected for the new name of the installer.

## v1.24.1
    * Updated LICENSE file to MPL 2.0.

## v1.24.0
    * Again: Updated publish.zsh to support dual-remote publishing to CloudSecOps-Org repositories.

## v1.23.6
    * Updated publish.zsh to support dual-remote publishing to CloudSecOps-Org repositories.

## v1.23.5
    * Fix duplicate logo in Office365 emails by adding Content-Disposition: inline header

## v1.23.4
    * Add comprehensive ticketing system documentation in ticketing README
    * Document ticketing system parity recommendations between Jira and ServiceNow
    * Correct Multi-Account Management section in architecture documentation
    * Improve architecture documentation with accurate account roles and responsibilities

## v1.23.3
    * Enhance error handling in ECR1, KMS4, ELB1, and S32 auto-remediation functions
    * Add specific AWS error code handling for better reliability
    * Improve error diagnostics and feedback in remediation messages
    * Fix string formatting in ELB1 auto-remediation

## v1.23.2
    * Fix RDS4 auto-remediation function to use correct API call for DB instance snapshots
    * Fix string formatting in RDS4 success messages to correctly display snapshot names
    * Fix field name casing in RDS9 to use correct capitalization (DB vs Db) for parameter groups
    * Enhance error handling in RDS6 auto-remediation for IAM role management

## v1.23.1
    * Additional `Fault` added to return code comparisons.

## v1.23.0
    * All RDS autoremediation `*NotFound` code comparisons changed to `*NotFoundFault`.

## v1.22.1
    * The wording of whom to contact for SOAR failures updated; it's now company neutral.

## v1.22.0
    * Precomputing SOAR failure boolean SOARFailure for incidents.
    * Prompts updated to use the new boolean.

## v1.21.1
    * Prompt update for weekly report.

## v1.21.0
    * For Anthropic Claude, removed the top_k parameter. Now only using a temperature of 0.3 which is
      optimal in this context.

## v1.20.1
    * Edge case for recreated S3 log bucket handled.

## v1.20.0
    * Changes to weekly AI report prompts to improve the handling of AWS notification incidents.

## v1.19.1
    * Hourly SecHub enabled controls sync task now handles suspended accounts robustly.

## v1.19.0
    * AWS Bedrock service failures and throttling after the timeout now sends the email without AI enhancements.

## v1.18.2
    * Throttling handled for possibly overloaded Bedrock.

## v1.18.1
    * Added file processing info log message

## v1.18.0
    * AI prompt work to improve the appearance of numbered lists.

## v1.17.3
    * Increased the number of retries for Suppress Findings further.

## v1.17.2
    * When the system is flooded with incidents, for instance after generating CVE vulnerabilities, the
      Suppress Findings lambda can overburden the ASFF update API on AWS. Increased the number of retries
      from 25 to 250, with larger backoff and interval.

## v1.17.1
    * Auto-remediations for ELB.1 and ELB.4 updated to cater for changes in ASFF format for these events.

## v1.17.0
    * Bedrock supported as the (enabled) default. OpenAI is still available.

## v1.16.2
    * Hourly task now handles non-ASCII team names without bombing, using ASCII replacement techniques.

## v1.16.1
    * Auto-remediations now correctly pass DeferTeamFixes back to the calling ASFF processor, 
      so we can decide whether to ticket teams or not.

## v1.16.0
    * Python v3.12.2.
    * `.python-version` file to support `pyenv`.
    * `boto3` version no longer bundled.

## v1.15.1
    * Incidents now included in the penalty calculations. Autoremediations are not included by design,
      as their underlying issues are fixed and not necessarily something that needs attention.

## v1.15.0
    * OpenAI weekly report prompt for the overview section now takes into account the environments
      where issues occurred.

## v1.14.7
    * OpenAI prompts for the weekly report updated to improve comparisons of averages and medians
      for ticket resolution times, to underline that lower numbers are better for tickets, 
      incidents, and autoremediations, and to provide better conclusions as to issue averages.

## v1.14.6
    * SecHub controls sync now correctly handles controls removed by AWS (having no associations to
      any standards any more).

## v1.14.5
    * Added missing dollar sign.

## v1.14.4
    * Passing DiskForensicsInvoke now correct: we set it up in the ASFF processor, then pass it to the
      incident SM.

## v1.14.3
    * Added missing ".$" characters in param passing in ASL.

## v1.14.2
    * Corrected DiskForensicsInvokeArn to DiskForensicsInvoke when calling the incident SM.

## v1.14.1
    * Added missing parameter reference passing in state machine.

## v1.14.0
    * Parametrised the environment names and made them case-insensitive for the 
      calculation of issue severities.

## v1.13.0
    * Added ProductName and GeneratorId to the data stored for an incident in DynamoDB.
      For human interaction and completeness; not required by any programmatic logic.

## v1.12.1
    * Included the ASFF event and the account data in the data sent to Microsoft Sentinel.

## v1.12.0
    * Multi-regional invocation of snapshotter updated. Now, `DiskForensicsInvoke` should
      be either 'Yes' or 'No'. The regional ARN is constructed during the call. This means
      that DiskForensicsInvokeARN no longer is needed and has been removed.

## v1.11.5
    * Modified the severities of a few of the alarms.
    * The name of the weekly AI report is now configurable (`WeeklyReportTitle`).

## v1.11.4
    * Full titles used in ticket emails.
    * Logic to include ISO week numbers in the Weekly AI Report email title.
    * Modified the OpenAI settings slightly (temperature lowered, etc).

## v1.11.3
    * Logging for Sentinel calls improved.

## v1.11.2
    * SNS topic `DelegatSOARExternalCallFailures` now receives messages when external calls fail.
      This includes OpenAI and Microsoft Sentinel.

## v1.11.1
    * The Sentinel call can now fail completely without affecting SOAR operation or generating new incidents.

## v1.11.0
    * Support for Microsoft Sentinel as recipient of all incidents.

## v1.10.2
    * Split the dashboard in two.

## v1.10.1
    * Only running the ASFF processor for a NEW and ACTIVE finding, or when there is an open ticket,
      regardless of state.

## v1.10.0
    * Only running the ASFF processor when Workflow.Status is NEW or there is an open ticket.

## v1.9.17
    * Corrected SUM to MAX aggregation operator where applicable for certain widgets.

## v1.9.16
    * Fully functional, deleting copy of orig script.

## v1.9.15
    * And the last test.

## v1.9.14
    * More tests.

## v1.9.13
    * Testing changes to ./publish script.

## v1.9.12
    * Dashboard layout changes.

## v1.9.11
    * Stat change from Sum to Maximum for some widgets.

## v1.9.10
    * Widgets for auto-remediations and incidents added. Counters updated for new CloudWatch metric dimensions.

## v1.9.9
    * Incident and Auto-Remediation metric data points changed: now works like tickets, i.e. complete data
      emitted every hour.

## v1.9.8
    * Cloudwatch metric data points in four dimensions for incidents and auto-remediations, just like for tickets.

## v1.9.7
    * Y axis adjusted for one widget.

## v1.9.6
    * Widgets for auto-remediations and incidents.

## v1.9.5
    * Cloudwatch metric data points for incidents, autoremediations, and tickets opened and closed.

## v1.9.4
    * Widgets for the new metrics.

## v1.9.3
    * Emitting ticket CloudWatch metrics every hour.

## v1.9.2
    * Dashboard name configurable so it can be used as the default dashboard.

## v1.9.1
    * Added EscalationEmailSeverities.

## v1.9.0
    * Overdue ticket email reminders with escalation address.

## v1.8.3
    * Added AI request timing widget.

## v1.8.2
    * Dashboard widgets for tickets opened and closed.

## v1.8.1
    * Fixed references.

## v1.8.0
    * CloudWatch dashboard for the SOAR.

## v1.7.6
    * Added robustness in `get_ticket_and_decide`.

## v1.7.5
    * ASFF processor refactored for fewer state changes in the vast majority of cases. This should
      halve the AWS Step Functions costs.

## v1.7.4
    * State machine and event renames.
    * Removed the suppression checks for duplicate issues. Not needed anymore.

## v1.7.3
    * Fixed key composition error causing all controls to be suppressed. Active controls per account
      now work as intended.

## v1.7.2
    * Fixed permission for table.

## v1.7.1
    * Recreated Delegat repo.

## v1.7.0
    * Each control failed finding is now checked against the cached set of Security Hub controls active in
      the specific account. This means that all accounts now can have different Security Hub control profiles
      active, to fully support the new centralised configuration in Security Hub.

## v1.6.7
    * Corrected cache emptying bug.

## v1.6.6
    * The DynamoDB table `enabled_controls` now contains the enabled Security Hub controls for each individual
      account. This is maintained through a Step Function executing every three hours.

## v1.6.5
    * Modified weekly AI report prompts.

## v1.6.4
    * Corrected autoremediation count for last week: was always the same as this week.

## v1.6.3
    * Updated a couple of AI prompts.

## v1.6.2
    * New accounts SUPPRESS failed findings rather than defer them - nothing should fail in a new account anyway.

## v1.6.1
    * Converted OpenAI interface code to >v1.0.0. Increased timeout to 600 seconds for non-report calls.

## v1.6.0
    * Added features to defer processing of incidents and auto-remediations.

## v1.5.4
    * Upgraded boto3 to 1.28.33

## v1.5.3
    * Corrected typo.

## v1.5.2
    * Removed EC2.22 local suppression because of its obsolescence.

## v1.5.1
    * Improved initial setup of DynamoDB tables.
    * Bugfix for policy_name local control suppression logic.
    * Prompt engineering to clarify SOAR incidents.

## v1.5.0
    * Added a switch (SOAREnabled) to enable and disable the SOAR functionality.

## v1.4.0
    * Added support for the OpenAI organization parameter.

## v1.3.1
    * Removed now obsolete local control suppressions.

## v1.3.0
    * Renamed `disable_when` to `suppress_when`.

## v1.2.1
    * Local control suppressions now accept 'policy_name' to compare IAM policy names for IAM.21 and similar.

## v1.1.1
    * Team fixes can now be deferred, making the SOAR process only autoremediations and incidents.
      This is sometimes useful during initial setup.

## v1.1.0
    * Updated SOAR to support Security Hub Global Configuration - removed the DynamoDB table for active controls.

## v1.0.3
    * Open-source credits and URLs
    * Fixed installer initial stackset creation.

## v1.0.2
    * Added DynamoDB.SdkClientException where missing.

## v1.0.1
    * `--dry-run` and `--verbose` added to `deploy`.

## v1.0.0
    * First release.
