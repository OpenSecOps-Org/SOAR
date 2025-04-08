# SOAR Central Processors

This project contains nested state machines for OpenSecOps SOAR. Together, they constitute the central
processors of security data:
  1. `SOARSecHubFindingsProcessor`: The main state machine triggered on ASFF data from Security Hub.
  1. `SOARAttemptAutoRemediation`: Invoked by `SOARSecHubFindingsProcessor` to handle autoremediation of failed controls.
  1. `SOARIncidents`: Invoked by `SOARSecHubFindingsProcessor` to handle incidents.
  1. `SOARWeeklyAIReport`: Invoked by `cron` every Monday morning to create the weekly security report. 

## Deployment

First make sure that your SSO setup is configured with a default profile giving you AWSAdministratorAccess
to your AWS Organizations administrative account. This is necessary as the AWS cross-account role used 
during deployment only can be assumed from that account.

```console
aws sso login
```

Then type:

```console
./deploy
```
