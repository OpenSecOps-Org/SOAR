# Change Log

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
