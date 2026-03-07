# Programmatic Security Controls

This document classifies each MSB security control as **AUTOMATED**, **DETECTIVE**, or **MANUAL** and summarises how it is implemented. Controls are deployed by the CDK stacks in this repository; no separate Lambda deployment or manual configuration step is required after `cdk deploy`.

---

## Control types

| Type | Definition |
|---|---|
| **AUTOMATED** | The control is enforced or configured by the CDK deployment itself, without any human action after deploy. |
| **DETECTIVE** | The control monitors the environment and alerts operators; it does not prevent the event from occurring, but it surfaces it quickly. |
| **MANUAL** | The control cannot be fully automated and requires a human action (e.g., enabling hardware MFA on the root account). |

---

## AUTOMATED Controls

These controls are applied or enforced on every `cdk deploy`. No manual steps are needed after deployment.

### Account Security Contact (CIS 1.18 / FSBP Account.1)

**Stack**: `IAMStack` — `create_security_contact()`

The account SECURITY alternate contact is set via an `AwsCustomResource` that calls `account:PutAlternateContact`. The `on_update` handler is identical to `on_create`, so re-deploying with updated contact details keeps the contact current.

**Prerequisite**: Provide both `--context notification_email=...` and `--context security_contact_phone=...`. If either value is absent, the custom resource is not created. A Security Hub Automation Rule in `SecurityRegionalStack` suppresses the corresponding FSBP Account.1 finding once the contact is set.

### IAM Password Policy (CIS 1.8, 1.9, 1.11-1.14)

**Stack**: `IAMStack`

An `AWS::IAM::AccountPasswordPolicy` CloudFormation resource sets the account password policy: minimum length 16, uppercase, lowercase, symbols, numbers, 24-password reuse prevention. `MaxPasswordAge` is intentionally omitted in line with NIST SP 800-63B and CIS v3.0.0.

### AWS Support Role (CIS 1.17)

**Stack**: `IAMStack`

IAM role `msb-aws-support-role` with `AWSSupportAccess` attached, assumed by `AccountRootPrincipal`.

### IAM Access Analyzer (CIS 1.20)

**Stack**: `IAMStack`

`accessanalyzer.CfnAnalyzer` creates an ACCOUNT-type analyser (`msb-access-analyzer-{account}-{region}`).

### S3 Block Public Access — Account Level (CIS 2.1.2)

**Stack**: `S3SecurityStack`

Custom resource calls `S3Control:PutPublicAccessBlock` with all four settings enabled for the entire account.

### S3 Block Public Access — Bucket Level (CIS 2.1.5)

**Stack**: `S3SecurityStack`

Lambda function (`msb-s3-public-access-checker`) enforces bucket-level public access blocks on all buckets in the account. Triggered daily and on every `CreateBucket` event.

### S3 Object Lock / WORM (FSBP S3.11 / CIS 3.11) — opt-in

**Stack**: `LoggingStack`

Enabled when `--context enable_object_lock=true` (default: off). The central logs bucket is created with Object Lock in Governance mode and a 365-day retention period. This setting must be selected before the first deploy; it cannot be retrofitted to an existing bucket.

### EBS Encryption by Default (CIS 2.2.1)

**Stack**: `KMSStack`

Custom resources call `ec2:EnableEbsEncryptionByDefault` and `ec2:ModifyEbsDefaultKmsKeyId` to point the account-level EBS default to the `msb/ebs-key` KMS key.

### KMS Key Rotation (FSBP KMS.4 / CIS 3.7)

**Stack**: `KMSStack`

Five CMKs are created with `enable_key_rotation=True`: master, CloudTrail, S3, RDS, and EBS keys.

### CloudTrail (FSBP CloudTrail.1-4 / CIS 3.1-3.7)

**Stack**: `LoggingStack`

Multi-region trail `msb-cloudtrail` with KMS encryption, CloudWatch Logs delivery, log file validation, and advanced event selectors for all S3 and Lambda data events.

**Control Tower note**: When `--context control_tower_managed=true`, the MSB trail is skipped and the CT organisation trail's log group is imported instead. The metric filters and alarms below still attach to that log group.

### SNS Delivery Status Logging (FSBP SNS.2)

**Stack**: `NotificationsRegionalStack` (non-global regions) and `LoggingStack` (global region)

The CDK `CfnTopic` escape hatch sets `http_success_feedback_role_arn`, `sqs_success_feedback_role_arn`, and `lambda_success_feedback_role_arn` (plus corresponding failure and sample-rate attributes) on every MSB notifications topic. A dedicated IAM role grants SNS write access to CloudWatch Logs for delivery-status reporting. This satisfies FSBP SNS.2 without any custom resource.

### SNS Topic Encryption (FSBP SNS.1)

**Stack**: `NotificationsRegionalStack` / `LoggingStack`

Each SNS topic is encrypted with a dedicated regional KMS key (`alias/msb-sns-notifications-{region}`).

### AWS Config Recorder and Delivery Channel

**Stack**: `LoggingRegionalStack`

`CfnConfigurationRecorder` (all-supported) and `CfnDeliveryChannel` (6-hour snapshot, writes to `msb-logs-*`) deployed per region.

**Control Tower note**: Skipped when `--context control_tower_managed=true`.

### Security Hub + CIS v3.0.0 + FSBP Standards

**Stack**: `SecurityRegionalStack`

`CfnHub` and two `CfnStandard` resources enable both FSBP v1.0.0 and CIS AWS Foundations Benchmark v3.0.0 per region. Two Automation Rules suppress findings that the MSB already addresses programmatically (Account.1 security contact, root hardware-MFA findings).

**Control Tower note**: Skipped when `--context control_tower_managed=true`.

### GuardDuty with All Protection Plans

**Stack**: `SecurityRegionalStack`

`CfnDetector` with `enable=True`, 15-minute publishing frequency, and all available protection plans (S3, EKS audit logs, EBS malware, RDS login events, Lambda network logs, EKS runtime monitoring, runtime monitoring).

**Control Tower note**: Skipped when `--context control_tower_managed=true`.

### Inspector v2

**Stack**: `SecurityRegionalStack`

Custom resource enables Inspector v2 for EC2, ECR, and Lambda. Findings are forwarded to SNS via EventBridge.

**Control Tower note**: Skipped when `--context control_tower_managed=true`.

### Macie

**Stack**: `SecurityRegionalStack`

`macie.CfnSession` with `FIFTEEN_MINUTES` finding publishing. Findings are forwarded to SNS via EventBridge.

**Control Tower note**: Skipped when `--context control_tower_managed=true`.

### Default Security Group Remediation (CIS 5.4)

**Stack**: `NetworkSecurityStack`

Lambda function (`msb-secure-default-sg`) revokes all ingress rules and any custom egress rules from default security groups across all VPCs. Triggered daily and on every `AuthorizeSecurityGroupIngress`, `AuthorizeSecurityGroupEgress`, and `CreateSecurityGroup` event.

### VPC Flow Logs (FSBP EC2.6 / CIS 3.9)

**Stack**: `NetworkSecurityStack` → `VpcStack`

Flow logs delivered to CloudWatch Logs (`/aws/vpc/flowlogs/{account}/{region}`) with a 1-year retention.

### VPC Endpoints

**Stack**: `VpcStack`

Gateway endpoints for S3 and DynamoDB; interface endpoints for SSM, SSMMessages, EC2Messages, KMS, CloudWatch Logs, CloudWatch Monitoring, SQS, SNS, Secrets Manager, ECR API, ECR Docker, ECS, and Lambda.

### WAFv2 Web ACL — opt-in

**Stack**: `WafStack`

Enabled when `--context enable_waf=true` (default: off). Deploys a Regional Web ACL per target region with five AWS Managed Rule Groups (CommonRuleSet, KnownBadInputsRuleSet, AmazonIpReputationList, AnonymousIpList, SQLiRuleSet) and a rate-limit rule (2000 requests per 5 minutes per IP, action: block). CloudWatch metrics and sampled requests are enabled on all rules. The Web ACL ARN is exported for manual association with ALBs, CloudFront distributions, or API Gateway stages.

### AWS Config Managed Rules

**Stack**: `ComplianceStack`

A comprehensive set of AWS Config managed rules is deployed per region covering encryption, IAM, S3, CloudTrail, networking, Lambda, and SSM. See `docs/control_implementation_details.md` for the full list.

---

## DETECTIVE Controls

These controls monitor the environment and alert on issues. They do not prevent events from occurring, but surface them quickly through CloudWatch alarms and SNS notifications.

### CloudWatch Metric Filter Alarms (CIS 3.1-3.14, 4.4, 4.15-4.16)

**Stack**: `LoggingStack`

Thirteen CloudWatch metric filters and alarms watch the CloudTrail log group and alert on:
- Unauthorized API calls (CIS 3.1)
- Console sign-in without MFA (CIS 3.2)
- CloudTrail configuration changes (CIS 3.5)
- Console authentication failures — threshold 3 (CIS 3.6)
- KMS CMK disabling or scheduled deletion (CIS 3.7)
- S3 bucket policy changes (CIS 3.8)
- AWS Config changes (CIS 3.9)
- Network gateway changes (CIS 3.12)
- Route table changes (CIS 3.13)
- VPC changes (CIS 3.14)
- IAM policy changes (CIS 4.4)
- Security group changes (CIS 4.15)
- Network ACL changes (CIS 4.16)

All alarms notify the `msb-notifications-{region}` SNS topic.

### Root Account Activity Monitoring (CIS 1.7 / FSBP IAM.7)

**Stack**: `SecurityMonitoringStack`

EventBridge rules alert on root account console sign-in and root account API calls.

### Security Group Change Notifications (CIS 5.3)

**Stack**: `SecurityMonitoringStack`

EventBridge rule alerts on `AuthorizeSecurityGroupIngress`, `RevokeSecurityGroupIngress`, `CreateSecurityGroup`, `DeleteSecurityGroup`, and related events.

### GuardDuty Findings Notifications

**Stack**: `SecurityRegionalStack`

EventBridge rule routes `Inspector2 Finding` and `Macie Finding` events to SNS. (GuardDuty findings are also forwarded to SNS via a separate EventBridge rule in `SecurityMonitoringStack`.) These rules remain active even when `control_tower_managed=true`.

### IAM Policy Governance Monitoring (FSBP IAM.16)

**Stack**: `IAMStack`

Lambda function (`msb-iam-policy-checker`) reports on IAM users with directly attached policies. Runs daily and on `AttachUserPolicy` / `PutUserPolicy` events. Reports via SNS.

### Remediation Lambda Error Alarms

**Stack**: `NetworkSecurityStack`, `S3SecurityStack`, `IAMStack`

Three CloudWatch alarms (one per remediation Lambda) fire when any Lambda invocation produces an error. Each alarm routes to the SNS notifications topic so that silent failures in the AUTOMATED remediation controls are surfaced immediately.

| Alarm name | Lambda function |
|---|---|
| `msb-default-sg-remediation-errors-{region}` | `msb-secure-default-sg` |
| `msb-s3-public-access-checker-errors-{region}` | `msb-s3-public-access-checker` |
| `msb-iam-policy-checker-errors-{region}` | `msb-iam-policy-checker` |

Without these alarms a failed Lambda would leave the account unmonitored with no indication of the failure.

### Compliance Dashboard

**Stack**: `ComplianceStack`

CloudWatch dashboard (`MSB-Compliance-Dashboard`) displays `ComplianceByConfigRule` metrics for COMPLIANT and NON_COMPLIANT resources.

---

## MANUAL Controls

These controls require human action and cannot be fully automated by CDK.

### Root Account Hardware MFA (FSBP IAM.4 / IAM.6 / IAM.9)

Physical hardware MFA must be registered to the root account via the AWS console. CDK cannot perform this action. Security Hub Automation Rules in `SecurityRegionalStack` suppress these findings so they do not clutter the posture score after the hardware token has been registered.

### Root Account Password Rotation

The root account password must be rotated manually in the AWS console.

### Root Account Access Key Removal (CIS 1.4 / FSBP IAM.4)

If root access keys exist they must be deleted via the AWS console or CLI. AWS Config rule `IAM_ROOT_ACCESS_KEY_CHECK` monitors for and reports any existing keys.

### MFA for IAM Users (CIS 1.10 / FSBP IAM.5)

Each IAM user must enrol their own MFA device. CDK enforces the password policy and Config reports non-compliant users, but MFA enrolment is a per-user human action.

### WAF Resource Association

After deploying `WafStack` with `--context enable_waf=true`, the Web ACL must be manually associated with ALBs, CloudFront distributions, or API Gateway stages. The Web ACL ARN is exported as `MSB-WAF-WebACLArn-{region}` to make this step straightforward.

---

## Control Tower Compatibility

When `--context control_tower_managed=true` is passed, the following stacks skip resource creation because Control Tower already manages these services at the Organisation level:

| Skipped resource | Reason |
|---|---|
| MSB CloudTrail (`msb-cloudtrail`) | CT deploys an organisation trail |
| Config recorder and delivery channel | CT deploys a recorder per region |
| GuardDuty detector | CT enables GuardDuty organisation-wide |
| Security Hub + standards | CT enables Security Hub organisation-wide |
| Inspector v2 | CT enables Inspector at the organisation level |
| Macie session | CT enables Macie at the organisation level |

All other controls (password policy, security contact, S3 block public access, EBS encryption, remediation Lambdas, CloudWatch metric filters, WAF, etc.) are deployed regardless of this flag.

The CloudTrail log group name used by metric filters defaults to `aws-controltower/CloudTrailLogs` in CT mode. Override this with `--context cloudtrail_log_group_name=<name>` if your CT trail uses a different log group.

---

## Implementation Strategy

All controls in this repository are implemented directly in CDK Python stacks. No separate Lambda packaging or manual resource creation steps are required after `cdk deploy`. The recommended deployment flow is:

1. Bootstrap the CDK toolkit in the target account and regions.
2. Set context variables (email, phone, optional flags) either in `cdk.json` or on the command line.
3. Run `cdk deploy --all` (or `cdk deploy --context target=global` then `cdk deploy --context target=regional` to sequence global and regional stacks).
4. Confirm the SNS email subscription in each deployed region.
5. Register hardware MFA on the root account (MANUAL).
6. Associate the WAF Web ACL with any applicable resources if WAF was enabled (MANUAL).
