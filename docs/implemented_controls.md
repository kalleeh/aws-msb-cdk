# Implemented Security Controls

This document lists the security controls that have been implemented in the MSB CDK project, along with their implementation details and test coverage. Controls marked PARTIAL are deployed by the codebase but require an opt-in flag or a post-deploy step to be fully effective.

---

## IAM Password Policy — CIS 1.8, 1.9, 1.11–1.14 / FSBP IAM.9 / SSB IAM.1

**Status**: IMPLEMENTED

**Implementation** (`IAMStack.create_password_policy`):
- `AWS::IAM::AccountPasswordPolicy` with `MinimumPasswordLength=16`, `RequireUppercaseCharacters`, `RequireLowercaseCharacters`, `RequireSymbols`, `RequireNumbers`, `PasswordReusePrevention=24`.
- `MaxPasswordAge` is intentionally omitted per NIST SP 800-63B (periodic expiration increases risk through predictable rotation patterns).

---

## AWS Support Role — CIS 1.17

**Status**: IMPLEMENTED

**Implementation** (`IAMStack.create_password_policy`):
- IAM role `msb-aws-support-role` with the `AWSSupportAccess` managed policy, assumed by the account root principal.
- Ensures a designated role exists for incident management with AWS Support.

---

## Security Contact — CIS 1.18 / FSBP Account.1

**Status**: IMPLEMENTED

**Implementation** (`IAMStack.create_security_contact`):
- Custom Resource calls `account:PutAlternateContact` with `AlternateContactType=SECURITY`, using `notification_email` and `security_contact_phone` context values.
- Activated when both values are provided at deploy time.
- A Security Hub Automation Rule in `SecurityRegionalStack` suppresses the Account.1 finding after the contact is set.

---

## IAM Access Analyzer — CIS 1.20 / FSBP IAM.8 / SSB IAM.6

**Status**: IMPLEMENTED

**Implementation** (`IAMStack.create_access_analyzer`):
- `AWS::AccessAnalyzer::Analyzer` of type `ACCOUNT` named `msb-access-analyzer-{account}-{region}`.
- Continuously monitors resource-based policies for external access.

---

## IAM Policy Governance Monitoring — FSBP IAM.16

**Status**: IMPLEMENTED

**Implementation** (`IAMStack.create_iam_policy_checker`):
- Lambda function `msb-iam-policy-checker` (Python 3.13) calls `iam:ListUsers`, `iam:ListUserPolicies`, and `iam:ListAttachedUserPolicies`.
- Runs on a daily EventBridge schedule and is also triggered on `AttachUserPolicy` and `PutUserPolicy` events.
- Publishes findings to the MSB SNS topic.
- CloudWatch alarm `msb-iam-policy-checker-errors-{region}` fires on any Lambda error so silent failures are surfaced.

---

## CloudTrail (Multi-Region, Encrypted, Validated) — CIS 3.1, 3.2, 3.5 / FSBP CloudTrail.1, CloudTrail.2, CloudTrail.4, CloudTrail.5, CloudTrail.7 / SSB LOG.1–LOG.4

**Status**: IMPLEMENTED

**Implementation** (`LoggingStack`):
- Trail `msb-cloudtrail` is multi-region with global service events, KMS encryption (dedicated CloudTrail CMK), log file validation, and CloudWatch Logs delivery with 1-year retention.
- Advanced event selectors capture all S3 object and Lambda function data events.
- Skipped when `control_tower_managed=True` — Control Tower's organization trail is used instead; the stack imports its CloudWatch log group for metric filters.

---

## CloudWatch Metric Filter Alarms (13 alarms) — CIS 3.x / 4.x / FSBP CloudWatch.2

**Status**: IMPLEMENTED

**Implementation** (`LoggingStack`):
All filters attach to the CloudTrail log group and each has an SNS-connected CloudWatch alarm:

| # | Alarm Name | CIS |
|---|-----------|-----|
| 1 | MSB-UnauthorizedAPICalls | 3.1 |
| 2 | MSB-ConsoleSignInWithoutMFA | 3.2 |
| 3 | MSB-CloudTrailConfigChanges | 3.5 |
| 4 | MSB-ConsoleAuthFailures (threshold: 3) | 3.6 |
| 5 | MSB-KMSKeyChanges | 3.7 |
| 6 | MSB-S3BucketPolicyChanges | 3.8 |
| 7 | MSB-AWSConfigChanges | 3.9 |
| 8 | MSB-NetworkGatewayChanges | 3.12 |
| 9 | MSB-RouteTableChanges | 3.13 |
| 10 | MSB-VPCChanges | 3.14 |
| 11 | MSB-IAMPolicyChanges | 4.4 |
| 12 | MSB-SecurityGroupChanges | 4.15 |
| 13 | MSB-NACLChanges | 4.16 |

---

## AWS Config Recorder and Delivery Channel — CIS 3.5 / FSBP Config.1 / SSB LOG.6

**Status**: IMPLEMENTED

**Implementation** (`LoggingRegionalStack`):
- `CfnConfigurationRecorder` records all supported resource types.
- `CfnDeliveryChannel` delivers snapshots to the MSB logs S3 bucket every six hours.
- Skipped when `control_tower_managed=True`.
- CloudWatch log groups for Config and VPC Flow Logs are always created.

---

## GuardDuty Enabled (All Protection Features) — CIS 3.8 / FSBP GuardDuty.1 / SSB LOG.7

**Status**: IMPLEMENTED

**Implementation** (`SecurityRegionalStack`):
- `CfnDetector` enabled with 15-minute finding publication and all available protection features:
  - S3_DATA_EVENTS
  - EKS_AUDIT_LOGS
  - EBS_MALWARE_PROTECTION (EC2_AGENT_MANAGEMENT)
  - RDS_LOGIN_EVENTS
  - LAMBDA_NETWORK_LOGS
  - EKS_RUNTIME_MONITORING (EKS_ADDON_MANAGEMENT)
  - RUNTIME_MONITORING (EC2_AGENT_MANAGEMENT, EKS_ADDON_MANAGEMENT, FARGATE_AGENT_MANAGEMENT)
- Findings are exported to `msb-guardduty-findings-{account}-{region}` (see GuardDuty Findings Bucket below).
- Skipped when `control_tower_managed=True`.

---

## GuardDuty Findings Bucket with Server Access Logs — FSBP S3.9 / CIS 3.6

**Status**: IMPLEMENTED

**Implementation** (`SecurityRegionalStack`):
- Dedicated bucket `msb-guardduty-findings-{account}-{region}`: versioned, BLOCK_ALL public access, HTTPS-only, Intelligent-Tiering lifecycle at 30 days, 365-day expiration, RETAIN.
- Dedicated access-logs bucket `msb-guardduty-access-logs-{account}-{region}` set as `server_access_logs_bucket` with prefix `guardduty-findings/`.

---

## Security Hub (FSBP + CIS v3.0.0) — CIS 3.10 / FSBP SecurityHub.1 / SSB LOG.8

**Status**: IMPLEMENTED

**Implementation** (`SecurityRegionalStack`):
- `CfnHub` with two standards enabled:
  - AWS Foundational Security Best Practices v1.0.0
  - CIS AWS Foundations Benchmark v3.0.0
- Two Automation Rules suppress findings that require manual action:
  - `MSB-Suppress-ManualControls-AccountContact` — suppresses Account.1 findings once the security contact is set programmatically.
  - `MSB-Suppress-ManualControls-RootMFA` — suppresses IAM.4/IAM.6/IAM.9 root hardware-MFA findings (cannot be automated).
- Skipped when `control_tower_managed=True`.

---

## Inspector v2 Enabled — FSBP Inspector.1

**Status**: IMPLEMENTED

**Implementation** (`SecurityRegionalStack`):
- Custom Resource calls `inspector2:Enable` for EC2, ECR, and Lambda resource types.
- EventBridge rule `msb-inspector-findings-{region}` routes Inspector findings to the MSB SNS topic.
- Skipped when `control_tower_managed=True`.

---

## Macie Enabled — FSBP Macie.1

**Status**: IMPLEMENTED

**Implementation** (`SecurityRegionalStack`):
- `CfnSession` with 15-minute finding publishing frequency and `ENABLED` status.
- EventBridge rule `msb-macie-findings-{region}` routes Macie findings to the MSB SNS topic.
- Skipped when `control_tower_managed=True`.

---

## SNS Delivery Status Logging — FSBP SNS.2

**Status**: IMPLEMENTED

**Implementation** (`NotificationsRegionalStack`, `LoggingStack`):
- IAM role for SNS with CloudWatch Logs write permissions attached to each MSB notifications topic.
- HTTP/S success and failure feedback role ARNs, SQS success and failure feedback role ARNs, and Lambda success and failure feedback role ARNs are all set with 100% sample rate on the `CfnTopic` resource.

---

## Regional SNS Notification Topic (KMS-Encrypted) — FSBP SNS.1, SNS.2 / SSB IR.1

**Status**: IMPLEMENTED

**Implementation** (`NotificationsRegionalStack`):
- One KMS-encrypted SNS topic (`msb-notifications-{region}`) per deployed region.
- Dedicated regional KMS key (`alias/msb-sns-notifications-{region}`) with rotation enabled.
- Email subscription for the operator notification address.
- SNS delivery status logging enabled (see SNS.2 above).

---

## S3 Block Public Access (Account Level) — CIS 2.1.2 / FSBP S3.1, S3.2 / SSB DAT.1

**Status**: IMPLEMENTED

**Implementation** (`S3SecurityStack`):
- Custom Resource calls `s3:PutAccountPublicAccessBlock` with all four flags (`BlockPublicAcls`, `BlockPublicPolicy`, `IgnorePublicAcls`, `RestrictPublicBuckets`) set to `True`.

---

## S3 Bucket-Level Public Access Enforcement — CIS 2.1.5 / FSBP S3.1, S3.2 / SSB DAT.1

**Status**: IMPLEMENTED

**Implementation** (`S3SecurityStack.create_bucket_public_access_checker`):
- Lambda `msb-s3-public-access-checker` (Python 3.13) calls `s3:GetBucketPublicAccessBlock` and `s3:PutBucketPublicAccessBlock` on every bucket in the account.
- Runs on a daily EventBridge schedule and on `CreateBucket` events.
- Publishes enforcement results to the MSB SNS topic.
- CloudWatch alarm `msb-s3-public-access-checker-errors-{region}` fires on any Lambda error.

---

## S3 Object Lock (Opt-In) — FSBP S3.11

**Status**: PARTIAL — requires `enable_object_lock=True` at deploy time

**Implementation** (`LoggingStack`):
- `object_lock_enabled` parameter passed to the CloudTrail logs bucket at creation time.
- When `True`: Governance mode with 365-day default retention.
- Config rule `S3_BUCKET_OBJECT_LOCK_ENABLED` in `ComplianceStack` detects non-compliant buckets regardless of the flag.

---

## KMS CMK Creation and Key Rotation — FSBP KMS.4 / SSB DAT.4

**Status**: IMPLEMENTED

**Implementation** (`KMSStack`):
- Five dedicated CMKs, all with `enable_key_rotation=True` and `RemovalPolicy.RETAIN`:
  - `msb/master-key` — general encryption
  - `msb/cloudtrail-key` — CloudTrail log encryption
  - `msb/s3-key` — S3 encryption
  - `msb/rds-key` — RDS encryption
  - `msb/ebs-key` — EBS encryption (set as account default)

---

## EBS Encryption by Default — CIS 2.2.1 / FSBP EC2.7 / SSB DAT.5

**Status**: IMPLEMENTED

**Implementation** (`KMSStack.enable_ebs_encryption_by_default`):
- Custom Resource calls `ec2:EnableEbsEncryptionByDefault`.
- Second Custom Resource calls `ec2:ModifyEbsDefaultKmsKeyId` to set the EBS CMK (`msb/ebs-key`) as the account default.

---

## Default Security Group Remediation — CIS 5.4 / FSBP EC2.2 / SSB NET.2

**Status**: IMPLEMENTED

**Implementation** (`NetworkSecurityStack.create_default_sg_security`):
- Lambda `msb-secure-default-sg` (Python 3.13) iterates all VPCs, finds each default security group, and revokes all ingress rules and any non-default egress rules.
- Runs on a daily EventBridge schedule and on `AuthorizeSecurityGroupIngress`, `AuthorizeSecurityGroupEgress`, and `CreateSecurityGroup` events.
- Publishes notification when groups are modified.
- CloudWatch alarm `msb-default-sg-remediation-errors-{region}` fires on any Lambda error.

---

## VPC Flow Logs — CIS 3.9 / FSBP EC2.6 / SSB NET.1

**Status**: IMPLEMENTED

**Implementation** (`NetworkSecurityStack`, `VpcStack`):
- IAM role `msb-vpc-flow-logs-role-{region}` for the VPC Flow Logs service principal.
- CloudWatch log group `/aws/vpc/flowlogs/{account}/{region}` with 1-year retention and RETAIN policy.
- `ec2.FlowLog` attached to the MSB VPC with `FlowLogTrafficType.ALL`.

---

## VPC with Endpoints and Segmented Subnets — FSBP EC2.15 / SSB NET.6

**Status**: IMPLEMENTED

**Implementation** (`VpcStack`):
- VPC `msb-vpc-{region}` with CIDR `10.0.0.0/16`, 2 AZs, public/private-egress/isolated subnets, NAT gateway.
- Gateway endpoints for S3 (with source-VPC condition) and DynamoDB (with source-VPC condition).
- Interface endpoints for 13 services: `ssm`, `ssmmessages`, `ec2messages`, `kms`, `logs`, `monitoring`, `sqs`, `sns`, `secretsmanager`, `ecr.api`, `ecr.dkr`, `ecs`, `lambda` — all with private DNS and a scoped security group allowing HTTPS from within the VPC only.
- Bastion security group: SSH restricted to `10.0.0.0/8`; outbound HTTPS only.
- Application security group: HTTPS from `0.0.0.0/0` (internet-facing); SSH from bastion SG only.

---

## Remediation Lambda Error Alarms — Operational Monitoring

**Status**: IMPLEMENTED

**Implementation** (IAMStack, NetworkSecurityStack, S3SecurityStack):
Three CloudWatch alarms, each with `threshold=1`, `evaluation_periods=1`, and an SNS alarm action:
- `msb-iam-policy-checker-errors-{region}` — IAM policy checker Lambda
- `msb-default-sg-remediation-errors-{region}` — Default SG remediation Lambda
- `msb-s3-public-access-checker-errors-{region}` — S3 public access checker Lambda

These ensure that if any automated remediation Lambda fails silently, the operator is alerted immediately.

---

## AWS Config Rules — FSBP / CIS / SSB COM.1

**Status**: IMPLEMENTED (Config rules detect; enforcement varies)

**Implementation** (`ComplianceStack._create_config_rules`):

| Config Rule | Framework Reference |
|-------------|-------------------|
| `ENCRYPTED_VOLUMES` | FSBP EC2.3, CIS 2.2.1 |
| `EC2_IMDSV2_CHECK` | FSBP EC2.8 |
| `CMK_BACKING_KEY_ROTATION_ENABLED` | FSBP KMS.4 |
| `RDS_INSTANCE_DELETION_PROTECTION_ENABLED` | FSBP RDS.3 |
| `RDS_STORAGE_ENCRYPTED` | FSBP RDS.2 |
| `SNS_ENCRYPTED_KMS` | FSBP SNS.1 |
| `ACCESS_KEYS_ROTATED` (maxAge=45d) | FSBP IAM.3, CIS 1.14 |
| `MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS` | FSBP IAM.5, CIS 1.10 |
| `IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS` | FSBP IAM.1 |
| `IAM_ROOT_ACCESS_KEY_CHECK` | CIS 1.4, FSBP IAM.4 |
| `ROOT_ACCOUNT_MFA_ENABLED` | CIS 1.5 |
| `IAM_PASSWORD_POLICY` | CIS 1.7 |
| `S3_BUCKET_PUBLIC_READ_PROHIBITED` | FSBP S3.1 |
| `S3_BUCKET_PUBLIC_WRITE_PROHIBITED` | FSBP S3.2 |
| `S3_BUCKET_SSL_REQUESTS_ONLY` | FSBP S3.5 |
| `S3_BUCKET_OBJECT_LOCK_ENABLED` | FSBP S3.11 |
| `CLOUD_TRAIL_ENABLED` | FSBP CloudTrail.1 |
| `CLOUD_TRAIL_ENCRYPTION_ENABLED` | FSBP CloudTrail.2 |
| `CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED` | FSBP CloudTrail.4 |
| `VPC_FLOW_LOGS_ENABLED` | FSBP EC2.6, CIS 3.9 |
| `INCOMING_SSH_DISABLED` | FSBP EC2.19, CIS 5.1 |
| `RESTRICTED_INCOMING_TRAFFIC` (port 3389) | FSBP EC2.20, CIS 5.2 |
| `RESTRICTED_INCOMING_TRAFFIC` (ports 20,21,23,3306,4333) | FSBP EC2.18 |
| `SUBNET_AUTO_ASSIGN_PUBLIC_IP_DISABLED` | FSBP EC2.15 |
| `EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK` | FSBP EC2.1 |
| `LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED` | FSBP Lambda.1 |
| `LAMBDA_FUNCTION_SETTINGS_CHECK` | FSBP Lambda.2 |
| `EC2_INSTANCE_MANAGED_BY_SSM` | FSBP SSM.1 |

---

## WAF (Optional) — SSB NET.10

**Status**: PARTIAL — deploy with `--context enable_waf=true`; manual association required

**Implementation** (`WafStack`):
- REGIONAL WAFv2 WebACL `msb-web-acl-{region}` with CloudWatch metrics and sampled requests enabled.
- Five AWS Managed Rule Groups:
  1. `AWSManagedRulesCommonRuleSet` (priority 10)
  2. `AWSManagedRulesKnownBadInputsRuleSet` (priority 20)
  3. `AWSManagedRulesAmazonIpReputationList` (priority 30)
  4. `AWSManagedRulesAnonymousIpList` (priority 40)
  5. `AWSManagedRulesSQLiRuleSet` (priority 50)
- Rate-limiting rule: 2 000 requests per 5 minutes per IP, BLOCK action (priority 60).
- WebACL ARN exported as `MSB-WAF-WebACLArn-{region}`.
- After deployment, associate the ARN with ALB, CloudFront, or API Gateway resources.
