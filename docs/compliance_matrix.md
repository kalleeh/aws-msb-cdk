# AWS MSB Compliance Matrix

This document maps the AWS Minimum Security Baseline (MSB) controls to industry standards and AWS security frameworks:
- AWS Foundational Security Best Practices (FSBP)
- CIS AWS Foundations Benchmark v3.0.0
- AWS Startup Security Baseline (SSB)

Each control is categorized by its security type:
- **Preventative**: Controls that prevent security incidents from occurring
- **Detective**: Controls that detect and alert on security incidents
- **Responsive**: Controls that help respond to security incidents
- **Proactive**: Controls that actively improve security posture

Status values:
- **IMPLEMENTED**: The control is fully implemented by the CDK code
- **PARTIAL**: The control is partially implemented (e.g., detects but does not prevent, or opt-in flag is required)
- **MANUAL**: The control requires a manual action that cannot be fully automated

## IAM Controls

| MSB Control | Status | Control Type | FSBP | CIS AWS 3.0.0 | AWS SSB | Stack |
|-------------|--------|--------------|------|--------------|---------|-------|
| IAM Password Policy | IMPLEMENTED | Preventative | IAM.9 | 1.8, 1.9, 1.11, 1.12, 1.13, 1.14 | IAM.1 | IAMStack |
| AWS Support Role | IMPLEMENTED | Preventative | - | 1.17 | - | IAMStack |
| Security Contact | IMPLEMENTED | Preventative | Account.1 | 1.18 | - | IAMStack |
| IAM Access Analyzer | IMPLEMENTED | Detective | IAM.8 | 1.20 | IAM.6 | IAMStack |
| IAM Policy Governance Monitoring | IMPLEMENTED | Detective | IAM.16 | - | - | IAMStack |
| MFA for Root Account | MANUAL | Preventative | IAM.4, IAM.6, IAM.9 | 1.5 | IAM.2 | - |
| No Root Access Keys | MANUAL | Preventative | IAM.4 | 1.4 | - | - |
| MFA for IAM Users | PARTIAL | Preventative | IAM.19 | 1.10 | IAM.3 | ComplianceStack (Config rule) |
| IAM Access Key Rotation | PARTIAL | Detective | IAM.3 | 1.14 | IAM.4 | ComplianceStack (Config rule) |
| No Inline/Direct IAM Policies | PARTIAL | Detective | IAM.1, IAM.16 | - | IAM.5 | IAMStack (Lambda checker) |

## Logging and Monitoring Controls

| MSB Control | Status | Control Type | FSBP | CIS AWS 3.0.0 | AWS SSB | Stack |
|-------------|--------|--------------|------|--------------|---------|-------|
| CloudTrail Enabled (multi-region) | IMPLEMENTED | Detective | CloudTrail.1, CloudTrail.5 | 3.1 | LOG.1 | LoggingStack |
| CloudTrail Log File Validation | IMPLEMENTED | Preventative | CloudTrail.4 | 3.2 | LOG.2 | LoggingStack |
| CloudTrail Logs Encrypted (KMS) | IMPLEMENTED | Preventative | CloudTrail.2 | 3.5 | LOG.3, DAT.7 | LoggingStack, KMSStack |
| CloudTrail S3 + Lambda Data Events | IMPLEMENTED | Detective | CloudTrail.7 | - | LOG.4 | LoggingStack |
| CloudWatch Log Group Retention (1 yr) | IMPLEMENTED | Detective | CloudWatch.1 | 3.4 | LOG.5 | LoggingStack |
| AWS Config Recorder + Delivery Channel | IMPLEMENTED | Detective | Config.1 | 3.5 | LOG.6 | LoggingRegionalStack |
| GuardDuty Enabled (all features) | IMPLEMENTED | Detective | GuardDuty.1 | 3.8 | LOG.7 | SecurityRegionalStack |
| Security Hub Enabled (FSBP + CIS v3.0.0) | IMPLEMENTED | Detective | SecurityHub.1 | 3.10 | LOG.8 | SecurityRegionalStack |
| VPC Flow Logs | IMPLEMENTED | Detective | EC2.6 | 3.9 | NET.1 | NetworkSecurityStack, VpcStack |
| S3 Access Logging (logs bucket) | IMPLEMENTED | Detective | S3.9 | 3.6 | LOG.9 | LoggingStack |
| GuardDuty Findings Bucket (with server access logs) | IMPLEMENTED | Detective | S3.9 | 3.6 | LOG.9 | SecurityRegionalStack |
| SNS Delivery Status Logging | IMPLEMENTED | Detective | SNS.2 | - | - | LoggingStack, NotificationsRegionalStack |
| Inspector v2 Enabled | IMPLEMENTED | Detective | Inspector.1 | - | - | SecurityRegionalStack |
| Macie Enabled | IMPLEMENTED | Detective | Macie.1 | - | - | SecurityRegionalStack |
| CW Alarm: Unauthorized API Calls | IMPLEMENTED | Detective | - | 3.1 | - | LoggingStack |
| CW Alarm: Console Sign-in Without MFA | IMPLEMENTED | Detective | - | 3.2 | - | LoggingStack |
| CW Alarm: CloudTrail Config Changes | IMPLEMENTED | Detective | - | 3.5 | - | LoggingStack |
| CW Alarm: Console Auth Failures | IMPLEMENTED | Detective | - | 3.6 | - | LoggingStack |
| CW Alarm: KMS CMK Disabling/Deletion | IMPLEMENTED | Detective | - | 3.7 | - | LoggingStack |
| CW Alarm: S3 Bucket Policy Changes | IMPLEMENTED | Detective | - | 3.8 | - | LoggingStack |
| CW Alarm: AWS Config Changes | IMPLEMENTED | Detective | - | 3.9 | - | LoggingStack |
| CW Alarm: Network Gateway Changes | IMPLEMENTED | Detective | - | 3.12 | - | LoggingStack |
| CW Alarm: Route Table Changes | IMPLEMENTED | Detective | - | 3.13 | - | LoggingStack |
| CW Alarm: VPC Changes | IMPLEMENTED | Detective | - | 3.14 | - | LoggingStack |
| CW Alarm: IAM Policy Changes | IMPLEMENTED | Detective | - | 4.4 | - | LoggingStack |
| CW Alarm: Security Group Changes | IMPLEMENTED | Detective | - | 4.15 | - | LoggingStack |
| CW Alarm: Network ACL Changes | IMPLEMENTED | Detective | - | 4.16 | - | LoggingStack |
| Regional SNS Notification Topic | IMPLEMENTED | Responsive | - | - | IR.1 | NotificationsRegionalStack |
| Remediation Lambda Error Alarms | IMPLEMENTED | Detective | - | - | - | IAMStack, NetworkSecurityStack, S3SecurityStack |

## Data Protection Controls

| MSB Control | Status | Control Type | FSBP | CIS AWS 3.0.0 | AWS SSB | Stack |
|-------------|--------|--------------|------|--------------|---------|-------|
| S3 Block Public Access (Account Level) | IMPLEMENTED | Preventative | S3.1, S3.2 | 2.1.2 | DAT.1 | S3SecurityStack |
| S3 Bucket-Level Public Access Enforcement | IMPLEMENTED | Preventative | S3.1, S3.2 | 2.1.5 | DAT.1 | S3SecurityStack |
| S3 Bucket SSL Enforcement | IMPLEMENTED | Preventative | S3.5 | 2.1.3 | DAT.3 | S3SecurityStack (create_secure_bucket), LoggingStack |
| S3 Bucket Versioning | IMPLEMENTED | Preventative | S3.14 | - | - | LoggingStack, SecurityRegionalStack |
| S3 Object Lock (opt-in, default off) | PARTIAL | Preventative | S3.11 | - | - | LoggingStack (enable_object_lock flag) |
| KMS CMK Creation (CloudTrail, S3, RDS, EBS) | IMPLEMENTED | Preventative | KMS.4 | 3.7 | DAT.4 | KMSStack |
| KMS Key Rotation Enabled | IMPLEMENTED | Preventative | KMS.4 | - | DAT.4 | KMSStack |
| EBS Encryption by Default (with CMK) | IMPLEMENTED | Preventative | EC2.7 | 2.2.1 | DAT.5 | KMSStack |
| RDS Storage Encryption | PARTIAL | Preventative | RDS.3 | 2.3.1 | DAT.6 | ComplianceStack (Config rule) |
| SNS Topic Encryption (KMS) | IMPLEMENTED | Preventative | SNS.1 | - | DAT.8 | NotificationsRegionalStack, LoggingStack |

## Network Security Controls

| MSB Control | Status | Control Type | FSBP | CIS AWS 3.0.0 | AWS SSB | Stack |
|-------------|--------|--------------|------|--------------|---------|-------|
| Default Security Group Remediation | IMPLEMENTED | Preventative | EC2.2 | 5.4 | NET.2 | NetworkSecurityStack |
| VPC Flow Logs Enabled | IMPLEMENTED | Detective | EC2.6 | 3.9 | NET.1 | NetworkSecurityStack, VpcStack |
| VPC Endpoint Security (S3, DynamoDB, + 13 interface endpoints) | IMPLEMENTED | Preventative | EC2.15 | - | NET.6 | VpcStack |
| Subnets: No Auto-Assign Public IP | PARTIAL | Preventative | EC2.15 | - | - | ComplianceStack (Config rule) |
| Restricted SSH Access | PARTIAL | Detective | EC2.19 | 5.2 | NET.7 | ComplianceStack (Config rule) |
| Restricted RDP Access | PARTIAL | Detective | EC2.20 | 5.2 | NET.8 | ComplianceStack (Config rule) |
| High-Risk Port Blocking | PARTIAL | Detective | EC2.18 | - | - | ComplianceStack (Config rule) |
| WAF (optional, REGIONAL scope) | PARTIAL | Preventative | - | - | NET.10 | WafStack (enable_waf=true) |

## Compliance Controls

| MSB Control | Status | Control Type | FSBP | CIS AWS 3.0.0 | AWS SSB | Stack |
|-------------|--------|--------------|------|--------------|---------|-------|
| AWS Config Rules (encryption, IAM, S3, network, Lambda, SSM) | IMPLEMENTED | Detective | Config.1 | 3.5 | COM.1 | ComplianceStack |
| Security Hub: FSBP Standard | IMPLEMENTED | Detective | SecurityHub.1 | - | COM.2 | SecurityRegionalStack |
| Security Hub: CIS AWS Foundations v3.0.0 | IMPLEMENTED | Detective | SecurityHub.1 | 3.10 | COM.2 | SecurityRegionalStack |
| Security Hub Automation Rules | IMPLEMENTED | Responsive | - | - | - | SecurityRegionalStack |
| CloudWatch Compliance Dashboard | IMPLEMENTED | Detective | - | - | COM.3 | ComplianceStack |
| EBS Snapshots Not Public | PARTIAL | Detective | EC2.1 | - | - | ComplianceStack (Config rule) |
| EC2 IMDSv2 Required | PARTIAL | Detective | EC2.8 | - | - | ComplianceStack (Config rule) |
| Lambda Public Access Prohibited | PARTIAL | Detective | Lambda.1 | - | - | ComplianceStack (Config rule) |
| Lambda Supported Runtimes | PARTIAL | Detective | Lambda.2 | - | - | ComplianceStack (Config rule) |
| EC2 Instances Managed by SSM | PARTIAL | Detective | SSM.1 | - | - | ComplianceStack (Config rule) |

## Incident Response Controls

| MSB Control | Status | Control Type | FSBP | CIS AWS 3.0.0 | AWS SSB | Stack |
|-------------|--------|--------------|------|--------------|---------|-------|
| Regional SNS Notification Topic | IMPLEMENTED | Responsive | SNS.2 | - | IR.1 | NotificationsRegionalStack |
| CloudWatch Alarms (13 CIS alarms) | IMPLEMENTED | Detective | CloudWatch.2 | 3.1–3.14, 4.4, 4.15, 4.16 | IR.2 | LoggingStack |
| EventBridge: Inspector Findings to SNS | IMPLEMENTED | Responsive | Inspector.1 | - | IR.3 | SecurityRegionalStack |
| EventBridge: Macie Findings to SNS | IMPLEMENTED | Responsive | Macie.1 | - | IR.3 | SecurityRegionalStack |
| GuardDuty Findings (15-min publish) | IMPLEMENTED | Detective | GuardDuty.1 | 3.8 | IR.4 | SecurityRegionalStack |
| IAM Access Analyzer Findings | IMPLEMENTED | Detective | IAM.8 | 1.20 | IR.6 | IAMStack |
| Remediation Lambda Error Alarms | IMPLEMENTED | Responsive | - | - | - | IAMStack, NetworkSecurityStack, S3SecurityStack |

## Residual Risk — Controls Not Implemented

The following controls from the security standards are not fully implemented in the MSB, representing residual risk:

| Control ID | Standard | Description | Risk Level | Reason |
|------------|----------|-------------|------------|--------|
| IAM.4, IAM.6, IAM.9 | FSBP | Hardware MFA for root account | Medium | Requires physical hardware; cannot be automated |
| CIS 1.5 | CIS 3.0.0 | Root account MFA enabled | Medium | Requires manual console setup; Config rule detects non-compliance |
| CIS 1.4 | CIS 3.0.0 | No root user access keys | Medium | Config rule detects non-compliance; removal is manual |
| S3.11 | FSBP | S3 Object Lock on log bucket | Low | Opt-in flag (`enable_object_lock=True`); off by default to avoid accidental WORM lock during initial deployment |
| SSB.IAM.8 | AWS SSB | Privileged access management | High | Requires additional tooling (e.g., AWS IAM Identity Center) beyond MSB scope |
| SSB.DAT.9 | AWS SSB | Data classification | Medium | Requires application-level controls; Macie is enabled for discovery |
| SSB.DAT.10 | AWS SSB | DLP controls | High | Requires additional tooling beyond infrastructure |
| SSB.LOG.10 | AWS SSB | Centralized log management / SIEM | Medium | MSB centralizes raw logs but does not deploy a SIEM or log analysis tool |
| SSB.IR.7 | AWS SSB | Incident response playbooks | High | Requires operational procedures beyond infrastructure |
| SSB.IR.8 | AWS SSB | Automated remediation | Medium | MSB provides alerts and three automated remediators; full playbook automation is out of scope |
| SSB.IR.9 | AWS SSB | Regular IR exercises | Medium | Requires operational procedures beyond infrastructure |
| CIS 5.5 | CIS 3.0.0 | Least-access routing for VPC peering | Medium | MSB creates secure VPCs but does not manage peering connections |
| WAF association | FSBP / SSB.NET.10 | WAF associated with ALB/CloudFront/API GW | Medium | WAFStack deploys a WebACL; association with specific resources is a post-deploy step |

## Detailed Control Mappings

### IAM Controls

#### IAM Password Policy (Preventative)
- **Implementation**: `IAMStack.create_password_policy()` — `AWS::IAM::AccountPasswordPolicy` with MinimumPasswordLength=16, UpperCase, LowerCase, Symbols, Numbers, PasswordReusePrevention=24. `MaxPasswordAge` is intentionally omitted per NIST SP 800-63B.
- **FSBP**: IAM.9
- **CIS AWS 3.0.0**: 1.8, 1.9, 1.11, 1.12, 1.13, 1.14
- **AWS SSB**: IAM.1

#### AWS Support Role (Preventative)
- **Implementation**: `IAMStack.create_password_policy()` — IAM role `msb-aws-support-role` with `AWSSupportAccess` managed policy, assumed by the account root principal.
- **CIS AWS 3.0.0**: 1.17

#### Security Contact (Preventative)
- **Implementation**: `IAMStack.create_security_contact()` — Custom Resource calls `account:PutAlternateContact` with `AlternateContactType=SECURITY`. Activated when `notification_email` and `security_contact_phone` context values are provided. Security Hub automation rule suppresses the Account.1 finding once set.
- **FSBP**: Account.1
- **CIS AWS 3.0.0**: 1.18

#### IAM Access Analyzer (Detective)
- **Implementation**: `IAMStack.create_access_analyzer()` — `AWS::AccessAnalyzer::Analyzer` of type `ACCOUNT`.
- **FSBP**: IAM.8
- **CIS AWS 3.0.0**: 1.20
- **AWS SSB**: IAM.6

#### IAM Policy Governance Monitoring (Detective)
- **Implementation**: `IAMStack.create_iam_policy_checker()` — Lambda (`msb-iam-policy-checker`) runs daily and on `AttachUserPolicy`/`PutUserPolicy` events; reports users with directly-attached policies to SNS. CloudWatch error alarm ensures silent failures are surfaced.
- **FSBP**: IAM.16

### Logging and Monitoring Controls

#### CloudTrail (Detective / Preventative)
- **Implementation**: `LoggingStack` — Multi-region trail `msb-cloudtrail` with KMS encryption, log file validation, CloudWatch Logs delivery (1-year retention), S3 + Lambda advanced data events.
- **FSBP**: CloudTrail.1, CloudTrail.2, CloudTrail.4, CloudTrail.5, CloudTrail.7
- **CIS AWS 3.0.0**: 3.1, 3.2, 3.5
- **AWS SSB**: LOG.1–LOG.4

#### CloudWatch Metric Filter Alarms (13 alarms, CIS 3.x / 4.x)
- **Implementation**: `LoggingStack` — Metric filters on the CloudTrail log group with SNS-connected alarms:
  1. Unauthorized API calls (CIS 3.1)
  2. Console sign-in without MFA (CIS 3.2)
  3. CloudTrail config changes (CIS 3.5)
  4. Console authentication failures, threshold 3 (CIS 3.6)
  5. KMS CMK disabling/deletion (CIS 3.7)
  6. S3 bucket policy changes (CIS 3.8)
  7. AWS Config changes (CIS 3.9)
  8. Network gateway changes (CIS 3.12)
  9. Route table changes (CIS 3.13)
  10. VPC changes (CIS 3.14)
  11. IAM policy changes (CIS 4.4)
  12. Security group changes (CIS 4.15)
  13. Network ACL changes (CIS 4.16)

#### AWS Config (Detective)
- **Implementation**: `LoggingRegionalStack` — `CfnConfigurationRecorder` (all resources) and `CfnDeliveryChannel` (6-hour snapshot frequency) per deployed region. Skipped when `control_tower_managed=True`.
- **FSBP**: Config.1
- **CIS AWS 3.0.0**: 3.5
- **AWS SSB**: LOG.6

#### GuardDuty (Detective)
- **Implementation**: `SecurityRegionalStack` — `CfnDetector` enabled with 15-minute publishing frequency and all protection features: S3_DATA_EVENTS, EKS_AUDIT_LOGS, EBS_MALWARE_PROTECTION, RDS_LOGIN_EVENTS, LAMBDA_NETWORK_LOGS, EKS_RUNTIME_MONITORING, RUNTIME_MONITORING (EC2, EKS, Fargate). Findings exported to a dedicated S3 bucket with server access logs.
- **FSBP**: GuardDuty.1
- **CIS AWS 3.0.0**: 3.8
- **AWS SSB**: LOG.7

#### Security Hub (Detective)
- **Implementation**: `SecurityRegionalStack` — `CfnHub` with both FSBP and CIS AWS Foundations Benchmark v3.0.0 standards enabled. Two automation rules suppress findings that require manual action (Account.1 when security contact is set programmatically; IAM root MFA hardware findings).
- **FSBP**: SecurityHub.1
- **CIS AWS 3.0.0**: 3.10
- **AWS SSB**: LOG.8

#### SNS Delivery Status Logging (Detective)
- **Implementation**: `NotificationsRegionalStack` and `LoggingStack` — IAM feedback role attached to each SNS topic with HTTP/S, SQS, and Lambda success and failure feedback role ARNs and 100% sample rate.
- **FSBP**: SNS.2

#### GuardDuty Findings Bucket with Server Access Logs (Detective)
- **Implementation**: `SecurityRegionalStack` — Dedicated `msb-guardduty-findings-{account}-{region}` bucket (versioned, RETAIN, lifecycle to Intelligent-Tiering) with a separate `msb-guardduty-access-logs-{account}-{region}` bucket as the server access logs destination.
- **FSBP**: S3.9
- **CIS AWS 3.0.0**: 3.6

#### Remediation Lambda Error Alarms (Detective / Operational)
- **Implementation**: Three CloudWatch alarms, one per remediation Lambda, each with threshold=1 and SNS action:
  - `msb-iam-policy-checker-errors-{region}` (IAMStack)
  - `msb-default-sg-remediation-errors-{region}` (NetworkSecurityStack)
  - `msb-s3-public-access-checker-errors-{region}` (S3SecurityStack)

### Data Protection Controls

#### S3 Block Public Access (Account Level) (Preventative)
- **Implementation**: `S3SecurityStack` — Custom Resource calls `s3:PutAccountPublicAccessBlock` with all four flags set to `True`.
- **FSBP**: S3.1, S3.2
- **CIS AWS 3.0.0**: 2.1.2
- **AWS SSB**: DAT.1

#### S3 Bucket-Level Public Access Enforcement (Preventative)
- **Implementation**: `S3SecurityStack.create_bucket_public_access_checker()` — Lambda (`msb-s3-public-access-checker`) runs daily and on `CreateBucket` events; enforces all four public access block settings on every bucket. CloudWatch error alarm ensures silent failures are surfaced.
- **FSBP**: S3.1, S3.2
- **CIS AWS 3.0.0**: 2.1.5
- **AWS SSB**: DAT.1

#### S3 Object Lock (Opt-In) (Preventative)
- **Implementation**: `LoggingStack` — `object_lock_enabled` parameter on the CloudTrail logs bucket; defaults to `False`. When `True`, enables Object Lock with Governance mode and 365-day retention. Config rule `S3_BUCKET_OBJECT_LOCK_ENABLED` detects non-compliant buckets.
- **FSBP**: S3.11
- **Status**: PARTIAL — requires explicit opt-in via `enable_object_lock=True`

#### KMS Keys and Rotation (Preventative)
- **Implementation**: `KMSStack` — Five dedicated CMKs (master, CloudTrail, S3, RDS, EBS), all with `enable_key_rotation=True` and `RemovalPolicy.RETAIN`.
- **FSBP**: KMS.4
- **AWS SSB**: DAT.4

#### EBS Encryption by Default (Preventative)
- **Implementation**: `KMSStack.enable_ebs_encryption_by_default()` — Custom Resources call `ec2:EnableEbsEncryptionByDefault` and `ec2:ModifyEbsDefaultKmsKeyId` to set the EBS CMK as the account-level default.
- **FSBP**: EC2.7
- **CIS AWS 3.0.0**: 2.2.1
- **AWS SSB**: DAT.5

### Network Security Controls

#### Default Security Group Remediation (Preventative)
- **Implementation**: `NetworkSecurityStack.create_default_sg_security()` — Lambda (`msb-secure-default-sg`) runs daily and on `AuthorizeSecurityGroupIngress`, `AuthorizeSecurityGroupEgress`, and `CreateSecurityGroup` events; removes all rules from default security groups across all VPCs. CloudWatch error alarm ensures silent failures are surfaced.
- **FSBP**: EC2.2
- **CIS AWS 3.0.0**: 5.4
- **AWS SSB**: NET.2

#### VPC and Endpoints (Preventative)
- **Implementation**: `VpcStack` — VPC with public, private (egress), and isolated subnets across 2 AZs; NAT gateway; VPC Flow Logs to CloudWatch; gateway endpoints for S3 and DynamoDB; interface endpoints for 13 AWS services (SSM, KMS, CloudWatch Logs, SNS, SQS, Secrets Manager, ECR, ECS, Lambda, and more) with private DNS and a scoped security group.
- **FSBP**: EC2.15
- **AWS SSB**: NET.6

#### WAF (Optional) (Preventative)
- **Implementation**: `WafStack` — REGIONAL WAFv2 WebACL deployed when `enable_waf=true` context is set. Includes five AWS Managed Rule Groups (CommonRuleSet, KnownBadInputs, AmazonIpReputationList, AnonymousIpList, SQLiRuleSet) plus a per-IP rate-limiting rule (2 000 req/5 min, BLOCK). After deployment, the WebACL ARN must be associated with the target ALB, CloudFront distribution, or API Gateway stage.
- **SSB**: NET.10
- **Status**: PARTIAL — WebACL is created; association with target resources is a post-deploy manual step
