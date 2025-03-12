# Compliance Test Coverage Report

## Overall Coverage: 64.4%

- Total Controls: 45
- Covered Controls: 29
- Uncovered Controls: 16

## Test Status Summary

- Passed Tests: 27
- Failed Tests: 0
- Unknown Status: 0

## Covered Controls

| Control | Description | Framework References | Tests |
|---------|-------------|---------------------|-------|
| AWS Config Enabled | Ensure AWS Config is enabled | FSBP: Config.1; CIS AWS 3.0.0: 3.5; AWS SSB: LOG.6 | ✅ test_config_rules_for_compliance, ✅ test_aws_config_enabled |
| AWS Config Rules | Ensure AWS Config Rules are configured for compliance monitoring | FSBP: Config.1; CIS AWS 3.0.0: 3.5; AWS SSB: COM.1, LOG.6 | ✅ test_config_rules_for_compliance, ✅ test_aws_config_enabled |
| Access Keys Rotated | Ensure access keys are rotated every 90 days or less | FSBP: IAM.3; CIS AWS 3.0.0: 1.14; AWS SSB: IAM.4 | ✅ test_access_keys_rotated |
| CloudTrail Configuration | Ensure CloudTrail is properly configured | FSBP: CloudTrail.1, CloudTrail.4, CloudTrail.5; CIS AWS 3.0.0: 3.1, 3.2; AWS SSB: LOG.1, LOG.2, LOG.4 | ✅ test_cloudtrail_enabled_and_configured |
| CloudTrail Log Encryption | Ensure CloudTrail logs are encrypted | FSBP: CloudTrail.2; CIS AWS 3.0.0: 3.5; AWS SSB: DAT.7 | ✅ test_config_rules_for_compliance, ✅ test_aws_config_enabled |
| CloudWatch Log Group Retention | Ensure CloudWatch Log Groups have retention periods set | FSBP: CloudWatch.1; CIS AWS 3.0.0: 3.4; AWS SSB: LOG.5 | ✅ test_cloudwatch_log_group_retention |
| Default Security Group Restrictions | Ensure default security groups restrict all traffic | FSBP: EC2.2; CIS AWS 3.0.0: 5.4; AWS SSB: NET.2 | ✅ test_default_security_group_restrictions |
| EBS Encryption by Default | Ensure EBS volumes are encrypted by default | FSBP: EC2.7; CIS AWS 3.0.0: 2.2.1; AWS SSB: DAT.5 | ✅ test_ebs_encryption_by_default |
| GuardDuty Enabled | Ensure GuardDuty is enabled | FSBP: GuardDuty.1; CIS AWS 3.0.0: 3.8; AWS SSB: LOG.7 | ✅ test_guardduty_enabled |
| GuardDuty Findings Alerts | Ensure GuardDuty findings are monitored and alerted | FSBP: GuardDuty.4; AWS SSB: IR.4 | ✅ test_guardduty_findings_alerts |
| IAM Access Analyzer | Ensure IAM Access Analyzer is enabled | FSBP: IAM.8; CIS AWS 3.0.0: 1.20; AWS SSB: IAM.6 | ✅ test_iam_access_analyzer_enabled, ✅ test_iam_access_analyzer_alerts |
| IAM Access Analyzer Alerts | Ensure IAM Access Analyzer findings are monitored and alerted | FSBP: IAM.8; AWS SSB: IR.6 | ✅ test_iam_access_analyzer_enabled, ✅ test_iam_access_analyzer_alerts |
| IAM Password Policy | Ensure IAM password policy meets security requirements | FSBP: IAM.9; CIS AWS 3.0.0: 1.8, 1.9, 1.10, 1.11; AWS SSB: IAM.1 | ✅ test_iam_password_policy_compliance |
| IAM Roles for Service Access | Ensure IAM roles are used for AWS service access | FSBP: IAM.21; CIS AWS 3.0.0: 1.16, 1.17; AWS SSB: IAM.7 | ✅ test_iam_roles_for_service_access |
| KMS Key Rotation | Ensure KMS keys are rotated | FSBP: KMS.4; CIS AWS 3.0.0: 3.7; AWS SSB: DAT.4 | ✅ test_kms_key_rotation |
| MFA for Console Access | Ensure MFA is enabled for all IAM users with console access | FSBP: IAM.19; CIS AWS 3.0.0: 1.12; AWS SSB: IAM.3 | ✅ test_mfa_for_console_access |
| Network ACL Monitoring | Ensure network ACL changes are monitored | FSBP: EC2.21; AWS SSB: NET.5 | ✅ test_network_acl_monitoring |
| No Root Access Key | Ensure no root account access key exists | CIS AWS 3.0.0: 1.4; AWS SSB: IAM.2 | ✅ test_security_monitoring_for_root_activity |
| Restricted RDP Access | Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 | FSBP: EC2.14; CIS AWS 3.0.0: 5.2; AWS SSB: NET.8 | ✅ test_restricted_rdp_access, ✅ test_restricted_ssh_access |
| Restricted SSH Access | Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 | FSBP: EC2.13; CIS AWS 3.0.0: 5.2; AWS SSB: NET.7 | ✅ test_restricted_rdp_access, ✅ test_restricted_ssh_access |
| Root Activity Monitoring | Ensure root account activity is monitored | FSBP: IAM.7; CIS AWS 3.0.0: 1.7; AWS SSB: IAM.2 | ✅ test_security_monitoring_for_root_activity |
| S3 Public Access Block | Ensure S3 buckets block public access | FSBP: S3.1, S3.4; CIS AWS 3.0.0: 2.1.1, 2.1.2, 2.1.5; AWS SSB: DAT.1, DAT.2 | ✅ test_s3_security_compliance |
| S3 SSL Enforcement | Ensure S3 buckets enforce SSL | FSBP: S3.5; CIS AWS 3.0.0: 2.1.3; AWS SSB: DAT.3 | ✅ test_s3_bucket_ssl_enforcement |
| SNS Topic Encryption | Ensure SNS topics are encrypted | FSBP: SNS.1; AWS SSB: DAT.8 | ✅ test_sns_topic_encryption |
| Security Group Monitoring | Ensure security group changes are monitored | FSBP: EC2.19; CIS AWS 3.0.0: 5.3; AWS SSB: NET.4 | ✅ test_security_group_monitoring |
| Security Hub Compliance Standards | Ensure Security Hub enables compliance standards | FSBP: SecurityHub.1; CIS AWS 3.0.0: 3.10; AWS SSB: COM.2, LOG.8 | ✅ test_security_hub_compliance_standards |
| Security Hub Findings Alerts | Ensure Security Hub findings are monitored and alerted | FSBP: SecurityHub.2; AWS SSB: COM.5, IR.5 | ✅ test_security_hub_findings_alerts |
| VPC Endpoints Security | Ensure VPC endpoints are configured with least privilege | FSBP: EC2.15; AWS SSB: NET.6 | ✅ test_vpc_endpoints_security |
| VPC Flow Logs | Ensure VPC Flow Logs are enabled | FSBP: EC2.6; CIS AWS 3.0.0: 3.9; AWS SSB: NET.1 | ✅ test_vpc_flow_logs_enabled |

## Uncovered Controls

| Control | Description | Framework References | Reason |
|---------|-------------|---------------------|--------|
| Automated Remediation | Ensure automated remediation is implemented for critical findings | AWS SSB: IR.8 | Not implemented |
| Centralized Log Management | Ensure logs are centrally managed and analyzed | AWS SSB: LOG.10 | Not implemented |
| CloudTrail Log File Validation | Ensure CloudTrail log file validation is enabled | CIS AWS 3.0.0: 3.3 | Not implemented |
| DLP Controls | Ensure data loss prevention controls are implemented | AWS SSB: DAT.10 | Not implemented |
| Data Classification | Ensure data is classified according to sensitivity | AWS SSB: DAT.9 | Not implemented |
| Incident Response Exercises | Ensure incident response exercises are conducted | AWS SSB: IR.9 | Not implemented |
| Incident Response Playbooks | Ensure incident response playbooks are documented | AWS SSB: IR.7 | Not implemented |
| Network Segmentation | Ensure network is properly segmented | AWS SSB: NET.9 | Not implemented |
| Security Contact Information | Ensure security contact information is registered | CIS AWS 3.0.0: 1.18 | Not implemented |
| VPC Peering Routing Tables | Ensure routing tables for VPC peering are least access | CIS AWS 3.0.0: 5.5 | Not implemented |
| WAF for Web Applications | Ensure WAF is implemented for web applications | AWS SSB: NET.10 | Not implemented |
| CloudWatch Alarms | Ensure CloudWatch alarms are configured for critical metrics | FSBP: CloudWatch.2; CIS AWS 3.0.0: 3.11; AWS SSB: IR.2 | Runtime verification required |
| Privileged Access Management | Ensure privileged access is managed and monitored | AWS SSB: IAM.8 | Runtime verification required |
| Compliance Reporting | Ensure compliance reports are generated and reviewed | FSBP: Config.3; AWS SSB: COM.3 | Manual verification required |
| Hardware MFA for Root | Ensure hardware MFA is enabled for the root account | FSBP: IAM.4; CIS AWS 3.0.0: 1.13; AWS SSB: IAM.5 | Documented residual risk |
| IAM Policies Attached to Groups | Ensure IAM policies are attached only to groups or roles | FSBP: IAM.16 | Testing framework limitations |

## Reason Categories for Uncovered Controls

### Runtime Verification Required
These controls can only be verified at runtime after deployment, not during CDK synthesis testing.
See [Untested Controls](untested_controls.md#1-runtime-dependent-controls) for details.

### Documented Residual Risk
These controls are explicitly documented as residual risk in the compliance matrix.
See [Untested Controls](untested_controls.md#2-documented-residual-risk-controls) for details.

### Implementation Gap
These controls are partially implemented but have gaps that prevent complete testing.
See [Untested Controls](untested_controls.md#3-implementation-gaps) for details.

### Testing Framework Limitations
These controls are difficult to test due to limitations in the testing framework.
See [Untested Controls](untested_controls.md#4-testing-framework-limitations) for details.

### Manual Verification Required
These controls require manual verification procedures.
See [Untested Controls](untested_controls.md#5-manual-verification-required) for details.

