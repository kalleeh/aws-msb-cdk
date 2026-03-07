# Residual Risk Register — AWS Security Baseline (MSB)

| | |
|---|---|
| **Document title** | Residual Risk Register — AWS Minimum Security Baseline CDK Deployment |
| **Version** | 1.0 |
| **Date** | [DATE] |
| **Prepared by** | [COMPANY NAME] Engineering |
| **Reviewed by** | [NAME] |
| **Approved by** | [NAME / TITLE] |

---

## 1. Purpose and Scope

This document records the security controls from the AWS Foundational Security Best Practices (FSBP), CIS AWS Foundations Benchmark v3.0.0, and AWS Startup Security Baseline (SSB) that are not fully implemented by the AWS Minimum Security Baseline (MSB) CDK deployment, and documents the formal acceptance of the resulting residual risk. It is intended to be provided to auditors, enterprise security reviewers, and internal governance functions as evidence that identified gaps have been evaluated and consciously accepted by accountable owners.

The scope of this register is limited to controls within the MSB CDK project. Controls implemented elsewhere in the organization's security program are out of scope for this document.

---

## 2. Risk Acceptance Criteria

Residual risks documented here have been accepted on the following grounds. A risk is accepted when it meets one or more of these criteria:

- **(a) Technically infeasible to automate:** The control requires physical hardware, manual console interaction, or out-of-band processes that cannot be driven by infrastructure-as-code.
- **(b) Requires manual operational procedure:** The control depends on human decision-making, organizational process, or tooling outside the scope of the MSB deployment.
- **(c) Outside the scope of infrastructure-as-code controls:** The control applies at the application, organizational, or operational layer and cannot be enforced through AWS CDK alone.

Risks accepted under this register are reviewed on at least an annual basis and whenever there is a material change to the MSB deployment or to the applicable frameworks.

---

## 3. Formally Accepted Risks

### 3.1 IAM Controls

| Risk ID | Control | Framework | Description | Why Accepted | Compensating Control | Risk Owner | Date Accepted |
|---|---|---|---|---|---|---|---|
| MSB-RR-001 | IAM.4 | FSBP | Hardware MFA for root account | Requires physical hardware security key; cannot be provisioned or enforced through infrastructure-as-code | Root account activity monitored via EventBridge (CIS 1.7); CloudWatch metric filter alarms on all root API calls; root account usage restricted by operational policy | [CISO/CTO] | [DATE] |
| MSB-RR-002 | CIS 1.13 | CIS 3.0.0 | MFA enabled for the root user | MFA enrollment is a manual, one-time console action performed outside of CDK | MSB-RR-001 compensating controls apply; Security Hub finding monitored; automated alert on any root console login | [CISO/CTO] | [DATE] |
| MSB-RR-003 | CIS 1.4 | CIS 3.0.0 | No root user access key exists | Removal of root access keys, if they exist, is a manual action; the MSB cannot programmatically delete credentials it did not create | CloudTrail logs all root API calls; EventBridge alerts on root API activity; IAM credential report reviewed periodically as operational procedure | [CISO/CTO] | [DATE] |
| MSB-RR-004 | CIS 1.18 | CIS 3.0.0 | Security contact information registered | AWS Account security contact is a manual console configuration in AWS Billing and Cost Management; the Security Hub finding for Account.1 is suppressed by MSB automation rule | MSB IAMStack optionally sets security contact via CDK custom resource when `notification_email` and `security_contact_phone` parameters are provided at deploy time; Security Hub finding suppressed where automated | [CISO/CTO] | [DATE] |
| MSB-RR-005 | SSB.IAM.8 | AWS SSB | Privileged access management | Full PAM capability (just-in-time access, session recording, approval workflows) requires dedicated tooling (e.g., AWS IAM Identity Center, third-party PAM) that is outside MSB scope | IAM Access Analyzer enabled (CIS 1.20); IAM password policy enforced (CIS 1.8–1.14); IAM policy checker Lambda alerts on direct user policy attachments daily; least-privilege IAM roles enforced across MSB stacks | [CISO/CTO] | [DATE] |

### 3.2 Data Protection Controls

| Risk ID | Control | Framework | Description | Why Accepted | Compensating Control | Risk Owner | Date Accepted |
|---|---|---|---|---|---|---|---|
| MSB-RR-006 | SSB.DAT.9 | AWS SSB | Data classification | Application-level data classification requires application-specific tagging strategies, metadata schemas, and business process ownership; cannot be generalized in infrastructure-as-code | Amazon Macie enabled and configured to publish findings to SNS; Macie findings EventBridge rule alerts on sensitive data discovery in S3; S3 public access blocked at account and bucket level | [CISO/CTO] | [DATE] |
| MSB-RR-007 | SSB.DAT.10 | AWS SSB | Data loss prevention (DLP) controls | Comprehensive DLP requires content inspection at the application layer and/or dedicated tooling (third-party DLP, S3 Object Lambda inspection pipelines) beyond MSB scope | Amazon Macie enabled for sensitive data discovery (partial DLP capability); S3 bucket-level and account-level public access blocks enforced by MSB Lambda; CloudTrail data events enabled for all S3 objects and all Lambda functions | [CISO/CTO] | [DATE] |

### 3.3 Logging and Monitoring Controls

| Risk ID | Control | Framework | Description | Why Accepted | Compensating Control | Risk Owner | Date Accepted |
|---|---|---|---|---|---|---|---|
| MSB-RR-008 | CIS 3.3 | CIS 3.0.0 | CloudTrail log file validation enabled | The MSB enables log file validation on the managed trail; however, it cannot enforce validation on any future trails created outside of MSB outside this stack | MSB CloudTrail has file validation enabled (`enable_file_validation=True`); logs stored in versioned, encrypted S3 bucket with lifecycle retention; CloudWatch alarm fires on any CloudTrail configuration changes (CIS 3.5 alarm) | [CISO/CTO] | [DATE] |
| MSB-RR-009 | CIS 3.7 | CIS 3.0.0 | CloudTrail logs encrypted at rest using KMS CMK | MSB encrypts the managed trail with a KMS CMK; future trails created outside the MSB stack are outside MSB control | MSB trail uses dedicated KMS CMK with automatic key rotation; KMS key changes trigger CloudWatch alarm (CIS 3.7 alarm); CloudTrail configuration changes trigger separate alarm | [CISO/CTO] | [DATE] |
| MSB-RR-010 | CIS 4.1–4.16 | CIS 3.0.0 | Full set of CIS monitoring and alerting controls | MSB implements all 13 CIS metric filter alarms (3.1–3.14, 4.4, 4.15, 4.16); some CIS monitoring controls require application-layer instrumentation or workload-specific configuration outside MSB scope | All 13 CIS CloudWatch metric filter alarms deployed; GuardDuty enabled with all protection plans; Security Hub FSBP and CIS v3.0.0 standards enabled; EventBridge rules covering IAM, SG, NACL, and root activity | [CISO/CTO] | [DATE] |
| MSB-RR-011 | SSB.LOG.10 | AWS SSB | Centralized log management with analysis | MSB centralizes logs to CloudTrail + S3 + CloudWatch Logs; full log analysis (SIEM, correlation, threat hunting) requires additional tooling (OpenSearch, third-party SIEM) beyond MSB scope | CloudTrail multi-region trail with one-year retention; CloudWatch Logs group for CloudTrail with one-year retention; VPC Flow Logs enabled via NetworkSecurityStack; GuardDuty findings exported to dedicated S3 bucket | [CISO/CTO] | [DATE] |

### 3.4 Incident Response Controls

| Risk ID | Control | Framework | Description | Why Accepted | Compensating Control | Risk Owner | Date Accepted |
|---|---|---|---|---|---|---|---|
| MSB-RR-012 | SSB.IR.7 | AWS SSB | Incident response playbooks | IR playbooks are operational documents requiring organizational process definition; cannot be generated by infrastructure-as-code | MSB alert response runbook (`docs/alert-response.md`) provides per-alert guidance; SNS alerting ensures findings reach the responsible team; GuardDuty and Security Hub provide per-finding remediation guidance inline | [CISO/CTO] | [DATE] |
| MSB-RR-013 | SSB.IR.8 | AWS SSB | Automated remediation | MSB provides automated enforcement for default SG rules (NetworkSecurityStack Lambda) and S3 public access blocks (S3SecurityStack Lambda); broader automated remediation (e.g., Security Hub automated response and remediation, AWS Systems Manager Automation) is outside MSB scope | Default SG secured automatically daily and on change events; S3 public access blocks enforced automatically daily and on bucket creation; GuardDuty findings published to SNS within 15 minutes; Security Hub findings available for custom automation rules | [CISO/CTO] | [DATE] |
| MSB-RR-014 | SSB.IR.9 | AWS SSB | Regular incident response exercises | Tabletop exercises and IR drills are an organizational and personnel process; they cannot be implemented in infrastructure-as-code | IR runbook documented; alerting pipeline tested as part of MSB deployment validation; teams encouraged to conduct annual tabletop exercises using the alert-response runbook as the basis | [CISO/CTO] | [DATE] |

### 3.5 Network Security Controls

| Risk ID | Control | Framework | Description | Why Accepted | Compensating Control | Risk Owner | Date Accepted |
|---|---|---|---|---|---|---|---|
| MSB-RR-015 | CIS 5.5 | CIS 3.0.0 | VPC peering routing tables configured for least access | MSB does not create or manage VPC peering connections; routing table configuration for peered VPCs is workload-specific and must be managed by the teams deploying those workloads | VPC changes and route table changes monitored by CloudWatch metric filter alarms (CIS 3.13, 3.14); NACL changes alarmed (CIS 4.16); Security Hub evaluates VPC security group and routing configurations continuously | [CISO/CTO] | [DATE] |
| MSB-RR-016 | SSB.NET.9 | AWS SSB | Network segmentation | MSB creates secure VPC infrastructure with VPC Flow Logs; application-tier segmentation (e.g., separate VPCs per environment, Transit Gateway hub-and-spoke) depends on workload architecture decisions outside MSB scope | VPC Flow Logs enabled with one-year CloudWatch Logs retention; default security groups secured to deny all; Security Hub evaluates EC2.2 (default VPC SG restricted) | [CISO/CTO] | [DATE] |
| MSB-RR-017 | SSB.NET.10 | AWS SSB | WAF for web applications | AWS WAF configuration is application-specific (requires knowledge of the web application's traffic patterns, endpoints, and threat model); cannot be generalized in a baseline CDK deployment | GuardDuty detects application-layer anomalies (e.g., brute force, credential stuffing) where applicable; CloudFront with AWS Managed Rules WAF is the recommended remediation pattern for teams deploying web applications | [CISO/CTO] | [DATE] |

---

## 4. Review and Sign-Off

This register has been reviewed and the residual risks documented above are formally accepted by the named risk owners.

| Role | Name | Signature | Date |
|---|---|---|---|
| Risk Owner (Engineering Lead) | | | |
| CISO / CTO | | | |
| Next scheduled review date | | | [DATE + 1 year] |

All residual risks in this register shall be re-evaluated:
- Annually, on or before the anniversary of the "Date Accepted" entries above
- Upon any material change to the MSB CDK project that affects controls relevant to the listed risks
- Upon any material change to the applicable frameworks (FSBP, CIS, AWS SSB)
- Following any security incident that is directly related to a listed residual risk

---

## 5. Change History

| Version | Date | Author | Description |
|---|---|---|---|
| 1.0 | [DATE] | [COMPANY NAME] Engineering | Initial formal risk register; converted from informal residual risk notes to auditor-facing format. All original risk content retained; reformatted as formal risk register with Risk IDs, compensating controls, and risk ownership. |
