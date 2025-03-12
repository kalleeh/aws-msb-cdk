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

## IAM Controls

| MSB Control | Control Type | FSBP | CIS AWS 3.0.0 | AWS SSB |
|-------------|--------------|------|--------------|---------|
| IAM Password Policy | Preventative | IAM.9 | 1.8, 1.9, 1.10, 1.11 | IAM.1 |
| MFA for Root Account | Preventative | IAM.6 | 1.5 | IAM.2 |
| MFA for IAM Users | Preventative | IAM.19 | 1.12 | IAM.3 |
| IAM Access Key Rotation | Preventative | IAM.3 | 1.14 | IAM.4 |
| IAM User Permissions Boundaries | Preventative | IAM.1 | 1.16 | IAM.5 |
| IAM Access Analyzer | Detective | IAM.8 | 1.20 | IAM.6 |
| IAM Roles for Service Access | Preventative | IAM.21 | 1.16, 1.17 | IAM.7 |
| IAM Policy Governance Monitoring | Detective | IAM.16 | - | - |
| Root Account Activity Monitoring | Detective | IAM.7 | 1.7 | - |

## Logging and Monitoring Controls

| MSB Control | Control Type | FSBP | CIS AWS 3.0.0 | AWS SSB |
|-------------|--------------|------|--------------|---------|
| CloudTrail Enabled | Detective | CloudTrail.1 | 3.1 | LOG.1 |
| CloudTrail Log File Validation | Preventative | CloudTrail.4 | 3.2 | LOG.2 |
| CloudTrail Logs Encrypted | Preventative | CloudTrail.2 | 3.5 | LOG.3 |
| CloudTrail Multi-Region | Detective | CloudTrail.5 | 3.1 | LOG.4 |
| CloudWatch Log Group Retention | Detective | CloudWatch.1 | 3.4 | LOG.5 |
| AWS Config Enabled | Detective | Config.1 | 3.5 | LOG.6 |
| GuardDuty Enabled | Detective | GuardDuty.1 | 3.8 | LOG.7 |
| Security Hub Enabled | Detective | SecurityHub.1 | 3.10 | LOG.8 |
| VPC Flow Logs | Detective | EC2.6 | 3.9 | NET.1 |
| S3 Bucket Access Logging | Detective | S3.9 | 3.6 | LOG.9 |

## Data Protection Controls

| MSB Control | Control Type | FSBP | CIS AWS 3.0.0 | AWS SSB |
|-------------|--------------|------|--------------|---------|
| S3 Block Public Access (Account) | Preventative | S3.1 | 2.1.2 | DAT.1 |
| S3 Bucket-Level Public Access Blocks | Preventative | S3.1 | 2.1.5 | DAT.1 |
| S3 Bucket Encryption | Preventative | S3.4 | 2.1.1 | DAT.2 |
| S3 Default Encryption | Preventative | S3.4 | 2.1.1 | DAT.2 |
| S3 Bucket SSL Enforcement | Preventative | S3.5 | 2.1.3 | DAT.3 |
| KMS Key Rotation | Preventative | KMS.4 | 3.7 | DAT.4 |
| EBS Volume Encryption by Default | Preventative | EC2.7 | 2.2.1 | DAT.5 |
| RDS Encryption | Preventative | RDS.3 | 2.3.1 | DAT.6 |
| CloudTrail Logs Encrypted | Preventative | CloudTrail.2 | 3.5 | DAT.7 |
| SNS Topic Encryption | Preventative | SNS.1 | - | DAT.8 |

## Network Security Controls

| MSB Control | Control Type | FSBP | CIS AWS 3.0.0 | AWS SSB |
|-------------|--------------|------|--------------|---------|
| Default Security Group Rules | Preventative | EC2.2 | 5.4 | NET.2 |
| Default VPC Security | Preventative | EC2.2 | 5.1 | NET.3 |
| VPC Flow Logs | Detective | EC2.6 | 3.9 | NET.1 |
| Security Group Monitoring | Detective | EC2.19 | 5.3 | NET.4 |
| Network ACL Monitoring | Detective | EC2.21 | - | NET.5 |
| VPC Endpoint Security | Preventative | EC2.15 | - | NET.6 |
| Restricted SSH Access | Preventative | EC2.13 | 5.2 | NET.7 |
| Restricted RDP Access | Preventative | EC2.14 | 5.2 | NET.8 |

## Compliance Controls

| MSB Control | Control Type | FSBP | CIS AWS 3.0.0 | AWS SSB |
|-------------|--------------|------|--------------|---------|
| AWS Config Rules | Detective | Config.1 | 3.5 | COM.1 |
| CIS Benchmark in Security Hub | Detective | SecurityHub.1 | 3.10 | COM.2 |
| Compliance Reporting | Detective | Config.3 | - | COM.3 |
| AWS Config Conformance Packs | Detective | Config.2 | - | COM.4 |
| Security Hub Findings | Detective | SecurityHub.2 | 3.10 | COM.5 |
| GuardDuty Findings | Detective | GuardDuty.1 | 3.8 | COM.6 |

## Incident Response Controls

| MSB Control | Control Type | FSBP | CIS AWS 3.0.0 | AWS SSB |
|-------------|--------------|------|--------------|---------|
| SNS Notifications | Responsive | SNS.2 | - | IR.1 |
| CloudWatch Alarms | Detective | CloudWatch.2 | 3.11 | IR.2 |
| EventBridge Rules | Detective | Events.1 | - | IR.3 |
| GuardDuty Findings Alerts | Responsive | GuardDuty.4 | 3.8 | IR.4 |
| Security Hub Findings Alerts | Responsive | SecurityHub.2 | 3.10 | IR.5 |
| IAM Access Analyzer Alerts | Responsive | IAM.8 | 1.20 | IR.6 |

## Residual Risk - Controls Not Implemented

The following controls from the security standards are not fully implemented in the MSB, representing residual risk:

| Control ID | Standard | Description | Risk Level | Reason for Exclusion |
|------------|----------|-------------|------------|----------------------|
| IAM.4 | FSBP | Hardware MFA for root account | Medium | Requires physical hardware; MSB focuses on programmatic controls |
| CIS 1.13 | CIS 3.0.0 | Ensure MFA is enabled for the "root" user | Medium | Requires manual setup; MSB monitors but can't enforce |
| CIS 1.4 | CIS 3.0.0 | Ensure no 'root' user access key exists | Medium | Requires operational procedure; MSB monitors but can't enforce removal |
| CIS 1.18 | CIS 3.0.0 | Ensure security contact information is registered | Low | Requires manual account configuration |
| CIS 3.3 | CIS 3.0.0 | Ensure CloudTrail log file validation is enabled | Low | Implemented but can't prevent future trails without validation |
| CIS 3.7 | CIS 3.0.0 | Ensure CloudTrail logs are encrypted at rest using KMS CMKs | Low | Implemented but can't prevent future trails without encryption |
| CIS 4.1-4.16 | CIS 3.0.0 | Various monitoring and alerting controls | Medium | MSB implements core monitoring but not all specific CIS monitoring recommendations |
| CIS 5.5 | CIS 3.0.0 | Ensure routing tables for VPC peering are "least access" | Medium | MSB creates secure VPCs but doesn't manage peering connections |
| SSB.IAM.8 | AWS SSB | Implement privileged access management | High | Requires additional tooling and processes beyond MSB |
| SSB.DAT.9 | AWS SSB | Implement data classification | Medium | Requires application-level controls and processes |
| SSB.DAT.10 | AWS SSB | Implement DLP controls | High | Requires additional tooling beyond infrastructure |
| SSB.LOG.10 | AWS SSB | Implement centralized log management | Medium | MSB centralizes logs but doesn't implement full log analysis |
| SSB.IR.7 | AWS SSB | Develop incident response playbooks | High | Requires operational procedures beyond infrastructure |
| SSB.IR.8 | AWS SSB | Implement automated remediation | Medium | MSB provides alerts but limited automated remediation |
| SSB.IR.9 | AWS SSB | Conduct regular incident response exercises | Medium | Requires operational procedures beyond infrastructure |
| SSB.NET.9 | AWS SSB | Implement network segmentation | Low | MSB creates basic network segmentation but may not meet all requirements |
| SSB.NET.10 | AWS SSB | Implement WAF for web applications | High | Requires application-specific configuration |

## Detailed Control Mappings

### IAM Controls

#### IAM Password Policy (Preventative)
- **Implementation**: `IAMStack` sets a strong password policy
- **FSBP**: IAM.9 - Ensure IAM password policy requires minimum complexity
- **CIS AWS 3.0.0**: 1.8-1.11 - Password policy requirements
- **AWS SSB**: IAM.1 - Implement strong password policy

#### IAM Access Key Rotation Monitoring (Detective)
- **Implementation**: `IAMStack` monitors access key age and sends notifications
- **FSBP**: IAM.3 - Ensure IAM access keys are rotated every 90 days or less
- **CIS AWS 3.0.0**: 1.14 - Ensure access keys are rotated every 90 days or less
- **AWS SSB**: IAM.4 - Rotate access keys regularly

#### IAM Policy Governance Monitoring (Detective)
- **Implementation**: `IAMStack` monitors and reports on direct policy attachments
- **FSBP**: IAM.16 - Ensure IAM policies are attached only to groups or roles
- **AWS SSB**: IAM.5 - Follow least privilege principle

#### Root Account Activity Monitoring (Detective)
- **Implementation**: `SecurityMonitoringStack` monitors and alerts on root account usage
- **FSBP**: IAM.7 - Eliminate use of root user for administrative tasks
- **CIS AWS 3.0.0**: 1.7 - Eliminate use of the 'root' user
- **AWS SSB**: IAM.2 - Secure root account

### Data Protection Controls

#### S3 Block Public Access (Account) (Preventative)
- **Implementation**: `S3SecurityStack` blocks public access at account level
- **FSBP**: S3.1 - Ensure S3 Block Public Access is enabled
- **CIS AWS 3.0.0**: 2.1.2 - Ensure S3 Block Public Access is enabled
- **AWS SSB**: DAT.1 - Enable S3 Block Public Access

#### S3 Bucket-Level Public Access Blocks (Preventative)
- **Implementation**: `S3SecurityStack` enforces bucket-level public access blocks
- **FSBP**: S3.1 - Ensure S3 Block Public Access is enabled
- **CIS AWS 3.0.0**: 2.1.5 - Ensure that S3 Buckets are configured with 'Block public access'
- **AWS SSB**: DAT.1 - Enable S3 Block Public Access

#### S3 Default Encryption (Preventative)
- **Implementation**: `S3SecurityStack` sets default encryption for S3 buckets
- **FSBP**: S3.4 - Ensure S3 buckets are encrypted
- **CIS AWS 3.0.0**: 2.1.1 - Ensure S3 Bucket Policy is set to deny HTTP requests
- **AWS SSB**: DAT.2 - Encrypt S3 buckets

#### EBS Volume Encryption by Default (Preventative)
- **Implementation**: `KMSStack` enables EBS encryption by default
- **FSBP**: EC2.7 - Ensure EBS volumes are encrypted
- **CIS AWS 3.0.0**: 2.2.1 - Ensure EBS volume encryption is enabled by default
- **AWS SSB**: DAT.5 - Encrypt EBS volumes

### Network Security Controls

#### Default Security Group Rules (Preventative)
- **Implementation**: `NetworkSecurityStack` secures default security groups
- **FSBP**: EC2.2 - Ensure default security groups restrict all traffic
- **CIS AWS 3.0.0**: 5.4 - Ensure default security groups restrict all traffic
- **AWS SSB**: NET.2 - Secure default security groups