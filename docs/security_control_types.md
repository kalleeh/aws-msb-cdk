# Security Control Types in AWS MSB

The AWS Minimum Security Baseline (MSB) implements security controls across four main categories:

## Preventative Controls

Preventative controls are designed to stop security incidents before they occur. They establish guardrails that prevent misconfigurations, unauthorized access, and data exposure.

### Key Preventative Controls in MSB:

| Control | Implementation | Description |
|---------|---------------|-------------|
| IAM Password Policy | `IAMStack` | Enforces strong password requirements including length, complexity, and rotation |
| S3 Block Public Access | `S3SecurityStack` | Prevents public access to S3 buckets at the account level |
| S3 Bucket-Level Public Access | `S3SecurityStack` | Ensures all buckets have public access blocks enabled |
| S3 Default Encryption | `S3SecurityStack` | Sets default encryption for all new S3 buckets |
| KMS Key Rotation | `KMSStack` | Automatically rotates encryption keys to limit the impact of key compromise |
| EBS Volume Encryption by Default | `KMSStack` | Ensures all new EBS volumes are encrypted |
| Default Security Group Rules | `NetworkSecurityStack` | Restricts all inbound and outbound traffic in default security groups |
| SSL Enforcement | `S3SecurityStack` | Requires SSL for all S3 bucket access |
| VPC Endpoint Security | `VpcStack` | Secures VPC endpoints with restrictive policies |
| IAM Permissions Boundaries | `IAMStack` | Limits maximum permissions that can be granted to IAM entities |

## Detective Controls

Detective controls identify potential security issues, policy violations, or threats after they occur. They provide visibility into your AWS environment and help identify misconfigurations or suspicious activities.

### Key Detective Controls in MSB:

| Control | Implementation | Description |
|---------|---------------|-------------|
| CloudTrail | `LoggingStack` | Records AWS API calls for auditing and investigation |
| VPC Flow Logs | `NetworkSecurityStack` | Captures network traffic metadata for security analysis |
| AWS Config | `LoggingRegionalStack` | Records resource configurations and changes over time |
| GuardDuty | `SecurityRegionalStack` | Provides intelligent threat detection |
| Security Hub | `SecurityRegionalStack` | Aggregates security findings from multiple AWS services |
| IAM Access Analyzer | `SecurityRegionalStack` | Identifies resources shared with external entities |
| CloudWatch Log Group Retention | `LoggingStack` | Ensures logs are retained for compliance and investigation |
| AWS Config Rules | `ComplianceStack` | Evaluates resources against best practices |
| IAM Access Key Rotation Monitoring | `IAMStack` | Monitors access keys for rotation compliance |
| IAM Policy Governance Monitoring | `IAMStack` | Identifies IAM users with directly attached policies |
| Root Account Activity Monitoring | `SecurityMonitoringStack` | Monitors and alerts on root account usage |

## Responsive Controls

Responsive controls help you address and remediate security issues once they're detected. They enable automated or manual responses to security events.

### Key Responsive Controls in MSB:

| Control | Implementation | Description |
|---------|---------------|-------------|
| SNS Notifications | `LoggingStack` | Sends alerts for security events |
| EventBridge Rules | `SecurityMonitoringStack` | Routes security events to appropriate targets |
| GuardDuty Findings Alerts | `SecurityMonitoringStack` | Notifies about potential threats detected by GuardDuty |
| Security Hub Findings Alerts | `SecurityMonitoringStack` | Notifies about security findings from Security Hub |
| CloudWatch Alarms | `SecurityMonitoringStack` | Triggers alerts based on metric thresholds |
| IAM Access Analyzer Alerts | `SecurityMonitoringStack` | Notifies about resources exposed to external access |

## Proactive Controls

Proactive controls continuously improve your security posture by identifying and addressing potential issues before they become problems. They help you stay ahead of emerging threats and evolving best practices.

### Key Proactive Controls in MSB:

| Control | Implementation | Description |
|---------|---------------|-------------|
| CIS Benchmark in Security Hub | `ComplianceStack` | Evaluates environment against industry best practices |
| Compliance Reporting | `ComplianceStack` | Provides regular reports on compliance status |
| AWS Config Conformance Packs | `ComplianceStack` | Evaluates resources against predefined compliance frameworks |
| Security Hub Standards | `SecurityRegionalStack` | Enables security standards in Security Hub |
| Resource Tagging | `VpcStack` | Enforces consistent tagging for security classification |
| Security Group Monitoring | `SecurityMonitoringStack` | Monitors changes to security groups |
| Network ACL Monitoring | `SecurityMonitoringStack` | Monitors changes to network ACLs |

## Control Implementation by Stack

| Stack | Control Types | Key Controls |
|-------|--------------|-------------|
| `IAMStack` | Preventative | Password Policy, Permissions Boundaries, IAM Groups |
| `S3SecurityStack` | Preventative | Block Public Access, Bucket Encryption, SSL Enforcement |
| `LoggingStack` | Detective, Responsive | CloudTrail, SNS Notifications, Log Retention |
| `KMSStack` | Preventative | Key Rotation, Key Policies |
| `NetworkSecurityStack` | Preventative, Detective | VPC Flow Logs, Default Security Group Rules |
| `SecurityRegionalStack` | Detective | GuardDuty, Security Hub, IAM Access Analyzer |
| `SecurityMonitoringStack` | Detective, Responsive | EventBridge Rules, Security Findings Alerts |
| `ComplianceStack` | Detective, Proactive | AWS Config Rules, CIS Benchmark, Compliance Reporting |
| `VpcStack` | Preventative | VPC Endpoint Security, Network Segmentation |
| `LoggingRegionalStack` | Detective | AWS Config, Regional Logging |