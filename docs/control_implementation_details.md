# AWS MSB Control Implementation Details

This document provides detailed information about how each security control is implemented in the AWS MSB CDK project, including the specific AWS services used, configuration details, and the security benefits provided.

## Deployment Context Variables

Several implementation choices are governed by CDK context variables passed at deploy time:

| Context variable | Default | Effect |
|---|---|---|
| `notification_email` | (required) | Email address for SNS subscriptions and the security contact |
| `security_contact_phone` | (none) | Phone number for the account security contact (CIS 1.18). If omitted the custom resource is not created |
| `enable_object_lock` | `false` | When `true`, enables S3 Object Lock (WORM) on the central logs bucket with 365-day Governance retention |
| `control_tower_managed` | `false` | When `true`, skips GuardDuty, Security Hub, Config recorder/channel, CloudTrail, Inspector, and Macie — these are already managed at the Organisation level by Control Tower |
| `enable_waf` | `false` | When `true`, deploys the optional `WafStack` with a WAFv2 Regional Web ACL per target region |
| `global_region` | `us-east-1` | AWS region for all global (account-scoped) stacks |
| `target_regions` | `[global_region]` | List of regions for regional stacks |

Example usage:
```
cdk deploy --all \
  --context notification_email=security@example.com \
  --context security_contact_phone=+12025551234 \
  --context enable_object_lock=true \
  --context enable_waf=true
```

---

## IAM Controls

### IAM Password Policy

**Implementation Stack**: `IAMStack`

**AWS Service**: AWS IAM

**Configuration**:
```python
CfnResource(self, "PasswordPolicy",
    type="AWS::IAM::AccountPasswordPolicy",
    properties={
        "MinimumPasswordLength": 16,
        "RequireUppercaseCharacters": True,
        "RequireLowercaseCharacters": True,
        "RequireSymbols": True,
        "RequireNumbers": True,
        "PasswordReusePrevention": 24,
        "HardExpiry": False,
        "AllowUsersToChangePassword": True
        # MaxPasswordAge intentionally omitted — NIST SP 800-63B and CIS v3.0.0
        # recommend against periodic password expiration.
    }
)
```

**Security Benefits**:
- Enforces strong passwords (16-char minimum) that are harder to crack
- Prevents password reuse across 24 previous passwords
- No forced expiry — aligns with NIST SP 800-63B which recommends against periodic rotation as it encourages predictable patterns
- Aligns with CIS AWS Foundations Benchmark v3.0.0 recommendations 1.8, 1.9, 1.11-1.14

### Account Security Contact (CIS 1.18 / FSBP Account.1)

**Implementation Stack**: `IAMStack` — `create_security_contact()`

**AWS Service**: AWS Custom Resource (`account:PutAlternateContact`)

**Prerequisites**: Both `--context notification_email=...` and `--context security_contact_phone=...` must be provided. If either is absent, the custom resource is skipped and no security contact is set.

**Configuration**:
```python
security_contact = cr.AwsCustomResource(self, "SecurityContact",
    install_latest_aws_sdk=False,
    on_create=cr.AwsSdkCall(
        service="Account",
        action="putAlternateContact",
        parameters={
            "AlternateContactType": "SECURITY",
            "EmailAddress": notification_email,
            "Name": "Security Contact",
            "PhoneNumber": security_contact_phone,
            "Title": "Security"
        },
        physical_resource_id=cr.PhysicalResourceId.of("security-contact")
    ),
    on_update=cr.AwsSdkCall(...),   # same parameters — idempotent
    policy=cr.AwsCustomResourcePolicy.from_statements([
        iam.PolicyStatement(
            actions=["account:PutAlternateContact"],
            resources=["*"]
        )
    ])
)
```

The custom resource uses an `on_update` handler identical to `on_create` so that a `cdk deploy` with changed contact details always keeps the contact current.

A Security Hub Automation Rule (`MSB-Suppress-ManualControls-AccountContact`) in `SecurityRegionalStack` suppresses the FSBP Account.1 `FAILED` finding once the contact is set programmatically.

**Security Benefits**:
- Sets the SECURITY alternate contact automatically on every deploy — no manual console action required
- Enables AWS to reach the security team for abuse notifications, security bulletins, and vulnerability disclosures
- Aligns with CIS AWS Foundations Benchmark v3.0.0 recommendation 1.18 and FSBP Account.1

### IAM Policy Governance Monitoring (FSBP IAM.16)

**Implementation Stack**: `IAMStack`

**AWS Service**: AWS Lambda, Amazon EventBridge

**Configuration**:
```python
iam_policy_checker = lambda_.Function(self, "IAMPolicyChecker",
    function_name="msb-iam-policy-checker",
    runtime=lambda_.Runtime.PYTHON_3_13,
    handler="index.handler",
    code=lambda_.Code.from_asset("lambda/iam_policy_checker"),
    timeout=Duration.seconds(60),
    environment={
        "NOTIFICATION_TOPIC_ARN": self.notifications_topic.topic_arn
    }
)

# Daily schedule
events.Rule(self, "IAMPolicyCheckerSchedule",
    schedule=events.Schedule.rate(Duration.days(1)),
    targets=[targets.LambdaFunction(iam_policy_checker)]
)

# Event-driven: fires on AttachUserPolicy / PutUserPolicy
policy_attachment_rule = events.Rule(self, "IAMPolicyAttachmentRule",
    event_pattern=events.EventPattern(
        source=["aws.iam"],
        detail_type=["AWS API Call via CloudTrail"],
        detail={
            "eventSource": ["iam.amazonaws.com"],
            "eventName": ["AttachUserPolicy", "PutUserPolicy"]
        }
    ),
    targets=[targets.LambdaFunction(iam_policy_checker)]
)
```

A CloudWatch alarm (`msb-iam-policy-checker-errors-{region}`) triggers on any Lambda error and routes the alarm action to the SNS notifications topic so that silent failures are surfaced immediately.

**Security Benefits**:
- Identifies IAM users with directly attached policies (inline or managed)
- Reports via SNS so operators can migrate policies to groups
- Addresses FSBP IAM.16
- No manual monitoring required; error alarm prevents silent failures

### IAM Access Analyzer (CIS 1.20)

**Implementation Stack**: `IAMStack` — `create_access_analyzer()`

**AWS Service**: AWS IAM Access Analyzer

**Configuration**:
```python
accessanalyzer.CfnAnalyzer(self, "IAMAccessAnalyzer",
    analyzer_name=f"msb-access-analyzer-{self.account}-{self.region}",
    type="ACCOUNT"
)
```

**Security Benefits**:
- Identifies resources (S3 buckets, IAM roles, KMS keys, etc.) shared with external entities
- Helps prevent unintended access to your resources
- Supports the principle of least privilege
- Aligns with CIS AWS Foundations Benchmark v3.0.0 recommendation 1.20

### AWS Support Role (CIS 1.17)

**Implementation Stack**: `IAMStack`

**AWS Service**: AWS IAM

**Configuration**: An IAM Role named `msb-aws-support-role` is created with `AWSSupportAccess` attached and `AssumedBy: AccountRootPrincipal`. This satisfies the CIS requirement that a support role exists without granting it broad cross-service permissions.

---

## Logging and Monitoring Controls

### CloudTrail

**Implementation Stack**: `LoggingStack`

**AWS Service**: AWS CloudTrail

**Control Tower note**: When `--context control_tower_managed=true`, the MSB CloudTrail is not created. Instead, the Control Tower organisation trail's CloudWatch Logs group (`aws-controltower/CloudTrailLogs` by default, overridable via `--context cloudtrail_log_group_name=...`) is imported so that all metric filters and alarms defined below can still attach to it.

**Configuration**:
```python
trail = cloudtrail.Trail(self, "CloudTrail",
    bucket=logs_bucket,
    send_to_cloud_watch_logs=True,
    cloud_watch_logs_retention=logs.RetentionDays.ONE_YEAR,
    is_multi_region_trail=True,
    include_global_service_events=True,
    enable_file_validation=True,
    management_events=cloudtrail.ReadWriteType.ALL,
    trail_name="msb-cloudtrail",
    encryption_key=cloudtrail_key   # KMS key from KMSStack or auto-created
)
```

Advanced event selectors (via `CfnTrail` escape hatch) additionally capture all S3 data events and all Lambda invoke events.

**Security Benefits**:
- Records API calls for auditing, compliance, and security analysis
- Enables investigation of security incidents
- Provides accountability for all actions taken in the AWS account
- Aligns with CIS AWS Foundations Benchmark v3.0.0 recommendations 3.1-3.7

### CloudWatch Metric Filters and Alarms (CIS 3.x / 4.x)

**Implementation Stack**: `LoggingStack`

**AWS Service**: Amazon CloudWatch Logs, Amazon CloudWatch Alarms, Amazon SNS

All alarms use `TreatMissingData.NOT_BREACHING` and notify the `msb-notifications-{region}` SNS topic.

| Alarm name | Control | Metric filter pattern |
|---|---|---|
| `MSB-UnauthorizedAPICalls` | CIS 3.1 | `errorCode = *UnauthorizedOperation OR AccessDenied*` |
| `MSB-ConsoleSignInWithoutMFA` | CIS 3.2 | `ConsoleLogin` + `MFAUsed != Yes` + `IAMUser` + `Success` |
| `MSB-CloudTrailConfigChanges` | CIS 3.5 | `CreateTrail / UpdateTrail / DeleteTrail / StartLogging / StopLogging` |
| `MSB-ConsoleAuthFailures` | CIS 3.6 | `ConsoleLogin` + `Failed authentication` (threshold: 3) |
| `MSB-KMSKeyChanges` | CIS 3.7 | `DisableKey / ScheduleKeyDeletion` |
| `MSB-S3BucketPolicyChanges` | CIS 3.8 | `PutBucketAcl / PutBucketPolicy / DeleteBucketPolicy` etc. |
| `MSB-AWSConfigChanges` | CIS 3.9 | `StopConfigurationRecorder / DeleteDeliveryChannel` etc. |
| `MSB-NetworkGatewayChanges` | CIS 3.12 | `CreateCustomerGateway / AttachInternetGateway` etc. |
| `MSB-RouteTableChanges` | CIS 3.13 | `CreateRoute / ReplaceRoute / DeleteRouteTable` etc. |
| `MSB-VPCChanges` | CIS 3.14 | `CreateVpc / DeleteVpc / ModifyVpcAttribute` etc. |
| `MSB-IAMPolicyChanges` | CIS 4.4 | `PutGroupPolicy / CreatePolicy / AttachRolePolicy` etc. |
| `MSB-SecurityGroupChanges` | CIS 4.15 | `AuthorizeSecurityGroupIngress / CreateSecurityGroup` etc. |
| `MSB-NACLChanges` | CIS 4.16 | `CreateNetworkAcl / DeleteNetworkAclEntry` etc. |

### SNS Delivery Status Logging (FSBP SNS.2)

**Implementation Stacks**: `NotificationsRegionalStack` (all non-global regions) and `LoggingStack` (global region when `notifications_topic` is not passed in)

**AWS Service**: Amazon SNS, AWS IAM, Amazon CloudWatch Logs

Both stacks use the CDK `CfnTopic` escape hatch to set delivery-status feedback properties that are not exposed on the L2 `sns.Topic` construct:

```python
# IAM role that SNS assumes to write delivery logs
feedback_role = iam.Role(self, "SNSFeedbackRole",
    assumed_by=iam.ServicePrincipal("sns.amazonaws.com"),
    inline_policies={"CloudWatchLogs": iam.PolicyDocument(statements=[
        iam.PolicyStatement(
            actions=[
                "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents",
                "logs:GetLogDelivery", "logs:UpdateLogDelivery", "logs:DeleteLogDelivery",
                "logs:ListLogDeliveries", "logs:PutRetentionPolicy",
            ],
            resources=["*"]   # CloudWatch Logs delivery APIs require wildcard
        )
    ])}
)

# Escape hatch: set CfnTopic attributes not available on L2
cfn_topic = self.notifications_topic.node.default_child
cfn_topic.http_success_feedback_role_arn = feedback_role.role_arn
cfn_topic.http_failure_feedback_role_arn = feedback_role.role_arn
cfn_topic.http_success_feedback_sample_rate = 100
cfn_topic.sqs_success_feedback_role_arn = feedback_role.role_arn
cfn_topic.sqs_failure_feedback_role_arn = feedback_role.role_arn
cfn_topic.sqs_success_feedback_sample_rate = 100
cfn_topic.lambda_success_feedback_role_arn = feedback_role.role_arn
cfn_topic.lambda_failure_feedback_role_arn = feedback_role.role_arn
cfn_topic.lambda_success_feedback_sample_rate = 100
```

**Security Benefits**:
- Logs successful and failed deliveries to CloudWatch Logs for HTTP/S, SQS, and Lambda subscribers
- Satisfies FSBP SNS.2 without requiring a separate custom resource
- Provides an audit trail for notification delivery failures

### SNS Topic (Regional)

**Implementation Stack**: `NotificationsRegionalStack` (for non-global regions) / `LoggingStack` (global region)

**AWS Service**: Amazon SNS, AWS KMS

Every deployed region gets its own SNS topic (`msb-notifications-{region}`) encrypted with a dedicated regional KMS key (`alias/msb-sns-notifications-{region}`). This is required because EventBridge does not support cross-region SNS targets; each regional stack needs a same-region delivery endpoint.

**Security Benefits**:
- Ensures EventBridge rules in each region have a same-region delivery target
- All topics are KMS-encrypted (satisfies FSBP SNS.1)
- Delivery status logging enabled on every topic (satisfies FSBP SNS.2)

### VPC Flow Logs

**Implementation Stack**: `NetworkSecurityStack`

**AWS Service**: Amazon VPC Flow Logs, Amazon CloudWatch Logs

**Configuration**:
```python
flow_logs_group = logs.LogGroup(self, "VPCFlowLogsGroup",
    log_group_name=f"/aws/vpc/flowlogs/{self.account}/{self.region}",
    retention=logs.RetentionDays.ONE_YEAR,
    removal_policy=RemovalPolicy.RETAIN
)

flow_logs_role = iam.Role(self, "VPCFlowLogsRole",
    assumed_by=iam.ServicePrincipal("vpc-flow-logs.amazonaws.com"),
    role_name=f"msb-vpc-flow-logs-role-{self.region}"
)
```

The `FlowLogDestination` object is passed into `VpcStack`, where it is attached to the MSB VPC via `ec2.FlowLog`.

**Security Benefits**:
- Captures network traffic metadata for security analysis and forensics
- Enables detection of unusual traffic patterns
- Aligns with CIS AWS Foundations Benchmark v3.0.0 recommendation 3.9

### GuardDuty (FSBP GD.1 / CIS 3.8)

**Implementation Stack**: `SecurityRegionalStack`

**AWS Service**: Amazon GuardDuty

**Control Tower note**: Skipped when `--context control_tower_managed=true`. Control Tower enables GuardDuty at the Organisation level; creating a separate detector here would conflict.

**Configuration**:
```python
detector = guardduty.CfnDetector(self, "GuardDutyDetector",
    enable=True,
    finding_publishing_frequency="FIFTEEN_MINUTES",
    features=[
        # S3_DATA_EVENTS, EKS_AUDIT_LOGS, EBS_MALWARE_PROTECTION,
        # RDS_LOGIN_EVENTS, LAMBDA_NETWORK_LOGS,
        # EKS_RUNTIME_MONITORING, RUNTIME_MONITORING
    ]
)
```

All available protection plans (S3, EKS audit logs, EBS malware, RDS login, Lambda network, EKS runtime, runtime monitoring) are enabled. Finding publishing frequency is 15 minutes.

**GuardDuty Findings Bucket**:

GuardDuty findings are exported to a dedicated S3 bucket (`msb-guardduty-findings-{account}-{region}`) with:
- S3-managed encryption and all public access blocked
- Versioning enabled
- Server access logs written to `msb-guardduty-access-logs-{account}-{region}` with prefix `guardduty-findings/`
- Lifecycle: transition to Intelligent-Tiering after 30 days, expire after 365 days

The access-logs bucket itself has a 90-day expiry lifecycle and does not enable its own server access logs (recursive logging is not recommended by AWS and is explicitly suppressed in cdk-nag).

**Security Benefits**:
- Provides intelligent threat detection across all enabled protection plans
- Continuously monitors for malicious activity and unauthorized behavior
- Findings are durably stored in S3 with access logging for audit purposes
- Aligns with CIS AWS Foundations Benchmark v3.0.0 recommendation 3.8

### AWS Config Recorder and Delivery Channel

**Implementation Stack**: `LoggingRegionalStack`

**AWS Service**: AWS Config

**Control Tower note**: Skipped when `--context control_tower_managed=true`. Control Tower creates its own Config recorder per region.

**Configuration**:
```python
recorder = config.CfnConfigurationRecorder(self, "ConfigRecorder",
    role_arn=config_role.role_arn,
    recording_group=config.CfnConfigurationRecorder.RecordingGroupProperty(
        all_supported=True
    )
)
delivery_channel = config.CfnDeliveryChannel(self, "ConfigDeliveryChannel",
    s3_bucket_name=logs_bucket.bucket_name,
    s3_key_prefix="config",
    config_snapshot_delivery_properties=...  # Six_Hours snapshot frequency
)
```

Config logs are written to `msb-logs-{account}-{region}` under the `config/` prefix.

### Root Account Activity Monitoring

**Implementation Stack**: `SecurityMonitoringStack`

**AWS Service**: Amazon EventBridge, Amazon SNS

**Configuration**: EventBridge rules watch for `aws.signin` events where `userIdentity.type = Root` and route them to the SNS notifications topic.

**Security Benefits**:
- Provides real-time monitoring of root account usage
- Sends immediate alerts when root account is used
- Addresses CIS AWS Foundations Benchmark v3.0.0 control 1.7 and FSBP IAM.7
- No operational overhead once implemented

---

## Data Protection Controls

### S3 Block Public Access (Account Level, CIS 2.1.2)

**Implementation Stack**: `S3SecurityStack`

**AWS Service**: Amazon S3 (S3Control API)

**Configuration**:
```python
block_public_access = cr.AwsCustomResource(self, "BlockPublicAccess",
    on_create=cr.AwsSdkCall(
        service="S3Control",
        action="putPublicAccessBlock",
        parameters={
            "AccountId": self.account,
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "BlockPublicPolicy": True,
                "IgnorePublicAcls": True,
                "RestrictPublicBuckets": True
            }
        },
        physical_resource_id=cr.PhysicalResourceId.of("s3-block-public-access")
    ),
    policy=cr.AwsCustomResourcePolicy.from_statements([
        iam.PolicyStatement(
            actions=["s3:PutAccountPublicAccessBlock"],
            resources=["*"]
        )
    ])
)
```

**Security Benefits**:
- Prevents public access to any S3 bucket at the account level, overriding bucket-level settings
- Provides a defence-in-depth layer on top of bucket-level blocks
- Aligns with CIS AWS Foundations Benchmark v3.0.0 recommendation 2.1.2

### S3 Bucket-Level Public Access Blocks (CIS 2.1.5)

**Implementation Stack**: `S3SecurityStack`

**AWS Service**: AWS Lambda, Amazon EventBridge

A Lambda function (`msb-s3-public-access-checker`, Python 3.13) checks every bucket in the account and calls `s3:PutBucketPublicAccessBlock` on any bucket that does not have all four block settings enabled. It runs daily via EventBridge schedule and is also triggered on `CreateBucket` CloudTrail events for near-real-time enforcement.

A CloudWatch alarm (`msb-s3-public-access-checker-errors-{region}`) triggers on any Lambda error and routes to the SNS notifications topic.

**Security Benefits**:
- Ensures all S3 buckets have public access blocks enabled at the bucket level
- Automatically remediates non-compliant buckets within one day (or within minutes on new bucket creation)
- Addresses CIS AWS Foundations Benchmark v3.0.0 control 2.1.5
- Error alarm prevents silent remediation failures

### S3 Object Lock / WORM (FSBP S3.11 / CIS 3.11)

**Implementation Stack**: `LoggingStack`

**AWS Service**: Amazon S3 Object Lock

**Control**: Opt-in via `--context enable_object_lock=true`. Default is `false`.

When enabled, the central logs bucket (`msb-logs-{account}-{region}`) is created with:
```python
object_lock_enabled=True,
object_lock_default_retention=s3.ObjectLockRetention.governance(Duration.days(365))
```

This enforces WORM immutability in **Governance** mode for 365 days. Object Lock must be configured at bucket creation time; it cannot be retrofitted to an existing bucket. Deploying with `enable_object_lock=true` on a pre-existing stack will create a new bucket.

**Security Benefits**:
- Prevents log tampering by making objects immutable for the retention period
- Governance mode allows authorised principals with `s3:BypassGovernanceRetention` to override if needed
- Addresses FSBP S3.11 and CIS 3.11

### KMS Key Rotation

**Implementation Stack**: `KMSStack`

**AWS Service**: AWS KMS

Five customer-managed keys are created, all with `enable_key_rotation=True` and `RemovalPolicy.RETAIN`:

| Key alias | Purpose |
|---|---|
| `msb/master-key` | General encryption |
| `msb/cloudtrail-key` | CloudTrail log encryption |
| `msb/s3-key` | S3 encryption |
| `msb/rds-key` | RDS encryption |
| `msb/ebs-key` | EBS default encryption |

**Security Benefits**:
- Automatically rotates encryption keys annually to limit the impact of key compromise
- Maintains backward compatibility for encrypted data
- Aligns with CIS AWS Foundations Benchmark v3.0.0 recommendation 3.7 and FSBP KMS.4

### EBS Volume Encryption by Default (CIS 2.2.1)

**Implementation Stack**: `KMSStack`

**AWS Service**: Amazon EC2, AWS KMS

**Configuration**: Two custom resources call `ec2:EnableEbsEncryptionByDefault` and `ec2:ModifyEbsDefaultKmsKeyId` (pointing to `msb/ebs-key`) so that all new EBS volumes in the account are automatically encrypted with the MSB-managed key.

**Security Benefits**:
- Ensures all new EBS volumes are encrypted by default
- Uses a dedicated KMS key for EBS encryption
- Addresses CIS AWS Foundations Benchmark v3.0.0 control 2.2.1

---

## Network Security Controls

### Default Security Group Remediation (CIS 5.4)

**Implementation Stack**: `NetworkSecurityStack`

**AWS Service**: Amazon EC2, AWS Lambda, Amazon EventBridge

A Lambda function (`msb-secure-default-sg`, Python 3.13) enumerates all VPCs, finds each VPC's default security group, and revokes all ingress rules and any custom egress rules. It runs daily and is additionally triggered by `AuthorizeSecurityGroupIngress`, `AuthorizeSecurityGroupEgress`, and `CreateSecurityGroup` CloudTrail events so that violations are remediated within minutes.

A CloudWatch alarm (`msb-default-sg-remediation-errors-{region}`) triggers on any Lambda error and routes to the SNS notifications topic.

**Security Benefits**:
- Restricts all inbound and outbound traffic in default security groups across all VPCs
- Prevents accidental use of default security groups with permissive rules
- Continuously monitors and automatically remediates non-compliant groups
- Error alarm prevents silent remediation failures
- Aligns with CIS AWS Foundations Benchmark v3.0.0 recommendation 5.4

### Security Group Monitoring

**Implementation Stack**: `SecurityMonitoringStack`

**AWS Service**: Amazon EventBridge, Amazon SNS

EventBridge rules detect changes to security groups (`AuthorizeSecurityGroupIngress`, `RevokeSecurityGroupIngress`, `CreateSecurityGroup`, `DeleteSecurityGroup`, etc.) and forward events to the SNS notifications topic.

**Security Benefits**:
- Monitors changes to security groups in real-time
- Enables quick response to unauthorised or suspicious changes
- Aligns with CIS AWS Foundations Benchmark v3.0.0 recommendation 5.3

### VPC and Network Architecture

**Implementation Stack**: `VpcStack`

**AWS Service**: Amazon VPC

The MSB VPC (`msb-vpc-{region}`, CIDR `10.0.0.0/16`) contains three subnet tiers across two AZs:
- **Public** — internet-facing resources; NAT gateway for outbound
- **Private with egress** — application tier; outbound via NAT gateway
- **Isolated** — database tier; no internet routing

Interface VPC endpoints are created for: SSM, SSMMessages, EC2Messages, KMS, CloudWatch Logs, CloudWatch Monitoring, SQS, SNS, Secrets Manager, ECR API, ECR Docker, ECS, and Lambda. Gateway endpoints are created for S3 and DynamoDB.

### WAFv2 Web ACL (optional)

**Implementation Stack**: `WafStack`

**AWS Service**: AWS WAFv2

**Control**: Opt-in — deployed only when `--context enable_waf=true`.

The Web ACL is REGIONAL scope (for ALB and API Gateway association) with the following rules in priority order:

| Priority | Rule | Action |
|---|---|---|
| 10 | `AWSManagedRulesCommonRuleSet` | Inherit rule group defaults |
| 20 | `AWSManagedRulesKnownBadInputsRuleSet` | Inherit rule group defaults |
| 30 | `AWSManagedRulesAmazonIpReputationList` | Inherit rule group defaults |
| 40 | `AWSManagedRulesAnonymousIpList` | Inherit rule group defaults |
| 50 | `AWSManagedRulesSQLiRuleSet` | Inherit rule group defaults |
| 60 | `RateLimitPerIP` (rate-based, 2000 req/5 min) | Block |

The Web ACL ARN is exported as `MSB-WAF-WebACLArn-{region}` for use when associating with ALBs, CloudFront distributions, or API Gateway stages.

CloudWatch metrics and sampled requests are enabled on all rules and on the Web ACL itself.

**Security Benefits**:
- Blocks common web exploits (OWASP Top 10 and known bad inputs)
- Blocks requests from IPs on the AWS threat intelligence list and anonymous/VPN IPs
- Protects against SQL injection
- Limits request rates per source IP to mitigate DDoS and credential-stuffing attacks

---

## Compliance Controls

### AWS Config Rules

**Implementation Stack**: `ComplianceStack`

**AWS Service**: AWS Config

Config managed rules are deployed per region. They detect (but do not remediate) non-compliant resources; findings appear in the Security Hub and the MSB Compliance Dashboard.

| Rule identifier | Control |
|---|---|
| `ENCRYPTED_VOLUMES` | FSBP EC2.3 / CIS 2.2.1 — EBS volumes encrypted |
| `EC2_IMDSV2_CHECK` | FSBP EC2.8 — IMDSv2 required |
| `CMK_BACKING_KEY_ROTATION_ENABLED` | FSBP KMS.4 — KMS key rotation |
| `RDS_INSTANCE_DELETION_PROTECTION_ENABLED` | FSBP RDS.3 — RDS deletion protection |
| `RDS_STORAGE_ENCRYPTED` | FSBP RDS.2 — RDS storage encrypted |
| `SNS_ENCRYPTED_KMS` | FSBP SNS.1 — SNS topics encrypted |
| `ACCESS_KEYS_ROTATED` (maxAge: 45 days) | FSBP IAM.3 / CIS 1.14 — access key rotation |
| `MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS` | FSBP IAM.5 / CIS 1.10 — MFA for console |
| `IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS` | FSBP IAM.1 — no full admin policies |
| `IAM_ROOT_ACCESS_KEY_CHECK` | CIS 1.4 / FSBP IAM.4 — no root access keys |
| `ROOT_ACCOUNT_MFA_ENABLED` | CIS 1.5 — root MFA enabled |
| `IAM_PASSWORD_POLICY` | CIS 1.7 — password policy requirements |
| `S3_BUCKET_PUBLIC_READ_PROHIBITED` | FSBP S3.1 |
| `S3_BUCKET_PUBLIC_WRITE_PROHIBITED` | FSBP S3.2 |
| `S3_BUCKET_SSL_REQUESTS_ONLY` | FSBP S3.5 |
| `S3_BUCKET_OBJECT_LOCK_ENABLED` | FSBP S3.11 |
| `CLOUD_TRAIL_ENABLED` | FSBP CloudTrail.1 |
| `CLOUD_TRAIL_ENCRYPTION_ENABLED` | FSBP CloudTrail.2 |
| `CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED` | FSBP CloudTrail.4 |
| `VPC_FLOW_LOGS_ENABLED` | FSBP EC2.6 / CIS 3.9 |
| `INCOMING_SSH_DISABLED` | FSBP EC2.19 / CIS 5.1 |
| `RESTRICTED_INCOMING_TRAFFIC` (port 3389) | FSBP EC2.20 / CIS 5.2 |
| `RESTRICTED_INCOMING_TRAFFIC` (ports 20,21,23,3306,4333) | FSBP EC2.18 |
| `SUBNET_AUTO_ASSIGN_PUBLIC_IP_DISABLED` | FSBP EC2.15 |
| `EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK` | FSBP EC2.1 |
| `LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED` | FSBP Lambda.1 |
| `LAMBDA_FUNCTION_SETTINGS_CHECK` (runtime list) | FSBP Lambda.2 |
| `EC2_INSTANCE_MANAGED_BY_SSM` | FSBP SSM.1 |

A CloudWatch dashboard (`MSB-Compliance-Dashboard`) displays `ComplianceByConfigRule` metrics for COMPLIANT vs NON_COMPLIANT resources.

### Security Hub Standards

**Implementation Stack**: `SecurityRegionalStack`

**AWS Service**: AWS Security Hub

**Control Tower note**: Skipped when `--context control_tower_managed=true`.

**Configuration**:
```python
security_hub = securityhub.CfnHub(self, "SecurityHub")

fsbp_standard = securityhub.CfnStandard(self, "FBSPStandard",
    standards_arn="arn:aws:securityhub:{region}::standards/aws-foundational-security-best-practices/v/1.0.0"
)
cis_standard = securityhub.CfnStandard(self, "CISv3Standard",
    standards_arn="arn:aws:securityhub:{region}::standards/cis-aws-foundations-benchmark/v/3.0.0"
)
```

Two Security Hub Automation Rules are also created:
- `MSB-Suppress-ManualControls-AccountContact` — suppresses FSBP Account.1 `NEW/FAILED` findings (the contact is set programmatically)
- `MSB-Suppress-ManualControls-RootMFA` — suppresses FSBP IAM.4/IAM.6/IAM.9 findings that require physical hardware MFA for root

**Security Benefits**:
- Enables both FSBP and CIS v3.0.0 standards simultaneously for comprehensive coverage
- Evaluates environment against ~250 combined controls
- Provides a real-time posture score and per-control pass/fail in the Security Hub dashboard

### Inspector v2 (FSBP Inspector)

**Implementation Stack**: `SecurityRegionalStack`

**AWS Service**: Amazon Inspector v2

**Control Tower note**: Skipped when `--context control_tower_managed=true`.

**Configuration**: A custom resource calls `inspector2:Enable` for `EC2`, `ECR`, and `LAMBDA` resource types. Inspector v2 findings are routed to SNS via an EventBridge rule (`msb-inspector-findings-{region}`).

### Macie (FSBP Macie)

**Implementation Stack**: `SecurityRegionalStack`

**AWS Service**: Amazon Macie

**Control Tower note**: Skipped when `--context control_tower_managed=true`.

**Configuration**: `macie.CfnSession` with `FIFTEEN_MINUTES` publishing frequency. Macie findings are routed to SNS via an EventBridge rule (`msb-macie-findings-{region}`).

---

## Incident Response Controls

### SNS Notifications

**Implementation Stack**: `LoggingStack` (global region), `NotificationsRegionalStack` (additional regions)

**AWS Service**: Amazon SNS, AWS KMS

Every deployed region gets an SNS topic (`msb-notifications-{region}`) encrypted with a regional KMS key. The operator email address receives an email subscription on each topic. Delivery status logging (SNS.2) is enabled on all topics via the CfnTopic escape hatch (see the SNS Delivery Status Logging section above).

### GuardDuty Findings Alerts

**Implementation Stack**: `SecurityRegionalStack`

**AWS Service**: Amazon EventBridge, Amazon SNS

EventBridge rules route `aws.inspector2 / Inspector2 Finding` and `aws.macie2 / Macie Finding` events to the regional SNS topic. These rules are kept even when `control_tower_managed=true` so that findings generated by the CT-managed services continue to be forwarded.

### Remediation Lambda Error Alarms

**Implementation Stack**: `NetworkSecurityStack`, `S3SecurityStack`, `IAMStack`

**AWS Service**: Amazon CloudWatch Alarms, Amazon SNS

Three CloudWatch alarms monitor the remediation Lambda functions for errors. Each alarm is configured with `threshold=1`, `evaluation_periods=1`, a 5-minute period, and routes its alarm action to the regional SNS topic.

| Alarm name | Lambda | Stack |
|---|---|---|
| `msb-default-sg-remediation-errors-{region}` | `msb-secure-default-sg` | `NetworkSecurityStack` |
| `msb-s3-public-access-checker-errors-{region}` | `msb-s3-public-access-checker` | `S3SecurityStack` |
| `msb-iam-policy-checker-errors-{region}` | `msb-iam-policy-checker` | `IAMStack` |

These alarms ensure that silent Lambda failures are surfaced immediately rather than leaving the environment unmonitored.
