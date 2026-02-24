# AWS MSB Control Implementation Details

This document provides detailed information about how each security control is implemented in the AWS MSB CDK project, including the specific AWS services used, configuration details, and the security benefits provided.

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

### IAM Access Key Rotation Monitoring

**Implementation Stack**: `IAMStack`

**AWS Service**: AWS Lambda, Amazon EventBridge

**Configuration**:
```python
access_key_checker = lambda_.Function(self, "AccessKeyChecker",
    runtime=lambda_.Runtime.PYTHON_3_9,
    handler="index.handler",
    code=lambda_.Code.from_inline("..."),
    timeout=Duration.seconds(60),
    environment={
        "MAX_KEY_AGE_DAYS": "90",
        "NOTIFICATION_TOPIC_ARN": notifications_topic.topic_arn if notifications_topic else ""
    }
)

events.Rule(self, "AccessKeyCheckerSchedule",
    schedule=events.Schedule.rate(Duration.days(1)),
    targets=[targets.LambdaFunction(access_key_checker)]
)
```

**Security Benefits**:
- Monitors IAM access keys for rotation compliance
- Sends notifications for keys that need rotation
- Addresses CIS AWS Foundations Benchmark v3.0.0 control 1.14
- No manual monitoring required

### IAM Policy Governance Monitoring

**Implementation Stack**: `IAMStack`

**AWS Service**: AWS Lambda, Amazon EventBridge

**Configuration**:
```python
iam_policy_checker = lambda_.Function(self, "IAMPolicyChecker",
    runtime=lambda_.Runtime.PYTHON_3_9,
    handler="index.handler",
    code=lambda_.Code.from_inline("..."),
    timeout=Duration.seconds(60),
    environment={
        "NOTIFICATION_TOPIC_ARN": notifications_topic.topic_arn if notifications_topic else ""
    }
)

events.Rule(self, "IAMPolicyCheckerSchedule",
    schedule=events.Schedule.rate(Duration.days(1)),
    targets=[targets.LambdaFunction(iam_policy_checker)]
)

policy_attachment_rule = events.Rule(self, "IAMPolicyAttachmentRule",
    event_pattern=events.EventPattern(
        source=["aws.iam"],
        detail_type=["AWS API Call via CloudTrail"],
        detail={
            "eventSource": ["iam.amazonaws.com"],
            "eventName": [
                "AttachUserPolicy",
                "PutUserPolicy"
            ]
        }
    ),
    targets=[targets.LambdaFunction(iam_policy_checker)]
)
```

**Security Benefits**:
- Identifies IAM users with directly attached policies
- Provides recommendations for better IAM governance
- Addresses FSBP IAM.16
- No operational overhead once implemented

### IAM Access Analyzer

**Implementation Stack**: `SecurityRegionalStack`

**AWS Service**: AWS IAM Access Analyzer

**Configuration**:
```python
access_analyzer = iam.CfnAccessAnalyzer(self, "IAMAccessAnalyzer",
    analyzer_name=f"msb-accessanalyzer-{self.region}",
    type="ACCOUNT"
)
```

**Security Benefits**:
- Identifies resources (S3 buckets, IAM roles, KMS keys, etc.) that are shared with external entities
- Helps prevent unintended access to your resources
- Supports the principle of least privilege
- Aligns with CIS AWS Foundations Benchmark v3.0.0 recommendation 1.20

## Logging and Monitoring Controls

### CloudTrail

**Implementation Stack**: `LoggingStack`

**AWS Service**: AWS CloudTrail

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
    trail_name="msb-cloudtrail"
)
```

**Security Benefits**:
- Records API calls for auditing, compliance, and security analysis
- Enables investigation of security incidents
- Provides accountability for actions taken in your AWS account
- Aligns with CIS AWS Foundations Benchmark v3.0.0 recommendations 3.1-3.7

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

**Security Benefits**:
- Captures network traffic metadata for security analysis
- Enables detection of unusual traffic patterns
- Supports network forensics and troubleshooting
- Aligns with CIS AWS Foundations Benchmark v3.0.0 recommendation 3.9

### GuardDuty

**Implementation Stack**: `SecurityRegionalStack`

**AWS Service**: Amazon GuardDuty

**Configuration**:
```python
detector = guardduty.CfnDetector(self, "GuardDutyDetector",
    enable=True
)
```

**Security Benefits**:
- Provides intelligent threat detection
- Continuously monitors for malicious activity and unauthorized behavior
- Analyzes events across multiple AWS data sources
- Aligns with CIS AWS Foundations Benchmark v3.0.0 recommendation 3.8

### Root Account Activity Monitoring

**Implementation Stack**: `SecurityMonitoringStack`

**AWS Service**: Amazon EventBridge, Amazon SNS

**Configuration**:
```python
root_activity_rule = events.Rule(self, "RootActivityMonitoringRule",
    rule_name=f"msb-root-activity-monitoring-{self.region}",
    description="Monitors and alerts on root account activity",
    event_pattern=events.EventPattern(
        source=["aws.signin"],
        detail_type=["AWS Console Sign In via CloudTrail"],
        detail={
            "userIdentity": {
                "type": ["Root"]
            }
        }
    )
)

root_activity_rule.add_target(targets.SnsTopic(
    notifications_topic,
    message=events.RuleTargetInput.from_text(
        "ALERT: AWS Root account was used to sign in to the console. " +
        "Root account usage should be minimized. " +
        "Event details: " +
        events.RuleTargetInput.from_event("$.detail").to_string()
    )
))
```

**Security Benefits**:
- Provides real-time monitoring of root account usage
- Sends immediate alerts when root account is used
- Addresses CIS AWS Foundations Benchmark v3.0.0 control 1.7 and FSBP IAM.7
- No operational overhead once implemented

## Data Protection Controls

### S3 Block Public Access (Account)

**Implementation Stack**: `S3SecurityStack`

**AWS Service**: Amazon S3

**Configuration**:
```python
# Custom resource to block public access at account level
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
- Prevents public access to S3 buckets at the account level
- Provides a defense-in-depth approach to S3 security
- Reduces the risk of data exposure
- Aligns with CIS AWS Foundations Benchmark v3.0.0 recommendation 2.1.2

### S3 Bucket-Level Public Access Blocks

**Implementation Stack**: `S3SecurityStack`

**AWS Service**: AWS Lambda, Amazon EventBridge

**Configuration**:
```python
s3_bucket_public_access_checker = lambda_.Function(self, "S3BucketPublicAccessChecker",
    runtime=lambda_.Runtime.PYTHON_3_9,
    handler="index.handler",
    code=lambda_.Code.from_inline("..."),
    timeout=Duration.seconds(300),
    environment={
        "NOTIFICATION_TOPIC_ARN": notifications_topic.topic_arn if notifications_topic else ""
    }
)

events.Rule(self, "S3PublicAccessCheckerSchedule",
    schedule=events.Schedule.rate(Duration.days(1)),
    targets=[targets.LambdaFunction(s3_bucket_public_access_checker)]
)

bucket_creation_rule = events.Rule(self, "S3BucketCreationRule",
    event_pattern=events.EventPattern(
        source=["aws.s3"],
        detail_type=["AWS API Call via CloudTrail"],
        detail={
            "eventSource": ["s3.amazonaws.com"],
            "eventName": ["CreateBucket"]
        }
    ),
    targets=[targets.LambdaFunction(s3_bucket_public_access_checker)]
)
```

**Security Benefits**:
- Ensures all S3 buckets have public access blocks enabled
- Automatically remediates non-compliant buckets
- Addresses CIS AWS Foundations Benchmark v3.0.0 control 2.1.5
- Provides notifications on enforcement actions

### S3 Default Encryption

**Implementation Stack**: `S3SecurityStack`

**AWS Service**: Amazon S3

**Configuration**:
```python
default_encryption = cr.AwsCustomResource(self, "S3DefaultEncryption",
    on_create=cr.AwsSdkCall(
        service="S3Control",
        action="putBucketEncryption",
        parameters={
            "AccountId": self.account,
            "BucketEncryption": {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256"
                            },
                            "BucketKeyEnabled": True
                        }
                    ]
                }
            }
        },
        physical_resource_id=cr.PhysicalResourceId.of("s3-default-encryption")
    ),
    policy=cr.AwsCustomResourcePolicy.from_statements([
        iam.PolicyStatement(
            actions=["s3:PutEncryptionConfiguration"],
            resources=["*"]
        )
    ])
)
```

**Security Benefits**:
- Ensures all new S3 buckets have encryption enabled by default
- Addresses CIS AWS Foundations Benchmark v3.0.0 control 2.1.1
- No operational overhead once implemented

### KMS Key Rotation

**Implementation Stack**: `KMSStack`

**AWS Service**: AWS KMS

**Configuration**:
```python
key = kms.Key(self, "MasterKey",
    alias="msb/master-key",
    description="MSB Master Key for general encryption",
    enable_key_rotation=True,
    removal_policy=RemovalPolicy.RETAIN
)
```

**Security Benefits**:
- Automatically rotates encryption keys to limit the impact of key compromise
- Maintains backward compatibility for encrypted data
- Follows cryptographic best practices
- Aligns with CIS AWS Foundations Benchmark v3.0.0 recommendation 3.7

### EBS Volume Encryption by Default

**Implementation Stack**: `KMSStack`

**AWS Service**: Amazon EC2, AWS KMS

**Configuration**:
```python
enable_ebs_encryption = cr.AwsCustomResource(self, "EnableEBSEncryptionByDefault",
    on_create=cr.AwsSdkCall(
        service="EC2",
        action="enableEbsEncryptionByDefault",
        parameters={},
        physical_resource_id=cr.PhysicalResourceId.of("enable-ebs-encryption-by-default")
    ),
    policy=cr.AwsCustomResourcePolicy.from_statements([
        iam.PolicyStatement(
            actions=["ec2:EnableEbsEncryptionByDefault"],
            resources=["*"]
        )
    ])
)

cr.AwsCustomResource(self, "EnableEBSEncryptionDescription",
    on_create=cr.AwsSdkCall(
        service="EC2",
        action="modifyEbsDefaultKmsKeyId",
        parameters={
            "KmsKeyId": ebs_key.key_arn
        },
        physical_resource_id=cr.PhysicalResourceId.of("ebs-default-kms-key")
    ),
    policy=cr.AwsCustomResourcePolicy.from_statements([
        iam.PolicyStatement(
            actions=["ec2:ModifyEbsDefaultKmsKeyId"],
            resources=["*"]
        ),
        iam.PolicyStatement(
            actions=["kms:DescribeKey"],
            resources=[ebs_key.key_arn]
        )
    ])
)
```

**Security Benefits**:
- Ensures all new EBS volumes are encrypted by default
- Uses a dedicated KMS key for EBS encryption
- Addresses CIS AWS Foundations Benchmark v3.0.0 control 2.2.1
- No operational overhead once implemented

## Network Security Controls

### Default Security Group Rules

**Implementation Stack**: `NetworkSecurityStack`

**AWS Service**: Amazon EC2, AWS Lambda, Amazon EventBridge

**Configuration**:
```python
secure_default_sg_function = lambda_.Function(self, "SecureDefaultSGFunction",
    runtime=lambda_.Runtime.PYTHON_3_9,
    handler="index.handler",
    code=lambda_.Code.from_inline("..."),
    timeout=Duration.seconds(60),
    environment={
        "NOTIFICATION_TOPIC_ARN": notifications_topic.topic_arn if notifications_topic else ""
    }
)

events.Rule(self, "SecureDefaultSGSchedule",
    schedule=events.Schedule.rate(Duration.days(1)),
    targets=[targets.LambdaFunction(secure_default_sg_function)]
)

sg_changes_rule = events.Rule(self, "SGChangesRule",
    event_pattern=events.EventPattern(
        source=["aws.ec2"],
        detail_type=["AWS API Call via CloudTrail"],
        detail={
            "eventSource": ["ec2.amazonaws.com"],
            "eventName": [
                "AuthorizeSecurityGroupIngress",
                "AuthorizeSecurityGroupEgress",
                "CreateSecurityGroup"
            ]
        }
    ),
    targets=[targets.LambdaFunction(secure_default_sg_function)]
)
```

**Security Benefits**:
- Restricts all inbound and outbound traffic in default security groups
- Prevents accidental use of default security groups with permissive rules
- Follows the principle of least privilege
- Aligns with CIS AWS Foundations Benchmark v3.0.0 recommendation 5.4
- Continuously monitors and automatically remediates non-compliant security groups

### Security Group Monitoring

**Implementation Stack**: `SecurityMonitoringStack`

**AWS Service**: Amazon EventBridge, Amazon SNS

**Configuration**:
```python
sg_changes_rule = events.Rule(self, "SecurityGroupChangesRule",
    rule_name=f"msb-security-group-changes-{self.region}",
    description="Detects changes to security groups",
    event_pattern=events.EventPattern(
        source=["aws.ec2"],
        detail_type=["AWS API Call via CloudTrail"],
        detail={
            "eventSource": ["ec2.amazonaws.com"],
            "eventName": [
                "AuthorizeSecurityGroupIngress",
                "AuthorizeSecurityGroupEgress",
                "RevokeSecurityGroupIngress",
                "RevokeSecurityGroupEgress",
                "CreateSecurityGroup",
                "DeleteSecurityGroup"
            ]
        }
    )
)

sg_changes_rule.add_target(targets.SnsTopic(notifications_topic))
```

**Security Benefits**:
- Monitors changes to security groups in real-time
- Enables quick response to unauthorized or suspicious changes
- Provides an audit trail of security group modifications
- Aligns with CIS AWS Foundations Benchmark v3.0.0 recommendation 5.3

## Compliance Controls

### AWS Config Rules

**Implementation Stack**: `ComplianceStack`

**AWS Service**: AWS Config

**Configuration**:
```python
# CIS Benchmark rules
cis_rules = [
    config.ManagedRule(self, "RootAccountMFAEnabled",
        identifier="ROOT_ACCOUNT_MFA_ENABLED"
    ),
    config.ManagedRule(self, "IAMUserMFAEnabled",
        identifier="IAM_USER_MFA_ENABLED"
    ),
    config.ManagedRule(self, "IAMPasswordPolicy",
        identifier="IAM_PASSWORD_POLICY"
    ),
    config.ManagedRule(self, "CloudTrailEnabled",
        identifier="CLOUD_TRAIL_ENABLED"
    ),
    config.ManagedRule(self, "CloudTrailEncryptionEnabled",
        identifier="CLOUD_TRAIL_ENCRYPTION_ENABLED"
    ),
    config.ManagedRule(self, "S3BucketPublicReadProhibited",
        identifier="S3_BUCKET_PUBLIC_READ_PROHIBITED"
    ),
    config.ManagedRule(self, "S3BucketPublicWriteProhibited",
        identifier="S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
    ),
    config.ManagedRule(self, "S3BucketServerSideEncryptionEnabled",
        identifier="S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
    ),
    config.ManagedRule(self, "RestrictedIncomingTraffic",
        identifier="RESTRICTED_INCOMING_TRAFFIC",
        input_parameters={
            "blockedPort1": "22",
            "blockedPort2": "3389"
        }
    ),
    config.ManagedRule(self, "VpcDefaultSecurityGroupClosed",
        identifier="VPC_DEFAULT_SECURITY_GROUP_CLOSED"
    )
]
```

**Security Benefits**:
- Evaluates resources against security best practices
- Provides continuous compliance monitoring
- Identifies non-compliant resources
- Aligns with CIS AWS Foundations Benchmark v3.0.0 recommendation 3.5

### CIS Benchmark in Security Hub

**Implementation Stack**: `SecurityRegionalStack`

**AWS Service**: AWS Security Hub

**Configuration**:
```python
# Enable Security Hub
security_hub = securityhub.CfnHub(self, "SecurityHub")

# Enable FSBP v1.0.0 — AWS Foundational Security Best Practices (~200 controls)
fsbp_standard = securityhub.CfnStandard(self, "FBSPStandard",
    standards_arn=f"arn:aws:securityhub:{self.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
)
fsbp_standard.node.add_dependency(security_hub)

# Enable CIS AWS Foundations Benchmark v3.0.0 (~58 controls)
cis_standard = securityhub.CfnStandard(self, "CISv3Standard",
    standards_arn=f"arn:aws:securityhub:{self.region}::standards/cis-aws-foundations-benchmark/v/3.0.0"
)
cis_standard.node.add_dependency(security_hub)
```

**Security Benefits**:
- Enables both FSBP and CIS v3.0.0 standards simultaneously for comprehensive coverage
- Evaluates environment against ~250 combined controls
- Provides a real-time posture score and per-control pass/fail in the Security Hub dashboard
- Native `CfnStandard` construct used — no custom resource or Lambda required

## Incident Response Controls

### SNS Notifications

**Implementation Stack**: `LoggingStack`

**AWS Service**: Amazon SNS

**Configuration**:
```python
notifications_topic = sns.Topic(self, "NotificationsTopic",
    topic_name=f"msb-notifications-{self.region}",
    display_name="MSB Security Notifications"
)

# Add email subscription if provided
if notification_email:
    notifications_topic.add_subscription(
        sns_subs.EmailSubscription(notification_email)
    )
```

**Security Benefits**:
- Sends alerts for security events
- Enables timely response to security incidents
- Provides a centralized notification mechanism
- Supports AWS Foundational Security Best Practices

### GuardDuty Findings Alerts

**Implementation Stack**: `SecurityMonitoringStack`

**AWS Service**: Amazon EventBridge, Amazon SNS

**Configuration**:
```python
# EventBridge rule for GuardDuty findings
guardduty_rule = events.Rule(self, "GuardDutyFindingsRule",
    rule_name="msb-guardduty-findings",
    description="Detects GuardDuty findings",
    event_pattern=events.EventPattern(
        source=["aws.guardduty"],
        detail_type=["GuardDuty Finding"]
    )
)

if notifications_topic:
    guardduty_rule.add_target(targets.SnsTopic(notifications_topic))
```

**Security Benefits**:
- Notifies about potential threats detected by GuardDuty
- Enables quick response to security threats
- Provides context for security investigations
- Aligns with CIS AWS Foundations Benchmark v3.0.0 recommendation 3.8