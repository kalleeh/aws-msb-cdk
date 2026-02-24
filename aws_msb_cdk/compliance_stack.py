from aws_cdk import (
    Stack,
    aws_config as config,
    aws_iam as iam,
    aws_cloudwatch as cloudwatch,
)
from constructs import Construct

class ComplianceStack(Stack):
    """
    Stack that implements compliance controls via AWS Config Rules.
    Security Hub standards (FSBP + CIS v3.0.0) are enabled in SecurityRegionalStack.
    """

    def __init__(self, scope: Construct, construct_id: str, notifications_topic, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create AWS Config Rules using L2 constructs
        self._create_config_rules()

        # CloudWatch dashboard for compliance monitoring
        dashboard = cloudwatch.Dashboard(self, "ComplianceDashboard",
            dashboard_name="MSB-Compliance-Dashboard"
        )

        dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Config Rules Compliance",
                left=[
                    cloudwatch.Metric(
                        namespace="AWS/Config",
                        metric_name="ComplianceByConfigRule",
                        dimensions_map={"ComplianceType": "COMPLIANT"},
                        statistic="Average"
                    ),
                    cloudwatch.Metric(
                        namespace="AWS/Config",
                        metric_name="ComplianceByConfigRule",
                        dimensions_map={"ComplianceType": "NON_COMPLIANT"},
                        statistic="Average"
                    )
                ]
            )
        )

    def _create_config_rules(self):
        """Create AWS Config Rules mapping to FSBP and CIS v3.0.0 controls"""

        # --- Encryption ---

        # FSBP EC2.3 / CIS 2.2.1 - EBS volumes encrypted
        config.ManagedRule(self, "EncryptedVolumesRule",
            identifier="ENCRYPTED_VOLUMES",
            description="Checks if EBS volumes are encrypted"
        )

        # FSBP EC2.8 - IMDSv2 required on EC2 instances
        config.ManagedRule(self, "EC2IMDSv2Rule",
            identifier="EC2_IMDSV2_CHECK",
            description="Checks if EC2 instances use IMDSv2 (FSBP EC2.8)"
        )

        # FSBP KMS.4 - KMS key rotation enabled (covered by kms_stack, Config checks it)
        config.ManagedRule(self, "KMSKeyRotationRule",
            identifier="CMK_BACKING_KEY_ROTATION_ENABLED",
            description="Checks if KMS CMK rotation is enabled (FSBP KMS.4)"
        )

        # FSBP RDS.3 - RDS deletion protection
        config.ManagedRule(self, "RDSDeletionProtectionRule",
            identifier="RDS_INSTANCE_DELETION_PROTECTION_ENABLED",
            description="Checks if RDS instances have deletion protection (FSBP RDS.3)"
        )

        # FSBP RDS.2 - RDS storage encrypted
        config.ManagedRule(self, "RDSStorageEncryptedRule",
            identifier="RDS_STORAGE_ENCRYPTED",
            description="Checks if RDS database instances are encrypted"
        )

        # FSBP SNS.1 - SNS topics encrypted with KMS
        config.ManagedRule(self, "SNSEncryptedRule",
            identifier="SNS_ENCRYPTED_KMS",
            description="Checks if SNS topics are encrypted with KMS (FSBP SNS.1)"
        )

        # --- IAM ---

        # FSBP IAM.3 / CIS 1.14 - Access keys rotated within 90 days
        config.ManagedRule(self, "AccessKeysRotatedRule",
            identifier="ACCESS_KEYS_ROTATED",
            description="Checks if IAM access keys are rotated within 90 days",
            input_parameters={"maxAccessKeyAge": "90"}
        )

        # FSBP IAM.5 / CIS 1.10 - MFA enabled for console access
        config.ManagedRule(self, "MFAEnabledForConsoleAccessRule",
            identifier="MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS",
            description="Checks if MFA is enabled for all IAM users with console access"
        )

        # CIS 1.5 - Root account MFA enabled
        config.ManagedRule(self, "RootAccountMFARule",
            identifier="ROOT_ACCOUNT_MFA_ENABLED",
            description="Checks if the root user has MFA enabled"
        )

        # CIS 1.7 - IAM password policy
        config.ManagedRule(self, "IAMPasswordPolicyRule",
            identifier="IAM_PASSWORD_POLICY",
            description="Checks if the IAM password policy meets requirements"
        )

        # --- S3 ---

        # FSBP S3.1 - S3 public read prohibited
        config.ManagedRule(self, "S3BucketPublicReadRule",
            identifier="S3_BUCKET_PUBLIC_READ_PROHIBITED",
            description="Checks if S3 buckets allow public read access"
        )

        # FSBP S3.2 - S3 public write prohibited
        config.ManagedRule(self, "S3BucketPublicWriteRule",
            identifier="S3_BUCKET_PUBLIC_WRITE_PROHIBITED",
            description="Checks if S3 buckets allow public write access"
        )

        # FSBP S3.5 - S3 SSL requests only
        config.ManagedRule(self, "S3BucketSSLRule",
            identifier="S3_BUCKET_SSL_REQUESTS_ONLY",
            description="Checks if S3 buckets have policies requiring SSL"
        )

        # FSBP S3.11 - S3 Object Lock enabled (for audit/compliance buckets)
        config.ManagedRule(self, "S3ObjectLockRule",
            identifier="S3_BUCKET_OBJECT_LOCK_ENABLED",
            description="Checks if S3 buckets have Object Lock enabled (FSBP S3.11)"
        )

        # --- CloudTrail ---

        # FSBP CloudTrail.1 - CloudTrail enabled
        config.ManagedRule(self, "CloudTrailEnabledRule",
            identifier="CLOUD_TRAIL_ENABLED",
            description="Checks if CloudTrail is enabled"
        )

        # FSBP CloudTrail.2 - CloudTrail encryption
        config.ManagedRule(self, "CloudTrailEncryptionRule",
            identifier="CLOUD_TRAIL_ENCRYPTION_ENABLED",
            description="Checks if CloudTrail logs are encrypted"
        )

        # FSBP CloudTrail.4 - CloudTrail log file validation
        config.ManagedRule(self, "CloudTrailLogFileValidationRule",
            identifier="CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED",
            description="Checks if CloudTrail log file validation is enabled"
        )

        # --- Networking ---

        # FSBP EC2.6 / CIS 3.9 - VPC flow logs enabled
        config.ManagedRule(self, "VPCFlowLogsEnabledRule",
            identifier="VPC_FLOW_LOGS_ENABLED",
            description="Checks if VPC Flow Logs are enabled for VPCs"
        )

        # FSBP EC2.19 / CIS 5.1 - Unrestricted SSH
        config.ManagedRule(self, "RestrictedSSHRule",
            identifier="INCOMING_SSH_DISABLED",
            description="Checks if security groups allow unrestricted SSH access"
        )

        # FSBP EC2.20 / CIS 5.2 - Unrestricted RDP
        config.ManagedRule(self, "RestrictedRDPRule",
            identifier="RESTRICTED_INCOMING_TRAFFIC",
            description="Checks if security groups allow unrestricted RDP access",
            input_parameters={"blockedPort1": "3389"}
        )

        # FSBP EC2.15 - Subnets should not auto-assign public IPs
        config.ManagedRule(self, "SubnetAutoAssignPublicIPRule",
            identifier="SUBNET_AUTO_ASSIGN_PUBLIC_IP_DISABLED",
            description="Checks if subnets are configured to auto-assign public IPs (FSBP EC2.15)"
        )

        # --- Lambda ---

        # FSBP Lambda.1 - Lambda functions not publicly accessible
        config.ManagedRule(self, "LambdaPublicAccessRule",
            identifier="LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED",
            description="Checks if Lambda functions allow public access (FSBP Lambda.1)"
        )

        # FSBP Lambda.2 - Lambda using supported runtimes
        config.ManagedRule(self, "LambdaRuntimeRule",
            identifier="LAMBDA_FUNCTION_SETTINGS_CHECK",
            description="Checks if Lambda functions use supported runtimes (FSBP Lambda.2)",
            input_parameters={
                "runtime": "python3.11,python3.12,python3.13,nodejs20.x,nodejs22.x,java21,java17,dotnet8"
            }
        )

        # --- Systems Manager ---

        # FSBP SSM.1 - EC2 instances managed by SSM
        config.ManagedRule(self, "EC2ManagedBySSMRule",
            identifier="EC2_INSTANCE_MANAGED_BY_SSM",
            description="Checks if EC2 instances are managed by SSM (FSBP SSM.1)"
        )
