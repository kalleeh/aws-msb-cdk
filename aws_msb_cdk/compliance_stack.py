from aws_cdk import (
    Stack,
    aws_config as config,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_events as events,
    aws_events_targets as targets,
    aws_sns as sns,
    CustomResource,
    Duration,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cloudwatch_actions,
)
from constructs import Construct

class ComplianceStack(Stack):
    """
    Stack that implements compliance controls:
    - AWS Config Rules for compliance monitoring
    - CIS Benchmark enablement in Security Hub
    - Compliance reporting
    - PCI DSS, HIPAA, and CIS compliance controls
    """
    
    def __init__(self, scope: Construct, construct_id: str, notifications_topic, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create AWS Config Rules using L2 constructs
        self._create_config_rules()
        
        # Enable CIS Benchmark in Security Hub
        self._enable_cis_benchmark()
        
        # Create CloudWatch dashboard for compliance monitoring
        dashboard = cloudwatch.Dashboard(self, "ComplianceDashboard",
            dashboard_name="MSB-Compliance-Dashboard"
        )
        
        # Add compliance metrics to dashboard
        dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Config Rules Compliance",
                left=[
                    cloudwatch.Metric(
                        namespace="AWS/Config",
                        metric_name="ComplianceByConfigRule",
                        dimensions_map={
                            "ComplianceType": "COMPLIANT"
                        },
                        statistic="Average"
                    ),
                    cloudwatch.Metric(
                        namespace="AWS/Config",
                        metric_name="ComplianceByConfigRule",
                        dimensions_map={
                            "ComplianceType": "NON_COMPLIANT"
                        },
                        statistic="Average"
                    )
                ]
            )
        )
    
    def _enable_cis_benchmark(self):
        """Enable CIS Benchmark in Security Hub"""
        # Lambda function to enable CIS Benchmark
        enable_cis_function = lambda_.Function(self, "EnableCISBenchmark",
            runtime=lambda_.Runtime.PYTHON_3_9,
            handler="index.handler",
            code=lambda_.Code.from_inline("""
import boto3
import cfnresponse
import time

def handler(event, context):
    if event['RequestType'] == 'Delete':
        cfnresponse.send(event, context, cfnresponse.SUCCESS, {})
        return

    try:
        # Enable CIS AWS Foundations Benchmark
        securityhub = boto3.client('securityhub')
        
        # Wait for Security Hub to be available
        time.sleep(10)
        
        # Enable CIS AWS Foundations Benchmark v1.2.0
        securityhub.batch_enable_standards(
            StandardsSubscriptionRequests=[
                {
                    'StandardsArn': f'arn:aws:securityhub:{context.invoked_function_arn.split(":")[3]}::standards/cis-aws-foundations-benchmark/v/1.2.0'
                }
            ]
        )
        
        cfnresponse.send(event, context, cfnresponse.SUCCESS, {})
    except Exception as e:
        print(e)
        cfnresponse.send(event, context, cfnresponse.FAILED, {})
"""),
            timeout=Duration.seconds(30)
        )

        # Add permissions to enable standards
        enable_cis_function.add_to_role_policy(iam.PolicyStatement(
            actions=["securityhub:BatchEnableStandards"],
            resources=["*"]
        ))

        # Custom resource to enable CIS Benchmark
        CustomResource(self, "CISBenchmarkEnabler",
            service_token=enable_cis_function.function_arn
        )
    
    def _create_config_rules(self):
        """Create AWS Config Rules for compliance monitoring"""
        
        # Encrypted Volumes Rule
        config.ManagedRule(self, "EncryptedVolumesRule",
            identifier="ENCRYPTED_VOLUMES",
            description="Checks if EBS volumes are encrypted"
        )
        
        # Root Account MFA Rule
        config.ManagedRule(self, "RootAccountMFARule",
            identifier="ROOT_ACCOUNT_MFA_ENABLED",
            description="Checks if the root user has MFA enabled"
        )
        
        # IAM Password Policy Rule
        config.ManagedRule(self, "IAMPasswordPolicyRule",
            identifier="IAM_PASSWORD_POLICY",
            description="Checks if the IAM password policy meets requirements"
        )
        
        # S3 Bucket Public Access Rule
        config.ManagedRule(self, "S3BucketPublicReadRule",
            identifier="S3_BUCKET_PUBLIC_READ_PROHIBITED",
            description="Checks if S3 buckets allow public read access"
        )
        
        # S3 Bucket Public Write Rule
        config.ManagedRule(self, "S3BucketPublicWriteRule",
            identifier="S3_BUCKET_PUBLIC_WRITE_PROHIBITED",
            description="Checks if S3 buckets allow public write access"
        )
        
        # S3 Bucket SSL Rule
        config.ManagedRule(self, "S3BucketSSLRule",
            identifier="S3_BUCKET_SSL_REQUESTS_ONLY",
            description="Checks if S3 buckets have policies requiring SSL"
        )
        
        # RDS Storage Encrypted Rule
        config.ManagedRule(self, "RDSStorageEncryptedRule",
            identifier="RDS_STORAGE_ENCRYPTED",
            description="Checks if RDS database instances are encrypted"
        )
        
        # RDS Multi-AZ Rule
        config.ManagedRule(self, "RDSMultiAZRule",
            identifier="RDS_MULTI_AZ_SUPPORT",
            description="Checks if RDS database instances have Multi-AZ enabled"
        )
        
        # CloudTrail Enabled Rule
        config.ManagedRule(self, "CloudTrailEnabledRule",
            identifier="CLOUD_TRAIL_ENABLED",
            description="Checks if CloudTrail is enabled"
        )
        
        # CloudTrail Encryption Rule
        config.ManagedRule(self, "CloudTrailEncryptionRule",
            identifier="CLOUD_TRAIL_ENCRYPTION_ENABLED",
            description="Checks if CloudTrail logs are encrypted"
        )
        
        # CloudTrail Log File Validation Rule
        config.ManagedRule(self, "CloudTrailLogFileValidationRule",
            identifier="CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED",
            description="Checks if CloudTrail log file validation is enabled"
        )
        
        # VPC Flow Logs Enabled Rule
        config.ManagedRule(self, "VPCFlowLogsEnabledRule",
            identifier="VPC_FLOW_LOGS_ENABLED",
            description="Checks if VPC Flow Logs are enabled for VPCs"
        )
        
        # Restricted SSH Rule
        config.ManagedRule(self, "RestrictedSSHRule",
            identifier="INCOMING_SSH_DISABLED",
            description="Checks if security groups allow unrestricted SSH access"
        )
        
        # Restricted RDP Rule
        config.ManagedRule(self, "RestrictedRDPRule",
            identifier="RESTRICTED_INCOMING_TRAFFIC",
            description="Checks if security groups allow unrestricted RDP access",
            input_parameters={
                "blockedPort1": "3389"
            }
        )
        
        # Access Keys Rotated Rule
        config.ManagedRule(self, "AccessKeysRotatedRule",
            identifier="ACCESS_KEYS_ROTATED",
            description="Checks if IAM access keys are rotated within 90 days",
            input_parameters={
                "maxAccessKeyAge": "90"
            }
        )
        
        # MFA Enabled for IAM Console Access
        config.ManagedRule(self, "MFAEnabledForConsoleAccessRule",
            identifier="MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS",
            description="Checks if MFA is enabled for all IAM users with console access"
        )