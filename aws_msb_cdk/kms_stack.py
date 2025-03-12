from aws_cdk import (
    Stack,
    RemovalPolicy,
    aws_kms as kms,
    aws_sns as sns,
    aws_iam as iam,
    custom_resources as cr,
)
from constructs import Construct

class KMSStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, notifications_topic=None, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Store the notifications topic
        self.notifications_topic = notifications_topic

        # Create a master key for general encryption
        self.master_key = kms.Key(self, "MasterKey",
            alias="msb/master-key",
            description="MSB Master Key for general encryption",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN
        )

        # Create a key for CloudTrail
        self.cloudtrail_key = kms.Key(self, "CloudTrailKey",
            alias="msb/cloudtrail-key",
            description="MSB Key for CloudTrail encryption",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN
        )

        # Create a key for S3
        self.s3_key = kms.Key(self, "S3Key",
            alias="msb/s3-key",
            description="MSB Key for S3 encryption",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN
        )

        # Create a key for RDS
        self.rds_key = kms.Key(self, "RDSKey",
            alias="msb/rds-key",
            description="MSB Key for RDS encryption",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN
        )

        # Create a key for EBS
        self.ebs_key = kms.Key(self, "EBSKey",
            alias="msb/ebs-key",
            description="MSB Key for EBS encryption",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN
        )

        # Enable EBS encryption by default (CIS 2.2.1)
        self.enable_ebs_encryption_by_default()

    def enable_ebs_encryption_by_default(self):
        """Enable EBS encryption by default for the account"""
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

        # Add a description to the custom resource
        cr.AwsCustomResource(self, "EnableEBSEncryptionDescription",
            on_create=cr.AwsSdkCall(
                service="EC2",
                action="modifyEbsDefaultKmsKeyId",
                parameters={
                    "KmsKeyId": self.ebs_key.key_arn
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
                    resources=[self.ebs_key.key_arn]
                )
            ])
        )