from aws_cdk import (
    Stack,
    aws_guardduty as guardduty,
    aws_securityhub as securityhub,
    aws_iam as iam,
    CfnResource,
    aws_s3 as s3,
    Duration,
    RemovalPolicy
)
from constructs import Construct

class SecurityRegionalStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, notifications_topic, notification_email=None, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # IAM Access Analyzer using CfnResource since CfnAccessAnalyzer is not available
        access_analyzer = CfnResource(self, "IAMAccessAnalyzer",
            type="AWS::AccessAnalyzer::Analyzer",
            properties={
                "AnalyzerName": f"msb-accessanalyzer-{self.region}",
                "Type": "ACCOUNT"
            }
        )

        # Create S3 bucket for GuardDuty findings export (optional)
        findings_bucket = s3.Bucket(self, "GuardDutyFindingsBucket",
            bucket_name=f"msb-guardduty-findings-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            versioned=True,
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="FindingsRetention",
                    enabled=True,
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INTELLIGENT_TIERING,
                            transition_after=Duration.days(30)
                        )
                    ],
                    expiration=Duration.days(365)
                )
            ]
        )

        # GuardDuty Detector with enhanced configuration
        # Using CfnDetector properties that are available in the current CDK version
        detector = guardduty.CfnDetector(self, "GuardDutyDetector",
            enable=True,
            finding_publishing_frequency="FIFTEEN_MINUTES",
            data_sources={
                "s3Logs": {
                    "enable": True
                }
            }
        )

        # Security Hub
        security_hub = securityhub.CfnHub(self, "SecurityHub")
        
        # Export resources for other stacks
        self.access_analyzer = access_analyzer
        self.detector = detector
        self.security_hub = security_hub
        self.findings_bucket = findings_bucket