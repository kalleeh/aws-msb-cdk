from aws_cdk import (
    Stack,
    aws_guardduty as guardduty,
    aws_securityhub as securityhub,
    aws_iam as iam,
    CfnResource
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

        # GuardDuty Detector
        detector = guardduty.CfnDetector(self, "GuardDutyDetector",
            enable=True
        )

        # Security Hub
        security_hub = securityhub.CfnHub(self, "SecurityHub")
        
        # Export resources for other stacks
        self.access_analyzer = access_analyzer
        self.detector = detector
        self.security_hub = security_hub