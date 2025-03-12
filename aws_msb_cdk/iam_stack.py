from aws_cdk import (
    Stack,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_events as events,
    aws_events_targets as targets,
    Duration,
    CfnResource
)
from constructs import Construct

class IAMStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, notifications_topic=None, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Store the notifications topic
        self.notifications_topic = notifications_topic

        # Create IAM password policy (CIS 1.8-1.11)
        self.create_password_policy()
        
    def create_password_policy(self):
        """Create IAM password policy that meets CIS benchmarks"""
        # CIS 1.8 - Ensure IAM password policy requires minimum length of 14 or greater
        # CIS 1.9 - Ensure IAM password policy prevents password reuse
        # CIS 1.10 - Ensure IAM password policy expires passwords within 90 days or less
        # CIS 1.11 - Ensure IAM password policy requires at least one uppercase letter
        # CIS 1.12 - Ensure IAM password policy requires at least one lowercase letter
        # CIS 1.13 - Ensure IAM password policy requires at least one symbol
        # CIS 1.14 - Ensure IAM password policy requires at least one number
        
        # Using CfnResource since CfnAccountPasswordPolicy is not available
        CfnResource(self, "PasswordPolicy",
            type="AWS::IAM::AccountPasswordPolicy",
            properties={
                "MinimumPasswordLength": 14,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
                "RequireSymbols": True,
                "RequireNumbers": True,
                "MaxPasswordAge": 90,
                "PasswordReusePrevention": 24,
                "HardExpiry": False,
                "AllowUsersToChangePassword": True
            }
        )