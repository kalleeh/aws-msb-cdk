from aws_cdk import (
    Stack,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_events as events,
    aws_events_targets as targets,
    aws_accessanalyzer as accessanalyzer,
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
        
        # Create IAM policy checker for IAM.16 compliance
        self.create_iam_policy_checker()
        
        # Create IAM Access Analyzer (CIS 1.20)
        self.create_access_analyzer()
        
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
        
    def create_iam_policy_checker(self):
        """
        Create IAM policy checker Lambda function to monitor and report on IAM policies 
        attached directly to users (FSBP IAM.16)
        """
        # Skip if no notifications topic is provided
        if not self.notifications_topic:
            return
            
        # Create Lambda function to check for IAM policies attached directly to users
        iam_policy_checker = lambda_.Function(self, "IAMPolicyChecker",
            runtime=lambda_.Runtime.PYTHON_3_9,
            handler="index.handler",
            code=lambda_.Code.from_asset("lambda/iam_policy_checker"),
            timeout=Duration.seconds(60),
            environment={
                "NOTIFICATION_TOPIC_ARN": self.notifications_topic.topic_arn
            }
        )

        # Add permissions to check IAM policies
        iam_policy_checker.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "iam:ListUsers",
                    "iam:ListUserPolicies",
                    "iam:ListAttachedUserPolicies"
                ],
                resources=["*"]
            )
        )

        # Add permission to publish to SNS topic
        iam_policy_checker.add_to_role_policy(
            iam.PolicyStatement(
                actions=["sns:Publish"],
                resources=[self.notifications_topic.topic_arn]
            )
        )

        # Schedule the Lambda to run daily
        events.Rule(self, "IAMPolicyCheckerSchedule",
            schedule=events.Schedule.rate(Duration.days(1)),
            targets=[targets.LambdaFunction(iam_policy_checker)]
        )

        # Also trigger on policy attachment events
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
        
    def create_access_analyzer(self):
        """Create IAM Access Analyzer for external access analysis (CIS 1.20)"""
        
        # Create IAM Access Analyzer
        accessanalyzer.CfnAnalyzer(self, "IAMAccessAnalyzer",
            analyzer_name=f"msb-access-analyzer-{self.account}-{self.region}",
            type="ACCOUNT"
        )