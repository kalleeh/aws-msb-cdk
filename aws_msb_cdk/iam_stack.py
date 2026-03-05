from aws_cdk import (
    Stack,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_events as events,
    aws_events_targets as targets,
    aws_accessanalyzer as accessanalyzer,
    custom_resources as cr,
    Duration,
    CfnResource
)
from constructs import Construct
from cdk_nag import NagSuppressions

class IAMStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, notifications_topic=None, notification_email=None, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Store the notifications topic
        self.notifications_topic = notifications_topic

        # Create IAM password policy (CIS 1.8-1.11)
        self.create_password_policy()

        # Create IAM policy checker for IAM.16 compliance
        self.create_iam_policy_checker()

        # Create IAM Access Analyzer (CIS 1.20)
        self.create_access_analyzer()

        # Set security contact (CIS 1.18)
        if notification_email:
            self.create_security_contact(notification_email)

    def create_password_policy(self):
        """Create IAM password policy aligned with NIST SP 800-63B and CIS v3.0.0"""
        # CIS 1.8 - Ensure IAM password policy requires minimum length of 14 or greater (using 16)
        # CIS 1.9 - Ensure IAM password policy prevents password reuse
        # CIS 1.11 - Ensure IAM password policy requires at least one uppercase letter
        # CIS 1.12 - Ensure IAM password policy requires at least one lowercase letter
        # CIS 1.13 - Ensure IAM password policy requires at least one symbol
        # CIS 1.14 - Ensure IAM password policy requires at least one number
        # NOTE: MaxPasswordAge intentionally omitted — NIST SP 800-63B (2017) and
        # CIS AWS v3.0.0 recommend against periodic password expiration as it increases
        # risk through predictable rotation patterns without security benefit.

        # Using CfnResource since CfnAccountPasswordPolicy is not available
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
            }
        )

        # CIS 1.17 - Ensure a support role has been created to manage incidents with AWS Support
        support_role = iam.Role(self, "AWSSupportRole",
            role_name="msb-aws-support-role",
            assumed_by=iam.AccountRootPrincipal(),
            description="Role for AWS Support access - CIS 1.17",
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AWSSupportAccess")
            ]
        )
        NagSuppressions.add_resource_suppressions(
            support_role,
            [{"id": "AwsSolutions-IAM4", "reason": "AWSSupportAccess is the required AWS managed policy for CIS 1.17 compliance — ensures a support role exists for incident management with AWS Support. No customer-managed equivalent exists for this purpose."}]
        )

    def create_iam_policy_checker(self):
        """
        Create IAM policy checker Lambda function to monitor and report on IAM policies
        attached directly to users (FSBP IAM.16)
        """
        # Skip if no notifications topic is provided
        if not self.notifications_topic:
            return

        # Custom execution role with scoped CloudWatch Logs permissions
        # (avoids AWSLambdaBasicExecutionRole managed policy — AwsSolutions-IAM4)
        function_name = "msb-iam-policy-checker"
        lambda_exec_role = iam.Role(self, "IAMPolicyCheckerRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            inline_policies={
                "CloudWatchLogs": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=[
                                "logs:CreateLogGroup",
                                "logs:CreateLogStream",
                                "logs:PutLogEvents"
                            ],
                            resources=[f"arn:aws:logs:{self.region}:{self.account}:log-group:/aws/lambda/{function_name}:*"]
                        )
                    ]
                )
            }
        )

        # Suppress IAM5 on the role: the inline policy uses a log-stream wildcard
        # (:*) which is the standard pattern for scoped CloudWatch Logs access.
        NagSuppressions.add_resource_suppressions(
            lambda_exec_role,
            [{"id": "AwsSolutions-IAM5", "reason": "Log stream wildcard (:*) is the standard ARN suffix for CloudWatch Logs — it scopes access to streams within the named log group only, not all log groups."}],
            apply_to_children=True
        )

        # Create Lambda function to check for IAM policies attached directly to users
        iam_policy_checker = lambda_.Function(self, "IAMPolicyChecker",
            function_name=function_name,
            role=lambda_exec_role,
            runtime=lambda_.Runtime.PYTHON_3_13,
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

        # Suppress IAM5: IAM list APIs are account-level and require wildcard resources.
        # Suppress L1: Lambda is already on Python 3.13 (latest); CDK Nag may lag.
        NagSuppressions.add_resource_suppressions(
            iam_policy_checker,
            [
                {"id": "AwsSolutions-IAM5", "reason": "iam:ListUsers, iam:ListUserPolicies, and iam:ListAttachedUserPolicies are account-level IAM APIs that do not support resource-level restrictions — wildcard is required by the IAM API contract."},
                {"id": "AwsSolutions-L1", "reason": "Lambda is already configured to use Python 3.13 (the latest supported runtime). CDK Nag version may not yet recognise python3.13 as the latest."}
            ],
            apply_to_children=True
        )
        NagSuppressions.add_resource_suppressions_by_path(
            self,
            f"/{self.stack_name}/IAMPolicyCheckerRole/DefaultPolicy/Resource",
            [{"id": "AwsSolutions-IAM5", "reason": "iam:ListUsers, iam:ListUserPolicies, and iam:ListAttachedUserPolicies are account-level IAM APIs that do not support resource-level restrictions — wildcard is required by the IAM API contract."}]
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

    def create_security_contact(self, notification_email):
        """Set account security contact (CIS 1.18)"""
        security_contact = cr.AwsCustomResource(self, "SecurityContact",
            install_latest_aws_sdk=False,
            on_create=cr.AwsSdkCall(
                service="Account",
                action="putAlternateContact",
                parameters={
                    "AlternateContactType": "SECURITY",
                    "EmailAddress": notification_email,
                    "Name": "Security Contact",
                    "PhoneNumber": "+1-555-000-0000",  # placeholder
                    "Title": "Security"
                },
                physical_resource_id=cr.PhysicalResourceId.of("security-contact")
            ),
            on_update=cr.AwsSdkCall(
                service="Account",
                action="putAlternateContact",
                parameters={
                    "AlternateContactType": "SECURITY",
                    "EmailAddress": notification_email,
                    "Name": "Security Contact",
                    "PhoneNumber": "+1-555-000-0000",
                    "Title": "Security"
                },
                physical_resource_id=cr.PhysicalResourceId.of("security-contact")
            ),
            policy=cr.AwsCustomResourcePolicy.from_statements([
                iam.PolicyStatement(
                    actions=["account:PutAlternateContact"],
                    resources=["*"]
                )
            ])
        )

        # Suppress IAM5: account:PutAlternateContact is an account-level API with no resource ARN
        NagSuppressions.add_resource_suppressions(
            security_contact,
            [{"id": "AwsSolutions-IAM5", "reason": "account:PutAlternateContact is an account-level API — no resource ARN exists; wildcard is required by the API contract."}],
            apply_to_children=True
        )

        # Suppress CDK provider framework Lambda issues (IAM4 and L1)
        NagSuppressions.add_resource_suppressions_by_path(
            self,
            f"/{self.stack_name}/AWS679f53fac002430cb0da5b7982bd2287/ServiceRole/Resource",
            [{"id": "AwsSolutions-IAM4", "reason": "CDK provider framework Lambda — AWSLambdaBasicExecutionRole is attached by CDK internally; this Lambda is not customer-managed code."}]
        )
        NagSuppressions.add_resource_suppressions_by_path(
            self,
            f"/{self.stack_name}/AWS679f53fac002430cb0da5b7982bd2287/Resource",
            [{"id": "AwsSolutions-L1", "reason": "CDK provider framework Lambda — runtime version is managed by CDK internally and cannot be overridden by the customer."}]
        )
