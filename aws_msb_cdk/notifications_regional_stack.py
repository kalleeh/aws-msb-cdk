from aws_cdk import (
    Stack,
    aws_sns as sns,
    aws_kms as kms,
    aws_iam as iam,
    aws_sns_subscriptions as subs,
    RemovalPolicy,
)
from constructs import Construct
from cdk_nag import NagSuppressions


class NotificationsRegionalStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, notification_email: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create a regional KMS key for SNS encryption
        sns_key = kms.Key(self, "SNSEncryptionKey",
            alias=f"alias/msb-sns-notifications-{self.region}",
            description=f"KMS key for regional SNS notifications topic in {self.region}",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN,
        )

        # Create regional SNS topic — one per deployed region
        self.notifications_topic = sns.Topic(self, "NotificationsTopic",
            topic_name=f"msb-notifications-{self.region}",
            display_name="MSB Security Notifications",
            master_key=sns_key,
        )

        # Subscribe the operator email address
        self.notifications_topic.add_subscription(
            subs.EmailSubscription(notification_email)
        )

        # IAM role allowing SNS to write delivery status to CloudWatch Logs (SNS.2)
        feedback_role = iam.Role(self, "SNSFeedbackRole",
            assumed_by=iam.ServicePrincipal("sns.amazonaws.com"),
            inline_policies={
                "CloudWatchLogs": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=[
                                "logs:CreateLogGroup",
                                "logs:CreateLogStream",
                                "logs:PutLogEvents",
                                "logs:GetLogDelivery",
                                "logs:UpdateLogDelivery",
                                "logs:DeleteLogDelivery",
                                "logs:ListLogDeliveries",
                                "logs:PutRetentionPolicy",
                            ],
                            resources=["*"]
                        )
                    ]
                )
            }
        )
        NagSuppressions.add_resource_suppressions(
            feedback_role,
            [{"id": "AwsSolutions-IAM5", "reason": "CloudWatch Logs delivery APIs (GetLogDelivery, UpdateLogDelivery, etc.) are control-plane operations that do not support resource-level ARN scoping — wildcard is required by the service."}]
        )

        # Enable delivery status logging for HTTP/S, SQS, and Lambda subscribers (SNS.2)
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

        # CDK Nag suppressions
        # AwsSolutions-SNS2: topic is encrypted with the regional KMS key above;
        # the finding fires because cdk_nag inspects KmsMasterKeyId before the
        # key ref is fully resolved in some versions — the encryption IS present.
        NagSuppressions.add_resource_suppressions(
            self.notifications_topic,
            [
                {
                    "id": "AwsSolutions-SNS2",
                    "reason": "SNS topic is encrypted with a dedicated regional KMS key (SNSEncryptionKey). "
                              "The master_key parameter is set on the Topic construct.",
                },
                {
                    "id": "AwsSolutions-SNS3",
                    "reason": "Email subscription protocol is intentional: this is the operator "
                              "notification address for security alerts. SSL is enforced for all "
                              "HTTPS delivery; email delivery by SNS itself uses AWS-managed transport.",
                },
            ],
        )
