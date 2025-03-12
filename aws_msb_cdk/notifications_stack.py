from aws_cdk import (
    Stack,
    aws_sns as sns,
    aws_kms as kms,
    aws_sns_subscriptions as subs,
    RemovalPolicy
)
from constructs import Construct

class NotificationsStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, kms_key=None, notification_email=None, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create KMS key for SNS encryption if not provided
        if not kms_key:
            kms_key = kms.Key(self, "SNSEncryptionKey",
                alias=f"alias/msb-sns-encryption-{self.region}",
                description="KMS key for SNS topic encryption",
                enable_key_rotation=True,
                removal_policy=RemovalPolicy.RETAIN
            )

        # Create SNS topic with KMS encryption
        self.notifications_topic = sns.Topic(self, "NotificationsTopic",
            topic_name=f"msb-notifications-{self.region}",
            display_name="MSB Security Notifications",
            master_key=kms_key  # Enable encryption with KMS
        )

        # Add email subscription if provided
        if notification_email:
            self.notifications_topic.add_subscription(
                subs.EmailSubscription(notification_email)
            )