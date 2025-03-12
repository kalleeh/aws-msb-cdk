from aws_cdk import (
    Stack,
    aws_s3 as s3,
    aws_cloudtrail as cloudtrail,
    aws_iam as iam,
    aws_logs as logs,
    aws_sns as sns,
    aws_sns_subscriptions as sns_subs,
    aws_kms as kms,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cloudwatch_actions,
    aws_logs_destinations as logs_destinations,
    RemovalPolicy,
    Duration,
)
from constructs import Construct

class LoggingStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, s3_security_stack=None, notification_email=None, kms_stack=None, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # S3 Bucket for Logs using secure bucket configuration if available
        if s3_security_stack:
            logs_bucket = s3_security_stack.create_secure_bucket(self, "LogsBucket",
                bucket_name=f"msb-logs-{self.account}-{self.region}",
                lifecycle_rules=[
                    s3.LifecycleRule(
                        id="LogRetention",
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
        else:
            # Fallback if s3_security_stack is not provided
            logs_bucket = s3.Bucket(self, "LogsBucket",
                bucket_name=f"msb-logs-{self.account}-{self.region}",
                encryption=s3.BucketEncryption.S3_MANAGED,
                block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                enforce_ssl=True,
                versioned=True,
                removal_policy=RemovalPolicy.RETAIN,
                lifecycle_rules=[
                    s3.LifecycleRule(
                        id="LogRetention",
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

        # SNS Topic for Notifications using L2 construct
        notifications_topic = sns.Topic(self, "NotificationsTopic",
            topic_name=f"msb-notifications-{self.region}",
            display_name="MSB Security Notifications"
        )
        
        # Add email subscription if provided
        if notification_email:
            notifications_topic.add_subscription(
                sns_subs.EmailSubscription(notification_email)
            )

        # Get KMS key for CloudTrail encryption if available
        cloudtrail_key = None
        if kms_stack and hasattr(kms_stack, 'cloudtrail_key'):
            cloudtrail_key = kms_stack.cloudtrail_key
        else:
            # Create a new KMS key for CloudTrail if not provided
            cloudtrail_key = kms.Key(self, "CloudTrailKey",
                alias=f"alias/msb-cloudtrail-key-{self.region}",
                description="KMS key for CloudTrail encryption",
                enable_key_rotation=True,
                removal_policy=RemovalPolicy.RETAIN
            )
            
            # Add CloudTrail service principal to key policy
            cloudtrail_key.add_to_resource_policy(
                iam.PolicyStatement(
                    sid="AllowCloudTrailToEncryptLogs",
                    actions=["kms:GenerateDataKey*"],
                    principals=[iam.ServicePrincipal("cloudtrail.amazonaws.com")],
                    resources=["*"],
                    conditions={
                        "StringLike": {
                            "kms:EncryptionContext:aws:cloudtrail:arn": f"arn:aws:cloudtrail:*:{self.account}:trail/*"
                        }
                    }
                )
            )

        # CloudTrail using L2 construct with KMS encryption
        trail = cloudtrail.Trail(self, "CloudTrail",
            bucket=logs_bucket,
            send_to_cloud_watch_logs=True,
            cloud_watch_logs_retention=logs.RetentionDays.ONE_YEAR,
            is_multi_region_trail=True,
            include_global_service_events=True,
            enable_file_validation=True,
            management_events=cloudtrail.ReadWriteType.ALL,
            trail_name="msb-cloudtrail",
            encryption_key=cloudtrail_key  # Add KMS encryption (correct parameter name)
        )
        
        # Enable data events for S3 and Lambda
        trail.add_s3_event_selector([
            cloudtrail.S3EventSelector(
                bucket=logs_bucket
            )
        ])
        
        # Get the CloudWatch Logs group created by CloudTrail
        # CloudTrail automatically creates a log group with the name /aws/cloudtrail/trail-name
        cloudtrail_log_group = logs.LogGroup.from_log_group_name(
            self, "CloudTrailLogGroup", 
            log_group_name="/aws/cloudtrail/msb-cloudtrail"
        )
        
        # Create metric filters and alarms for CloudTrail logs
        
        # 1. Unauthorized API calls metric filter and alarm (CloudWatch.2)
        unauthorized_api_metric = logs.MetricFilter(self, "UnauthorizedAPICallsMetricFilter",
            log_group=cloudtrail_log_group,
            filter_pattern=logs.FilterPattern.literal('{($.errorCode="*UnauthorizedOperation") || ($.errorCode="AccessDenied*")}'),
            metric_namespace="LogMetrics",
            metric_name="UnauthorizedAPICalls",
            default_value=0,
            metric_value="1"
        )
        
        unauthorized_api_alarm = cloudwatch.Alarm(self, "UnauthorizedAPICallsAlarm",
            metric=unauthorized_api_metric.metric(
                statistic="Sum",
                period=Duration.minutes(5)
            ),
            threshold=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            evaluation_periods=1,
            alarm_name="MSB-UnauthorizedAPICalls",
            alarm_description="Alarm for unauthorized API calls that could indicate malicious activity",
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
        )
        
        # Add SNS action to the alarm
        unauthorized_api_alarm.add_alarm_action(
            cloudwatch_actions.SnsAction(notifications_topic)
        )
        
        # AWS Config Role using L2 construct
        config_role = iam.Role(self, "ConfigRole",
            role_name=f"msb-config-role-{self.region}",
            assumed_by=iam.ServicePrincipal("config.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWS_ConfigRole")
            ]
        )
        
        # Add S3 bucket policy for Config
        logs_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AWSConfigBucketPermissions",
                effect=iam.Effect.ALLOW,
                principals=[iam.ServicePrincipal("config.amazonaws.com")],
                actions=[
                    "s3:GetBucketAcl",
                    "s3:ListBucket"
                ],
                resources=[logs_bucket.bucket_arn]
            )
        )
        
        logs_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AWSConfigBucketDelivery",
                effect=iam.Effect.ALLOW,
                principals=[iam.ServicePrincipal("config.amazonaws.com")],
                actions=["s3:PutObject"],
                resources=[f"{logs_bucket.bucket_arn}/AWSLogs/{self.account}/Config/*"],
                conditions={
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control"
                    }
                }
            )
        )
        
        # Export resources for other stacks
        self.logs_bucket = logs_bucket
        self.notifications_topic = notifications_topic
        self.config_role = config_role
        self.cloudtrail_key = cloudtrail_key
        self.cloudtrail_log_group = cloudtrail_log_group