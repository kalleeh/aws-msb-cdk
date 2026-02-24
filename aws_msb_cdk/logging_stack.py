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
    def __init__(self, scope: Construct, construct_id: str, s3_security_stack=None, notification_email=None, kms_stack=None, notifications_topic=None, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # S3 Bucket for Logs using secure bucket configuration if available
        if s3_security_stack:
            # NOTE: Object Lock (WORM immutability) should also be enabled on this bucket
            # for FSBP S3.11 / CIS 3.11 compliance. Object Lock must be set at bucket
            # creation time and may need to be added inside create_secure_bucket().
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
                # S3 server access logging for FSBP CloudTrail.6 / CIS 3.6
                server_access_logs_prefix="s3-access-logs/",
                # Object Lock for WORM immutability (FSBP S3.11 / CIS 3.11)
                object_lock_enabled=True,
                object_lock_default_retention=s3.ObjectLockRetention.governance(Duration.days(365)),
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

        # Use provided notifications topic or create a new one
        if notifications_topic:
            self.notifications_topic = notifications_topic
        else:
            # Get KMS key for SNS encryption if available
            sns_key = None
            if kms_stack and hasattr(kms_stack, 'master_key'):
                sns_key = kms_stack.master_key

            # SNS Topic for Notifications with KMS encryption if key is available
            self.notifications_topic = sns.Topic(self, "NotificationsTopic",
                topic_name=f"msb-notifications-{self.region}",
                display_name="MSB Security Notifications",
                master_key=sns_key  # Will be None if no KMS key is available
            )

            # Add email subscription if provided
            if notification_email:
                self.notifications_topic.add_subscription(
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
            encryption_key=cloudtrail_key
        )

        # Enable data events for the logs bucket via L2
        trail.add_s3_event_selector(
            [cloudtrail.S3EventSelector(bucket=logs_bucket)],
            include_management_events=True,
            read_write_type=cloudtrail.ReadWriteType.ALL
        )

        # Add advanced event selectors for ALL S3 buckets and ALL Lambda functions
        # using the escape hatch since CDK L2 doesn't support wildcard selectors (CIS 3.10, 3.11)
        cfn_trail = trail.node.default_child
        cfn_trail.add_property_override("AdvancedEventSelectors", [
            {
                "Name": "All S3 data events",
                "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Data"]},
                    {"Field": "resources.type", "Equals": ["AWS::S3::Object"]}
                ]
            },
            {
                "Name": "All Lambda data events",
                "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Data"]},
                    {"Field": "resources.type", "Equals": ["AWS::Lambda::Function"]}
                ]
            }
        ])

        # Get the CloudWatch Logs group created by CloudTrail
        cloudtrail_log_group = logs.LogGroup.from_log_group_name(
            self, "CloudTrailLogGroup",
            log_group_name="/aws/cloudtrail/msb-cloudtrail"
        )

        # ---------------------------------------------------------------------------
        # CloudWatch Metric Filters and Alarms — full CIS v3.0.0 set (3.1-3.14)
        # ---------------------------------------------------------------------------

        def _make_alarm(construct_id, metric, alarm_name, alarm_description, threshold=1):
            alarm = cloudwatch.Alarm(self, construct_id,
                metric=metric,
                threshold=threshold,
                comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
                evaluation_periods=1,
                alarm_name=alarm_name,
                alarm_description=alarm_description,
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
            )
            alarm.add_alarm_action(cloudwatch_actions.SnsAction(self.notifications_topic))
            return alarm

        # 1. Unauthorized API calls (CIS 3.1)
        unauthorized_api_metric = logs.MetricFilter(self, "UnauthorizedAPICallsMetricFilter",
            log_group=cloudtrail_log_group,
            filter_pattern=logs.FilterPattern.literal('{($.errorCode="*UnauthorizedOperation") || ($.errorCode="AccessDenied*")}'),
            metric_namespace="LogMetrics",
            metric_name="UnauthorizedAPICalls",
            default_value=0,
            metric_value="1"
        )
        _make_alarm("UnauthorizedAPICallsAlarm",
            metric=unauthorized_api_metric.metric(statistic="Sum", period=Duration.minutes(5)),
            alarm_name="MSB-UnauthorizedAPICalls",
            alarm_description="Unauthorized API calls — possible malicious activity (CIS 3.1)"
        )

        # 2. Console sign-in without MFA (CIS 3.2)
        console_no_mfa_metric = logs.MetricFilter(self, "ConsoleSignInWithoutMFAMetricFilter",
            log_group=cloudtrail_log_group,
            filter_pattern=logs.FilterPattern.literal('{($.eventName="ConsoleLogin") && ($.additionalEventData.MFAUsed !="Yes") && ($.userIdentity.type="IAMUser") && ($.responseElements.ConsoleLogin="Success")}'),
            metric_namespace="LogMetrics",
            metric_name="ConsoleSignInWithoutMFA",
            default_value=0,
            metric_value="1"
        )
        _make_alarm("ConsoleSignInWithoutMFAAlarm",
            metric=console_no_mfa_metric.metric(statistic="Sum", period=Duration.minutes(5)),
            alarm_name="MSB-ConsoleSignInWithoutMFA",
            alarm_description="Console sign-in without MFA (CIS 3.2)"
        )

        # 3. CloudTrail configuration changes (CIS 3.5)
        cloudtrail_config_metric = logs.MetricFilter(self, "CloudTrailConfigChangesMetricFilter",
            log_group=cloudtrail_log_group,
            filter_pattern=logs.FilterPattern.literal('{($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)}'),
            metric_namespace="LogMetrics",
            metric_name="CloudTrailConfigChanges",
            default_value=0,
            metric_value="1"
        )
        _make_alarm("CloudTrailConfigChangesAlarm",
            metric=cloudtrail_config_metric.metric(statistic="Sum", period=Duration.minutes(5)),
            alarm_name="MSB-CloudTrailConfigChanges",
            alarm_description="CloudTrail configuration changes (CIS 3.5)"
        )

        # 4. Console authentication failures (CIS 3.6) — threshold 3
        console_auth_failures_metric = logs.MetricFilter(self, "ConsoleAuthFailuresMetricFilter",
            log_group=cloudtrail_log_group,
            filter_pattern=logs.FilterPattern.literal('{($.eventName=ConsoleLogin) && ($.errorMessage="Failed authentication")}'),
            metric_namespace="LogMetrics",
            metric_name="ConsoleAuthFailures",
            default_value=0,
            metric_value="1"
        )
        _make_alarm("ConsoleAuthFailuresAlarm",
            metric=console_auth_failures_metric.metric(statistic="Sum", period=Duration.minutes(5)),
            alarm_name="MSB-ConsoleAuthFailures",
            alarm_description="Console authentication failures (CIS 3.6)",
            threshold=3
        )

        # 5. KMS CMK disabling or scheduled deletion (CIS 3.7)
        kms_key_changes_metric = logs.MetricFilter(self, "KMSKeyChangesMetricFilter",
            log_group=cloudtrail_log_group,
            filter_pattern=logs.FilterPattern.literal('{($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}'),
            metric_namespace="LogMetrics",
            metric_name="KMSKeyChanges",
            default_value=0,
            metric_value="1"
        )
        _make_alarm("KMSKeyChangesAlarm",
            metric=kms_key_changes_metric.metric(statistic="Sum", period=Duration.minutes(5)),
            alarm_name="MSB-KMSKeyChanges",
            alarm_description="KMS CMK disabling or scheduled deletion (CIS 3.7)"
        )

        # 6. S3 bucket policy changes (CIS 3.8)
        s3_bucket_policy_metric = logs.MetricFilter(self, "S3BucketPolicyChangesMetricFilter",
            log_group=cloudtrail_log_group,
            filter_pattern=logs.FilterPattern.literal('{($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || ($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) || ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))}'),
            metric_namespace="LogMetrics",
            metric_name="S3BucketPolicyChanges",
            default_value=0,
            metric_value="1"
        )
        _make_alarm("S3BucketPolicyChangesAlarm",
            metric=s3_bucket_policy_metric.metric(statistic="Sum", period=Duration.minutes(5)),
            alarm_name="MSB-S3BucketPolicyChanges",
            alarm_description="S3 bucket policy changes (CIS 3.8)"
        )

        # 7. AWS Config configuration changes (CIS 3.9)
        aws_config_changes_metric = logs.MetricFilter(self, "AWSConfigChangesMetricFilter",
            log_group=cloudtrail_log_group,
            filter_pattern=logs.FilterPattern.literal('{($.eventSource=config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder))}'),
            metric_namespace="LogMetrics",
            metric_name="AWSConfigChanges",
            default_value=0,
            metric_value="1"
        )
        _make_alarm("AWSConfigChangesAlarm",
            metric=aws_config_changes_metric.metric(statistic="Sum", period=Duration.minutes(5)),
            alarm_name="MSB-AWSConfigChanges",
            alarm_description="AWS Config configuration changes (CIS 3.9)"
        )

        # 8. Network gateway changes (CIS 3.12)
        network_gateway_metric = logs.MetricFilter(self, "NetworkGatewayChangesMetricFilter",
            log_group=cloudtrail_log_group,
            filter_pattern=logs.FilterPattern.literal('{($.eventName=CreateCustomerGateway) || ($.eventName=DeleteCustomerGateway) || ($.eventName=AttachInternetGateway) || ($.eventName=CreateInternetGateway) || ($.eventName=DeleteInternetGateway) || ($.eventName=DetachInternetGateway)}'),
            metric_namespace="LogMetrics",
            metric_name="NetworkGatewayChanges",
            default_value=0,
            metric_value="1"
        )
        _make_alarm("NetworkGatewayChangesAlarm",
            metric=network_gateway_metric.metric(statistic="Sum", period=Duration.minutes(5)),
            alarm_name="MSB-NetworkGatewayChanges",
            alarm_description="Network gateway changes (CIS 3.12)"
        )

        # 9. Route table changes (CIS 3.13)
        route_table_metric = logs.MetricFilter(self, "RouteTableChangesMetricFilter",
            log_group=cloudtrail_log_group,
            filter_pattern=logs.FilterPattern.literal('{($.eventName=CreateRoute) || ($.eventName=CreateRouteTable) || ($.eventName=ReplaceRoute) || ($.eventName=ReplaceRouteTableAssociation) || ($.eventName=DeleteRouteTable) || ($.eventName=DeleteRoute) || ($.eventName=DisassociateRouteTable)}'),
            metric_namespace="LogMetrics",
            metric_name="RouteTableChanges",
            default_value=0,
            metric_value="1"
        )
        _make_alarm("RouteTableChangesAlarm",
            metric=route_table_metric.metric(statistic="Sum", period=Duration.minutes(5)),
            alarm_name="MSB-RouteTableChanges",
            alarm_description="Route table changes (CIS 3.13)"
        )

        # 10. VPC changes (CIS 3.14)
        vpc_changes_metric = logs.MetricFilter(self, "VPCChangesMetricFilter",
            log_group=cloudtrail_log_group,
            filter_pattern=logs.FilterPattern.literal('{($.eventName=CreateVpc) || ($.eventName=DeleteVpc) || ($.eventName=ModifyVpcAttribute) || ($.eventName=AcceptVpcPeeringConnection) || ($.eventName=CreateVpcPeeringConnection) || ($.eventName=DeleteVpcPeeringConnection) || ($.eventName=RejectVpcPeeringConnection) || ($.eventName=AttachClassicLinkVpc) || ($.eventName=DetachClassicLinkVpc) || ($.eventName=DisableVpcClassicLink) || ($.eventName=EnableVpcClassicLink)}'),
            metric_namespace="LogMetrics",
            metric_name="VPCChanges",
            default_value=0,
            metric_value="1"
        )
        _make_alarm("VPCChangesAlarm",
            metric=vpc_changes_metric.metric(statistic="Sum", period=Duration.minutes(5)),
            alarm_name="MSB-VPCChanges",
            alarm_description="VPC changes (CIS 3.14)"
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
        self.notifications_topic = self.notifications_topic
        self.config_role = config_role
        self.cloudtrail_key = cloudtrail_key
        self.cloudtrail_log_group = cloudtrail_log_group
