from aws_cdk import (
    Stack,
    aws_config as config,
    aws_iam as iam,
    aws_s3 as s3,
    aws_logs as logs,
)
from constructs import Construct

class LoggingRegionalStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, logs_bucket, config_role, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # AWS Config Recorder using L2 construct
        recorder = config.CfnConfigurationRecorder(self, "ConfigRecorder",
            role_arn=config_role.role_arn,
            recording_group=config.CfnConfigurationRecorder.RecordingGroupProperty(
                all_supported=True
            )
        )

        # AWS Config Delivery Channel using L2 construct
        delivery_channel = config.CfnDeliveryChannel(self, "ConfigDeliveryChannel",
            s3_bucket_name=logs_bucket.bucket_name,
            s3_key_prefix="config",
            config_snapshot_delivery_properties=config.CfnDeliveryChannel.ConfigSnapshotDeliveryPropertiesProperty(
                delivery_frequency="Six_Hours"
            )
        )
        
        # Make sure the recorder is created before the delivery channel
        delivery_channel.add_depends_on(recorder)
        
        # Create CloudWatch Log Group for Config
        config_logs = logs.LogGroup(self, "ConfigLogsGroup",
            log_group_name=f"/aws/config/{self.region}",
            retention=logs.RetentionDays.ONE_YEAR
        )
        
        # Create CloudWatch Log Group for VPC Flow Logs
        vpc_flow_logs = logs.LogGroup(self, "VPCFlowLogsGroup",
            log_group_name=f"/aws/vpc/flowlogs/{self.region}",
            retention=logs.RetentionDays.ONE_YEAR
        )