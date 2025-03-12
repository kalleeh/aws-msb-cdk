#!/usr/bin/env python3
import os
from aws_cdk import App, Environment
import aws_cdk
from aws_msb_cdk.iam_stack import IAMStack
from aws_msb_cdk.logging_stack import LoggingStack
from aws_msb_cdk.logging_regional_stack import LoggingRegionalStack
from aws_msb_cdk.security_regional_stack import SecurityRegionalStack
from aws_msb_cdk.vpc_stack import VpcStack
from aws_msb_cdk.vpc_endpoints_stack import VpcEndpointsStack
from aws_msb_cdk.s3_security_stack import S3SecurityStack
from aws_msb_cdk.kms_stack import KMSStack
from aws_msb_cdk.network_security_stack import NetworkSecurityStack
from aws_msb_cdk.compliance_stack import ComplianceStack
from aws_msb_cdk.security_monitoring_stack import SecurityMonitoringStack
from aws_msb_cdk.notifications_stack import NotificationsStack

app = App()

# Get deployment context
notification_email = app.node.try_get_context("notification_email")
global_region = app.node.try_get_context("global_region") or "us-east-1"
target_regions = app.node.try_get_context("target_regions") or [global_region]
target = app.node.try_get_context("target")  # Optional: 'global' or 'regional'

if not notification_email:
    print("WARNING: notification_email not provided in context. Please provide it using --context notification_email=your.email@example.com")

# Account ID is the same for all environments
account_id = os.environ.get('CDK_DEFAULT_ACCOUNT')

# Global resources - deploy only in the global region
if not target or target == "global":
    global_env = Environment(account=account_id, region=global_region)
    
    print(f"Deploying global resources in {global_region}")
    
    # IAM Stack with password policy
    iam_stack = IAMStack(app, "MSB-IAM-Global", env=global_env)

    # KMS Stack
    kms_stack = KMSStack(app, "MSB-KMS-Global", 
        notifications_topic=None,  # Will be updated after notifications_stack is created
        env=global_env
    )

    # Notifications Stack with SNS encryption
    notifications_stack = NotificationsStack(app, "MSB-Notifications-Global",
        kms_key=kms_stack.master_key,
        notification_email=notification_email,
        env=global_env
    )

    # S3 Security Stack (needs to be created early for other stacks to use)
    s3_security_stack = S3SecurityStack(app, "MSB-S3-Security", 
        notifications_topic=notifications_stack.notifications_topic,
        env=global_env
    )

    # Logging Stack (uses S3 security configuration)
    logging_stack = LoggingStack(app, "MSB-Logging-Global", 
        s3_security_stack=s3_security_stack,
        notification_email=notification_email,
        env=global_env
    )

    # Update KMS Stack with notifications topic
    kms_stack.notifications_topic = notifications_stack.notifications_topic

# Regional resources - deploy in all target regions
if not target or target == "regional":
    for region in target_regions:
        regional_env = Environment(account=account_id, region=region)
        
        print(f"Deploying regional resources in {region}")
        
        # For regional resources, we need to reference the global resources
        # If we're only deploying regional resources or if we're in a non-global region,
        # we need to import the global resources
        if target == "regional" or region != global_region:
            # Import global resources
            logs_bucket_name = f"msb-logs-{account_id}-{global_region}"
            logs_bucket = aws_cdk.aws_s3.Bucket.from_bucket_name(
                app, f"ImportedLogsBucket-{region}", logs_bucket_name
            )
            
            notifications_topic_name = f"msb-notifications-{global_region}"
            notifications_topic = aws_cdk.aws_sns.Topic.from_topic_name(
                app, f"ImportedNotificationsTopic-{region}", notifications_topic_name
            )
            
            config_role_name = f"msb-config-role-{global_region}"
            config_role = aws_cdk.aws_iam.Role.from_role_name(
                app, f"ImportedConfigRole-{region}", config_role_name
            )
        else:
            # Use the resources created in this deployment
            logs_bucket = logging_stack.logs_bucket
            notifications_topic = notifications_stack.notifications_topic
            config_role = logging_stack.config_role

        # Network Security Stack
        network_security_stack = NetworkSecurityStack(app, f"MSB-Network-Security-{region}",
            notifications_topic=notifications_topic,
            env=regional_env
        )

        # Regional logging stack
        logging_regional_stack = LoggingRegionalStack(app, f"MSB-Logging-Regional-{region}",
            logs_bucket=logs_bucket,
            config_role=config_role,
            env=regional_env
        )

        # Security regional stack
        security_regional_stack = SecurityRegionalStack(app, f"MSB-Security-Regional-{region}",
            notifications_topic=notifications_topic,
            notification_email=notification_email,
            env=regional_env
        )

        # Security Monitoring Stack (centralized event monitoring)
        security_monitoring = SecurityMonitoringStack(app, f"MSB-Security-Monitoring-{region}",
            notifications_topic=notifications_topic,
            env=regional_env
        )

        # VPC Stack
        vpc_stack = VpcStack(app, f"MSB-VPC-Regional-{region}", 
            flow_logs_destination=network_security_stack.flow_logs_destination,
            env=regional_env
        )
        
        # VPC Endpoints Stack
        vpc_endpoints_stack = VpcEndpointsStack(app, f"MSB-VPC-Endpoints-{region}",
            vpc=vpc_stack.vpc,
            env=regional_env
        )

        # Compliance Stack
        compliance_stack = ComplianceStack(app, f"MSB-Compliance-{region}",
            notifications_topic=notifications_topic,
            env=regional_env
        )

app.synth()