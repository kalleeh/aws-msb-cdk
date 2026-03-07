#!/usr/bin/env python3
import os
from aws_cdk import App, Environment
import aws_cdk
from aws_msb_cdk.iam_stack import IAMStack
from aws_msb_cdk.logging_stack import LoggingStack
from aws_msb_cdk.logging_regional_stack import LoggingRegionalStack
from aws_msb_cdk.security_regional_stack import SecurityRegionalStack
from aws_msb_cdk.vpc_stack import VpcStack
from aws_msb_cdk.s3_security_stack import S3SecurityStack
from aws_msb_cdk.kms_stack import KMSStack
from aws_msb_cdk.network_security_stack import NetworkSecurityStack
from aws_msb_cdk.compliance_stack import ComplianceStack
from aws_msb_cdk.security_monitoring_stack import SecurityMonitoringStack
from aws_msb_cdk.notifications_regional_stack import NotificationsRegionalStack
from aws_msb_cdk.waf_stack import WafStack

app = App()
from cdk_nag import AwsSolutionsChecks
from aws_cdk import Aspects
Aspects.of(app).add(AwsSolutionsChecks(verbose=False))

from aws_cdk import Tags
Tags.of(app).add("Project", "MSB")
Tags.of(app).add("ManagedBy", "CDK")
Tags.of(app).add("Environment", "Production")

# Get deployment context
notification_email = app.node.try_get_context("notification_email")
security_contact_phone = app.node.try_get_context("security_contact_phone")
enable_object_lock = str(app.node.try_get_context("enable_object_lock") or "false").lower() == "true"
global_region = app.node.try_get_context("global_region") or "us-east-1"
target_regions = app.node.try_get_context("target_regions") or [global_region]
target = app.node.try_get_context("target")  # Optional: 'global' or 'regional'
if target and target not in ["global", "regional"]:
    raise ValueError(f"Invalid target '{target}'. Must be 'global' or 'regional'.")

if not notification_email:
    raise ValueError(
        "notification_email is required. Provide it with: "
        "--context notification_email=your.email@example.com"
    )

# Account ID is the same for all environments
account_id = os.environ.get('CDK_DEFAULT_ACCOUNT')

# Global resources - deploy only in the global region
if not target or target == "global":
    global_env = Environment(account=account_id, region=global_region)
    
    print(f"Deploying global resources in {global_region}")

    # KMS Stack (needs to be created early for encryption keys)
    kms_stack = KMSStack(app, "MSB-KMS-Global", env=global_env, termination_protection=True)

    # LoggingStack — creates the SNS topic and its own secure log bucket
    logging_stack = LoggingStack(app, "MSB-Logging-Global",
        notification_email=notification_email,
        kms_stack=kms_stack,
        enable_object_lock=enable_object_lock,
        env=global_env,
        termination_protection=True
    )

    # KMSStack can store the topic reference (doesn't use it at construction time)
    kms_stack.notifications_topic = logging_stack.notifications_topic

    # IAM Stack — created after LoggingStack so the notifications topic is available
    iam_stack = IAMStack(app, "MSB-IAM-Global",
        notifications_topic=logging_stack.notifications_topic,
        notification_email=notification_email,
        security_contact_phone=security_contact_phone,
        env=global_env,
        termination_protection=True
    )

    # S3SecurityStack now gets the real topic from the start
    s3_security_stack = S3SecurityStack(app, "MSB-S3-Security",
        notifications_topic=logging_stack.notifications_topic,
        env=global_env
    )

    from aws_cdk import CfnOutput
    CfnOutput(logging_stack, "NotificationsTopicArn",
        value=logging_stack.notifications_topic.topic_arn,
        description="MSB Security Notifications SNS Topic ARN",
        export_name="MSB-NotificationsTopicArn"
    )
    CfnOutput(logging_stack, "LogsBucketName",
        value=logging_stack.logs_bucket.bucket_name,
        description="MSB Centralized Logs S3 Bucket",
        export_name="MSB-LogsBucketName"
    )

# Regional resources - deploy in all target regions
if not target or target == "regional":
    for region in target_regions:
        regional_env = Environment(account=account_id, region=region)
        
        print(f"Deploying regional resources in {region}")
        
        # For regional resources, we need to reference the global resources
        # If we're only deploying regional resources or if we're in a non-global region,
        # we need to import the global resources
        if target == "regional" or region != global_region:
            # Pass raw strings so each stack can import resources locally in its
            # own scope — sharing an imported construct across stacks causes CDK
            # to raise a cross-stack EventBridge target error even when the
            # account/region are the same.
            logs_bucket = f"msb-logs-{account_id}-{global_region}"
            config_role = f"msb-config-role-{global_region}"
        else:
            # Use the resources created in this deployment
            logs_bucket = logging_stack.logs_bucket
            config_role = logging_stack.config_role

        # Every deployed region gets its own SNS notifications topic so that
        # EventBridge rules in that region have a same-region delivery target.
        # (EventBridge → SNS cross-region targets are not supported.)
        if target == "regional" or region != global_region:
            # Create a dedicated regional notifications topic
            notifications_regional_stack = NotificationsRegionalStack(
                app, f"MSB-Notifications-Regional-{region}",
                notification_email=notification_email,
                env=regional_env,
                termination_protection=True,
            )
            notifications_topic = notifications_regional_stack.notifications_topic
        else:
            # Global region in a combined deploy — reuse the topic from LoggingStack
            notifications_topic = logging_stack.notifications_topic

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

        # VPC Stack with VPC endpoints
        vpc_stack = VpcStack(app, f"MSB-VPC-Regional-{region}", 
            flow_logs_destination=network_security_stack.flow_logs_destination,
            env=regional_env
        )

        # Compliance Stack
        compliance_stack = ComplianceStack(app, f"MSB-Compliance-{region}",
            notifications_topic=notifications_topic,
            env=regional_env
        )

        # Optional WAF Stack - enable with --context enable_waf=true
        enable_waf = app.node.try_get_context("enable_waf")
        if enable_waf and str(enable_waf).lower() == "true":
            waf_stack = WafStack(app, f"MSB-WAF-{region}",
                notifications_topic=notifications_topic,
                env=regional_env
            )

app.synth()
