from aws_cdk import (
    Stack,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_events as events,
    aws_events_targets as targets,
    aws_s3 as s3,
    Duration,
    RemovalPolicy,
    custom_resources as cr,
)
from constructs import Construct
from cdk_nag import NagSuppressions

class S3SecurityStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, notifications_topic=None, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Store the notifications topic for later use
        self.notifications_topic = notifications_topic

        # Block public access at the account level (CIS 2.1.2)
        block_public_access = cr.AwsCustomResource(self, "BlockPublicAccess",
            install_latest_aws_sdk=False,
            on_create=cr.AwsSdkCall(
                service="S3Control",
                action="putPublicAccessBlock",
                parameters={
                    "AccountId": self.account,
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "BlockPublicPolicy": True,
                        "IgnorePublicAcls": True,
                        "RestrictPublicBuckets": True
                    }
                },
                physical_resource_id=cr.PhysicalResourceId.of("s3-block-public-access")
            ),
            policy=cr.AwsCustomResourcePolicy.from_statements([
                iam.PolicyStatement(
                    actions=["s3:PutAccountPublicAccessBlock"],
                    resources=["*"]
                )
            ])
        )

        NagSuppressions.add_resource_suppressions(
            block_public_access,
            [{"id": "AwsSolutions-IAM5", "reason": "s3:PutAccountPublicAccessBlock is an account-level S3 API — no specific bucket ARN can be specified; wildcard resource is required by the API contract."}],
            apply_to_children=True
        )

        # Create Lambda function to enforce bucket-level public access blocks (CIS 2.1.5)
        self.create_bucket_public_access_checker()

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

    def create_secure_bucket(self, scope, id, bucket_name=None, versioned=True,
                             lifecycle_rules=None,
                             encryption=s3.BucketEncryption.S3_MANAGED,
                             object_lock_enabled=False,
                             object_lock_default_retention=None):
        """Create a secure S3 bucket with best practices"""
        bucket = s3.Bucket(scope, id,
            bucket_name=bucket_name,
            encryption=encryption,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            versioned=versioned,
            removal_policy=RemovalPolicy.RETAIN,
            object_lock_enabled=object_lock_enabled,
            object_lock_default_retention=object_lock_default_retention,
            lifecycle_rules=lifecycle_rules or []
        )

        return bucket

    def create_bucket_public_access_checker(self):
        """Create Lambda function to enforce bucket-level public access blocks"""
        # Custom execution role with scoped CloudWatch Logs permissions
        # (avoids AWSLambdaBasicExecutionRole managed policy — AwsSolutions-IAM4)
        function_name = "msb-s3-public-access-checker"
        lambda_exec_role = iam.Role(self, "S3BucketPublicAccessCheckerRole",
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

        # Suppress IAM5 on the role itself: the inline policy uses a log-stream
        # wildcard (arn:...:log-group:/aws/lambda/...:*) which is the standard
        # pattern for scoped CloudWatch Logs access. The DefaultPolicy wildcard
        # is suppressed separately on the function below.
        NagSuppressions.add_resource_suppressions(
            lambda_exec_role,
            [{"id": "AwsSolutions-IAM5", "reason": "Log stream wildcard (:*) is the standard ARN suffix for CloudWatch Logs — it scopes access to streams within the named log group only, not all log groups."}],
            apply_to_children=True
        )

        # Create the Lambda function
        s3_bucket_public_access_checker = lambda_.Function(self, "S3BucketPublicAccessChecker",
            function_name=function_name,
            role=lambda_exec_role,
            runtime=lambda_.Runtime.PYTHON_3_13,
            handler="index.handler",
            code=lambda_.Code.from_inline("""
import boto3
import os
import json
import time

def handler(event, context):
    s3 = boto3.client('s3')
    sns = boto3.client('sns')
    topic_arn = os.environ.get('NOTIFICATION_TOPIC_ARN', '')

    # Get all buckets
    buckets = s3.list_buckets()['Buckets']

    enforced_buckets = []
    failed_buckets = []

    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            # Check if public access block is already configured
            try:
                public_access_block = s3.get_public_access_block(Bucket=bucket_name)
                config = public_access_block['PublicAccessBlockConfiguration']

                # If any setting is not enabled, update it
                if not (config.get('BlockPublicAcls', False) and
                        config.get('BlockPublicPolicy', False) and
                        config.get('IgnorePublicAcls', False) and
                        config.get('RestrictPublicBuckets', False)):

                    s3.put_public_access_block(
                        Bucket=bucket_name,
                        PublicAccessBlockConfiguration={
                            'BlockPublicAcls': True,
                            'BlockPublicPolicy': True,
                            'IgnorePublicAcls': True,
                            'RestrictPublicBuckets': True
                        }
                    )
                    enforced_buckets.append(bucket_name)

            except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                # No configuration exists, create one
                s3.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration={
                        'BlockPublicAcls': True,
                        'BlockPublicPolicy': True,
                        'IgnorePublicAcls': True,
                        'RestrictPublicBuckets': True
                    }
                )
                enforced_buckets.append(bucket_name)

        except Exception as e:
            failed_buckets.append({
                'bucket_name': bucket_name,
                'error': str(e)
            })

    # Send notification if any buckets were modified or failed
    if topic_arn and (enforced_buckets or failed_buckets):
        message = {
            'subject': 'S3 Bucket Public Access Block Enforcement',
            'message': 'S3 bucket public access block enforcement results:',
            'enforced_buckets': enforced_buckets,
            'failed_buckets': failed_buckets
        }

        sns.publish(
            TopicArn=topic_arn,
            Subject=message['subject'],
            Message=json.dumps(message, indent=2)
        )

    return {
        'statusCode': 200,
        'enforced_buckets_count': len(enforced_buckets),
        'failed_buckets_count': len(failed_buckets)
    }
        """),
            timeout=Duration.seconds(300),
            environment={
                "NOTIFICATION_TOPIC_ARN": self.notifications_topic.topic_arn if self.notifications_topic else ""
            }
        )

        # Add permissions to the Lambda function
        s3_bucket_public_access_checker.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "s3:GetBucketPublicAccessBlock",
                    "s3:PutBucketPublicAccessBlock",
                    "s3:ListAllMyBuckets"
                ],
                resources=["*"]
            )
        )

        # Add SNS publish permission if notifications topic exists
        if self.notifications_topic:
            s3_bucket_public_access_checker.add_to_role_policy(
                iam.PolicyStatement(
                    actions=["sns:Publish"],
                    resources=[self.notifications_topic.topic_arn]
                )
            )

        # Suppress IAM5 on the function (apply_to_children covers function-owned
        # constructs) and by-path on the role's DefaultPolicy (created lazily by
        # add_to_role_policy, so apply_to_children on the role misses it).
        NagSuppressions.add_resource_suppressions(
            s3_bucket_public_access_checker,
            [
                {"id": "AwsSolutions-IAM5", "reason": "s3:ListAllMyBuckets is an account-level API requiring wildcard resource. s3:GetBucketPublicAccessBlock and s3:PutBucketPublicAccessBlock require wildcard because the Lambda must enforce public access blocks on all buckets in the account."},
                {"id": "AwsSolutions-L1", "reason": "Lambda is already configured to use Python 3.13 (the latest supported runtime). CDK Nag version may not yet recognise python3.13 as the latest."}
            ],
            apply_to_children=True
        )
        NagSuppressions.add_resource_suppressions_by_path(
            self,
            f"/{self.stack_name}/S3BucketPublicAccessCheckerRole/DefaultPolicy/Resource",
            [{"id": "AwsSolutions-IAM5", "reason": "s3:ListAllMyBuckets requires wildcard (account-level API). s3:GetBucketPublicAccessBlock and s3:PutBucketPublicAccessBlock require wildcard because the Lambda enforces public access blocks across all buckets in the account."}]
        )

        # Schedule the Lambda to run daily
        events.Rule(self, "S3PublicAccessCheckerSchedule",
            schedule=events.Schedule.rate(Duration.days(1)),
            targets=[targets.LambdaFunction(s3_bucket_public_access_checker)]
        )

        # Also trigger on bucket creation
        bucket_creation_rule = events.Rule(self, "S3BucketCreationRule",
            event_pattern=events.EventPattern(
                source=["aws.s3"],
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    "eventSource": ["s3.amazonaws.com"],
                    "eventName": ["CreateBucket"]
                }
            ),
            targets=[targets.LambdaFunction(s3_bucket_public_access_checker)]
        )