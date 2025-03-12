from aws_cdk import (
    Stack,
    aws_iam as iam,
    aws_sns as sns,
    aws_lambda as lambda_,
    aws_events as events,
    aws_events_targets as targets,
    aws_s3 as s3,
    Duration,
    custom_resources as cr,
)
from constructs import Construct

class S3SecurityStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, notifications_topic=None, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Store the notifications topic for later use
        self.notifications_topic = notifications_topic

        # Block public access at the account level (CIS 2.1.2)
        block_public_access = cr.AwsCustomResource(self, "BlockPublicAccess",
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

        # Set default encryption for S3 buckets (CIS 2.1.1)
        self.set_default_bucket_encryption()
        
        # Create Lambda function to enforce bucket-level public access blocks (CIS 2.1.5)
        self.create_bucket_public_access_checker()
        
    def create_secure_bucket(self, scope, id, bucket_name=None, versioned=True, lifecycle_rules=None, encryption=s3.BucketEncryption.S3_MANAGED):
        """Create a secure S3 bucket with best practices"""
        bucket = s3.Bucket(scope, id,
            bucket_name=bucket_name,
            versioned=versioned,
            encryption=encryption,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            lifecycle_rules=lifecycle_rules or []
        )
        
        return bucket

    def set_default_bucket_encryption(self):
        """Set default encryption for S3 buckets"""
        default_encryption = cr.AwsCustomResource(self, "S3DefaultEncryption",
            on_create=cr.AwsSdkCall(
                service="S3Control",
                action="putBucketEncryption",
                parameters={
                    "AccountId": self.account,
                    "BucketEncryption": {
                        "ServerSideEncryptionConfiguration": {
                            "Rules": [
                                {
                                    "ApplyServerSideEncryptionByDefault": {
                                        "SSEAlgorithm": "AES256"
                                    },
                                    "BucketKeyEnabled": True
                                }
                            ]
                        }
                    }
                },
                physical_resource_id=cr.PhysicalResourceId.of("s3-default-encryption")
            ),
            policy=cr.AwsCustomResourcePolicy.from_statements([
                iam.PolicyStatement(
                    actions=["s3:PutEncryptionConfiguration"],
                    resources=["*"]
                )
            ])
        )

    def create_bucket_public_access_checker(self):
        """Create Lambda function to enforce bucket-level public access blocks"""
        # Create the Lambda function
        s3_bucket_public_access_checker = lambda_.Function(self, "S3BucketPublicAccessChecker",
            runtime=lambda_.Runtime.PYTHON_3_9,
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