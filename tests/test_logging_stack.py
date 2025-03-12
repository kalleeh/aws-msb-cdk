import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template, Match
from aws_msb_cdk.logging_stack import LoggingStack

class TestLoggingStack:
    @pytest.fixture
    def app(self):
        return cdk.App()
    
    @pytest.fixture
    def logging_stack(self, app):
        return LoggingStack(app, "TestLoggingStack", notification_email="test@example.com")
    
    @pytest.fixture
    def template(self, logging_stack):
        return Template.from_stack(logging_stack)
    
    def test_logs_bucket_created(self, template):
        # Verify S3 bucket is created
        template.resource_count_is("AWS::S3::Bucket", 1)
        
        # Verify bucket properties
        template.has_resource_properties("AWS::S3::Bucket", {
            "BucketEncryption": {
                "ServerSideEncryptionConfiguration": [
                    {
                        "ServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }
                ]
            },
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "BlockPublicPolicy": True,
                "IgnorePublicAcls": True,
                "RestrictPublicBuckets": True
            },
            "VersioningConfiguration": {
                "Status": "Enabled"
            }
        })
        
        # Verify bucket policy
        template.resource_count_is("AWS::S3::BucketPolicy", 1)
    
    def test_sns_topic_created(self, template):
        # Verify SNS topic is created
        template.resource_count_is("AWS::SNS::Topic", 1)
        
        # Verify topic properties
        template.has_resource_properties("AWS::SNS::Topic", {
            "DisplayName": "MSB Security Notifications"
        })
        
        # Verify subscription
        template.resource_count_is("AWS::SNS::Subscription", 1)
        template.has_resource_properties("AWS::SNS::Subscription", {
            "Protocol": "email",
            "Endpoint": "test@example.com"
        })
    
    def test_cloudtrail_created(self, template):
        # Verify CloudTrail is created
        template.resource_count_is("AWS::CloudTrail::Trail", 1)
        
        # Verify CloudTrail properties
        template.has_resource_properties("AWS::CloudTrail::Trail", {
            "IsMultiRegionTrail": True,
            "IncludeGlobalServiceEvents": True,
            "EnableLogFileValidation": True,
            "EventSelectors": Match.array_with([
                Match.object_like({
                    "ReadWriteType": "All"
                })
            ])
        })
    
    def test_kms_key_created(self, template):
        # Verify KMS key is created for CloudTrail
        template.resource_count_is("AWS::KMS::Key", 1)
        
        # Verify key properties
        template.has_resource_properties("AWS::KMS::Key", {
            "EnableKeyRotation": True,
            "Description": "KMS key for CloudTrail encryption"
        })
        
        # Verify alias exists (without checking the exact name which is dynamic)
        template.resource_count_is("AWS::KMS::Alias", 1)
    
    def test_cloudwatch_metric_filter_created(self, template):
        # Verify metric filter is created
        template.resource_count_is("AWS::Logs::MetricFilter", 1)
        
        # Verify filter properties
        template.has_resource_properties("AWS::Logs::MetricFilter", {
            "FilterPattern": '{($.errorCode="*UnauthorizedOperation") || ($.errorCode="AccessDenied*")}',
            "MetricTransformations": [
                {
                    "MetricName": "UnauthorizedAPICalls",
                    "MetricNamespace": "LogMetrics",
                    "MetricValue": "1"
                }
            ]
        })
    
    def test_cloudwatch_alarm_created(self, template):
        # Verify alarm is created
        template.resource_count_is("AWS::CloudWatch::Alarm", 1)
        
        # Verify alarm properties
        template.has_resource_properties("AWS::CloudWatch::Alarm", {
            "AlarmName": "MSB-UnauthorizedAPICalls",
            "ComparisonOperator": "GreaterThanOrEqualToThreshold",
            "EvaluationPeriods": 1,
            "Threshold": 1,
            "TreatMissingData": "notBreaching"
        })
    
    def test_iam_roles_created(self, template):
        # Verify IAM roles are created
        roles = template.find_resources("AWS::IAM::Role")
        assert len(roles) >= 1
        
        # Verify at least one role has CloudTrail in its name or path
        cloudtrail_roles = [role for role_id, role in roles.items() 
                           if "CloudTrail" in role_id]
        assert len(cloudtrail_roles) >= 1

class TestLoggingStackWithKMS:
    @pytest.fixture
    def app(self):
        return cdk.App()
    
    @pytest.fixture
    def kms_stack(self, app):
        # Create a mock KMS stack
        stack = cdk.Stack(app, "MockKMSStack")
        
        # Create a master key
        master_key = cdk.aws_kms.Key(stack, "MasterKey",
            enable_key_rotation=True,
            alias="alias/msb-master-key"
        )
        
        # Create a CloudTrail key
        cloudtrail_key = cdk.aws_kms.Key(stack, "CloudTrailKey",
            enable_key_rotation=True,
            alias="alias/msb-cloudtrail-key"
        )
        
        # Add properties to the stack
        stack.master_key = master_key
        stack.cloudtrail_key = cloudtrail_key
        
        return stack
    
    @pytest.fixture
    def logging_stack_with_kms(self, app, kms_stack):
        return LoggingStack(app, "TestLoggingStackWithKMS", 
                           notification_email="test@example.com",
                           kms_stack=kms_stack)
    
    @pytest.fixture
    def template(self, logging_stack_with_kms):
        return Template.from_stack(logging_stack_with_kms)
    
    def test_sns_topic_with_kms_encryption(self, template):
        # Verify SNS topic is created with KMS encryption
        template.has_resource_properties("AWS::SNS::Topic", {
            "DisplayName": "MSB Security Notifications",
            "KmsMasterKeyId": Match.any_value()
        })
    
    def test_cloudtrail_with_kms_encryption(self, template):
        # Verify CloudTrail is created with KMS encryption
        template.has_resource_properties("AWS::CloudTrail::Trail", {
            "KMSKeyId": Match.any_value()
        })
    
    def test_no_additional_kms_keys_created(self, template):
        # Verify no additional KMS keys are created when provided by KMS stack
        # We should have 0 keys created in this stack since they come from the KMS stack
        keys = template.find_resources("AWS::KMS::Key")
        assert len(keys) == 0