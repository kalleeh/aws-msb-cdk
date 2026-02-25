import pytest
import os
import aws_cdk as cdk
from aws_cdk.assertions import Template, Match

# Import the stacks to test
from aws_msb_cdk.iam_stack import IAMStack
from aws_msb_cdk.s3_security_stack import S3SecurityStack
from aws_msb_cdk.vpc_stack import VpcStack
from aws_msb_cdk.logging_stack import LoggingStack
from aws_msb_cdk.network_security_stack import NetworkSecurityStack
from aws_msb_cdk.compliance_stack import ComplianceStack
from aws_msb_cdk.security_monitoring_stack import SecurityMonitoringStack
from aws_msb_cdk.security_regional_stack import SecurityRegionalStack

def test_iam_stack_creates_password_policy():
    # GIVEN
    app = cdk.App()
    
    # WHEN
    stack = IAMStack(app, "TestIAMStack")
    template = Template.from_stack(stack)
    
    # THEN
    template.has_resource("AWS::IAM::AccountPasswordPolicy", {
        "Properties": {
            "MinimumPasswordLength": 16,
            "PasswordReusePrevention": 24,
            "RequireLowercaseCharacters": True,
            "RequireNumbers": True,
            "RequireSymbols": True,
            "RequireUppercaseCharacters": True,
            "AllowUsersToChangePassword": True,
            "HardExpiry": False
        }
    })

def test_s3_security_stack_blocks_public_access():
    # GIVEN
    app = cdk.App()
    
    # WHEN
    stack = S3SecurityStack(app, "TestS3SecurityStack")
    template = Template.from_stack(stack)
    
    # THEN
    template.has_resource("Custom::AWS", {})  # Custom resource for blocking public access
    
    # Verify Lambda function for blocking public access
    template.has_resource_properties("AWS::Lambda::Function", {
        "Handler": "index.handler",
        "Runtime": "python3.13",
        "Timeout": 300  # Updated to match the actual timeout
    })
    
    # Verify Lambda has proper permissions
    template.has_resource_properties("AWS::IAM::Policy", {
        "PolicyDocument": {
            "Statement": Match.array_with([
                Match.object_like({
                    "Action": "s3:PutAccountPublicAccessBlock",
                    "Effect": "Allow"
                })
            ])
        }
    })

def test_vpc_stack_creates_vpc_with_endpoints():
    # GIVEN
    app = cdk.App()
    
    # WHEN
    stack = VpcStack(app, "TestVPCStack")
    template = Template.from_stack(stack)
    
    # THEN
    template.resource_count_is("AWS::EC2::VPC", 1)
    
    # Verify VPC has proper configuration
    template.has_resource_properties("AWS::EC2::VPC", {
        "CidrBlock": "10.0.0.0/16",
        "EnableDnsHostnames": True,
        "EnableDnsSupport": True
    })
    
    # Verify Security Groups - there are 3 SGs: Bastion, Application, and VPC Endpoint SGs
    template.resource_count_is("AWS::EC2::SecurityGroup", 3)

def test_network_security_stack_creates_flow_logs_resources():
    # GIVEN
    app = cdk.App()
    
    # WHEN
    stack = NetworkSecurityStack(app, "TestNetworkSecurityStack", notifications_topic=None)
    template = Template.from_stack(stack)
    
    # THEN
    # Verify CloudWatch Log Group for Flow Logs
    template.has_resource_properties("AWS::Logs::LogGroup", {
        "RetentionInDays": 365
    })
    
    # Verify IAM Role for Flow Logs
    template.has_resource_properties("AWS::IAM::Role", {
        "AssumeRolePolicyDocument": {
            "Statement": [
                {
                    "Action": "sts:AssumeRole",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "vpc-flow-logs.amazonaws.com"
                    }
                }
            ]
        }
    })
    
    # Verify Lambda function for securing default VPC
    template.has_resource_properties("AWS::Lambda::Function", {
        "Handler": "index.handler",
        "Runtime": "python3.13"
    })

def test_compliance_stack_creates_config_rules():
    # GIVEN
    app = cdk.App()
    
    # WHEN
    stack = ComplianceStack(app, "TestComplianceStack", notifications_topic=None)
    template = Template.from_stack(stack)
    
    # THEN
    # Verify AWS Config Rules exist (compliance stack has ~26 rules)
    rules = template.find_resources("AWS::Config::ConfigRule")
    assert len(rules) >= 20

def test_security_monitoring_stack_creates_event_rules():
    # GIVEN
    import aws_cdk.aws_sns as sns
    app = cdk.App()
    topic_stack = cdk.Stack(app, "TopicStack")
    mock_topic = sns.Topic(topic_stack, "MockTopic")

    # WHEN
    stack = SecurityMonitoringStack(app, "TestSecurityMonitoringStack", notifications_topic=mock_topic)
    template = Template.from_stack(stack)

    # THEN
    # Verify EventBridge Rules - at least 3 should exist (GuardDuty, SecurityHub, IAM, SG, NACL, Root)
    rules = template.find_resources("AWS::Events::Rule")
    assert len(rules) >= 3

def test_security_regional_stack_creates_security_services():
    # GIVEN
    app = cdk.App()
    
    # WHEN
    stack = SecurityRegionalStack(app, "TestSecurityRegionalStack", notifications_topic=None)
    template = Template.from_stack(stack)
    
    # THEN
    # Verify at least one security service is created
    roles = template.find_resources("AWS::IAM::Role")
    assert len(roles) >= 1

    # Verify GuardDuty detector is created
    template.resource_count_is("AWS::GuardDuty::Detector", 1)

