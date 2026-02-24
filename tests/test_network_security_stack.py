import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template, Match
from aws_msb_cdk.network_security_stack import NetworkSecurityStack

class TestNetworkSecurityStack:
    @pytest.fixture
    def app(self):
        return cdk.App()
    
    @pytest.fixture
    def notifications_topic(self, app):
        # Create a mock SNS topic
        stack = cdk.Stack(app, "MockSNSStack")
        topic = cdk.aws_sns.Topic(stack, "MockTopic", 
                                 topic_name="mock-notifications",
                                 display_name="Mock Notifications")
        return topic
    
    @pytest.fixture
    def network_security_stack(self, app, notifications_topic):
        return NetworkSecurityStack(app, "TestNetworkSecurityStack", 
                                   notifications_topic=notifications_topic)
    
    @pytest.fixture
    def template(self, network_security_stack):
        return Template.from_stack(network_security_stack)
    
    def test_flow_logs_destination_created(self, template):
        # Verify IAM roles are created
        roles = template.find_resources("AWS::IAM::Role")
        assert len(roles) >= 1
        
        # Find the flow logs role
        flow_logs_role = None
        for role_id, role in roles.items():
            assume_role_policy = role["Properties"]["AssumeRolePolicyDocument"]
            for statement in assume_role_policy["Statement"]:
                if statement.get("Principal", {}).get("Service") == "vpc-flow-logs.amazonaws.com":
                    flow_logs_role = role
                    break
            if flow_logs_role:
                break
        
        assert flow_logs_role is not None
        
        # Verify CloudWatch Logs group is created
        template.resource_count_is("AWS::Logs::LogGroup", 1)
        
        # Verify log group properties
        template.has_resource_properties("AWS::Logs::LogGroup", {
            "RetentionInDays": 365
        })
    
    def test_secure_default_sg_lambda_created(self, template):
        # Verify Lambda function is created
        template.resource_count_is("AWS::Lambda::Function", 1)
        
        # Verify Lambda properties
        template.has_resource_properties("AWS::Lambda::Function", {
            "Handler": "index.handler",
            "Runtime": "python3.13",
            "Timeout": 60,
            "Environment": {
                "Variables": {
                    "NOTIFICATION_TOPIC_ARN": Match.any_value()
                }
            }
        })
        
        # Verify Lambda code includes security group operations
        lambda_functions = template.find_resources("AWS::Lambda::Function")
        lambda_id = list(lambda_functions.keys())[0]
        lambda_props = lambda_functions[lambda_id]["Properties"]
        
        # Check that the Lambda code contains key functions for securing default SGs
        code = lambda_props["Code"]["ZipFile"]
        assert "revoke_security_group_ingress" in code
        assert "revoke_security_group_egress" in code
        assert "describe_security_groups" in code
        assert "default" in code  # Check for default security group reference
    
    def test_lambda_iam_permissions(self, template):
        # Verify Lambda execution role has necessary permissions
        template.has_resource_properties("AWS::IAM::Policy", {
            "PolicyDocument": {
                "Statement": Match.array_with([
                    Match.object_like({
                        "Action": Match.array_with([
                            "ec2:DescribeSecurityGroups",
                            "ec2:DescribeVpcs",
                            "ec2:RevokeSecurityGroupIngress",
                            "ec2:RevokeSecurityGroupEgress"
                        ]),
                        "Effect": "Allow",
                        "Resource": "*"
                    })
                ])
            }
        })
        
        # Verify SNS publish permission
        template.has_resource_properties("AWS::IAM::Policy", {
            "PolicyDocument": {
                "Statement": Match.array_with([
                    Match.object_like({
                        "Action": "sns:Publish",
                        "Effect": "Allow"
                    })
                ])
            }
        })
    
    def test_lambda_scheduled_execution(self, template):
        # Verify EventBridge rule for scheduled execution
        template.resource_count_is("AWS::Events::Rule", 2)  # One for schedule, one for SG changes
        
        # Verify scheduled rule
        scheduled_rules = template.find_resources("AWS::Events::Rule", {
            "Properties": {
                "ScheduleExpression": Match.any_value()
            }
        })
        assert len(scheduled_rules) == 1
        
        # Get the rule ID
        rule_id = list(scheduled_rules.keys())[0]
        rule = scheduled_rules[rule_id]
        
        # Verify rule has targets
        targets = rule["Properties"].get("Targets", [])
        assert len(targets) > 0
        
        # Verify at least one target has an Arn
        target_with_arn = next((target for target in targets if "Arn" in target), None)
        assert target_with_arn is not None
    
    def test_security_group_changes_event_rule(self, template):
        # Verify EventBridge rule for security group changes
        sg_change_rules = template.find_resources("AWS::Events::Rule", {
            "Properties": {
                "EventPattern": Match.object_like({
                    "source": ["aws.ec2"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventSource": ["ec2.amazonaws.com"],
                        "eventName": Match.array_with([
                            "AuthorizeSecurityGroupIngress",
                            "AuthorizeSecurityGroupEgress",
                            "CreateSecurityGroup"
                        ])
                    }
                })
            }
        })
        assert len(sg_change_rules) == 1