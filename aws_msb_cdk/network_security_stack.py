from aws_cdk import (
    Stack,
    RemovalPolicy,
    aws_iam as iam,
    aws_logs as logs,
    aws_lambda as lambda_,
    aws_events as events,
    aws_events_targets as targets,
    Duration,
)
from constructs import Construct

class NetworkSecurityStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, notifications_topic=None, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Store the notifications topic
        self.notifications_topic = notifications_topic

        # Create VPC Flow Logs destination
        self.flow_logs_destination = self.create_flow_logs_destination()
        
        # Create Lambda function to secure default security groups (CIS 5.4)
        self.create_default_sg_security()

    def create_flow_logs_destination(self):
        """Create CloudWatch Logs group for VPC Flow Logs"""
        # Create IAM role for VPC Flow Logs
        flow_logs_role = iam.Role(self, "VPCFlowLogsRole",
            assumed_by=iam.ServicePrincipal("vpc-flow-logs.amazonaws.com"),
            role_name=f"msb-vpc-flow-logs-role-{self.region}"
        )

        # Create CloudWatch Logs group for VPC Flow Logs
        flow_logs_group = logs.LogGroup(self, "VPCFlowLogsGroup",
            log_group_name=f"/aws/vpc/flowlogs/{self.account}/{self.region}",
            retention=logs.RetentionDays.ONE_YEAR,
            removal_policy=RemovalPolicy.RETAIN
        )

        # Grant permissions to the role
        flow_logs_group.grant_write(flow_logs_role)

        return {
            "role": flow_logs_role,
            "log_group": flow_logs_group
        }

    def create_default_sg_security(self):
        """Create Lambda function to secure default security groups"""
        # Create the Lambda function
        secure_default_sg_function = lambda_.Function(self, "SecureDefaultSGFunction",
            runtime=lambda_.Runtime.PYTHON_3_13,
            handler="index.handler",
            code=lambda_.Code.from_inline("""
import boto3
import os
import json

def handler(event, context):
    ec2 = boto3.client('ec2')
    sns = boto3.client('sns')
    topic_arn = os.environ.get('NOTIFICATION_TOPIC_ARN', '')
    
    # Get all VPCs
    vpcs = ec2.describe_vpcs()
    
    secured_groups = []
    for vpc in vpcs['Vpcs']:
        vpc_id = vpc['VpcId']
        
        # Get default security group for this VPC
        security_groups = ec2.describe_security_groups(
            Filters=[
                {'Name': 'vpc-id', 'Values': [vpc_id]},
                {'Name': 'group-name', 'Values': ['default']}
            ]
        )
        
        for sg in security_groups['SecurityGroups']:
            sg_id = sg['GroupId']
            modified = False
            
            # Check and remove ingress rules
            if sg['IpPermissions']:
                ec2.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=sg['IpPermissions']
                )
                modified = True
            
            # Check and remove egress rules (if not the default "allow all")
            if sg['IpPermissionsEgress'] and not (
                len(sg['IpPermissionsEgress']) == 1 and
                sg['IpPermissionsEgress'][0].get('IpProtocol', '') == '-1' and
                any(ip_range.get('CidrIp') == '0.0.0.0/0' for ip_range in sg['IpPermissionsEgress'][0].get('IpRanges', []))
            ):
                ec2.revoke_security_group_egress(
                    GroupId=sg_id,
                    IpPermissions=sg['IpPermissionsEgress']
                )
                modified = True
            
            if modified:
                secured_groups.append({
                    'vpc_id': vpc_id,
                    'security_group_id': sg_id
                })
    
    # Send notification if any groups were modified
    if secured_groups and topic_arn:
        message = {
            'subject': 'Default Security Groups Secured',
            'message': 'The following default security groups were found with rules and have been secured:',
            'groups': secured_groups
        }
        
        sns.publish(
            TopicArn=topic_arn,
            Subject=message['subject'],
            Message=json.dumps(message, indent=2)
        )
    
    return {
        'statusCode': 200,
        'secured_groups_count': len(secured_groups)
    }
            """),
            timeout=Duration.seconds(60),
            environment={
                "NOTIFICATION_TOPIC_ARN": self.notifications_topic.topic_arn if self.notifications_topic else ""
            }
        )

        # Add permissions to the Lambda function
        secure_default_sg_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "ec2:DescribeSecurityGroups",
                    "ec2:DescribeVpcs",
                    "ec2:RevokeSecurityGroupIngress",
                    "ec2:RevokeSecurityGroupEgress",
                    "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
                    "ec2:UpdateSecurityGroupRuleDescriptionsEgress"
                ],
                resources=["*"]
            )
        )

        # Add SNS publish permission if notifications topic exists
        if self.notifications_topic:
            secure_default_sg_function.add_to_role_policy(
                iam.PolicyStatement(
                    actions=["sns:Publish"],
                    resources=[self.notifications_topic.topic_arn]
                )
            )

        # Schedule the Lambda to run daily
        events.Rule(self, "SecureDefaultSGSchedule",
            schedule=events.Schedule.rate(Duration.days(1)),
            targets=[targets.LambdaFunction(secure_default_sg_function)]
        )

        # Also trigger on security group changes
        sg_changes_rule = events.Rule(self, "SGChangesRule",
            event_pattern=events.EventPattern(
                source=["aws.ec2"],
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    "eventSource": ["ec2.amazonaws.com"],
                    "eventName": [
                        "AuthorizeSecurityGroupIngress",
                        "AuthorizeSecurityGroupEgress",
                        "CreateSecurityGroup"
                    ]
                }
            ),
            targets=[targets.LambdaFunction(secure_default_sg_function)]
        )