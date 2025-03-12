from aws_cdk import (
    Stack,
    aws_events as events,
    aws_events_targets as targets,
    aws_sns as sns,
)
from constructs import Construct

class SecurityMonitoringStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, notifications_topic=None, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Store the notifications topic
        self.notifications_topic = notifications_topic

        # Create EventBridge rules for security monitoring
        self.create_security_event_rules()
        
        # Create root account activity monitoring (CIS 1.7, IAM.7)
        self.create_root_account_monitoring()

    def create_security_event_rules(self):
        """Create EventBridge rules for security monitoring"""
        if not self.notifications_topic:
            return

        # GuardDuty findings rule
        guardduty_rule = events.Rule(self, "GuardDutyFindingsRule",
            rule_name=f"msb-guardduty-findings-{self.region}",
            description="Detects GuardDuty findings",
            event_pattern=events.EventPattern(
                source=["aws.guardduty"],
                detail_type=["GuardDuty Finding"]
            )
        )
        guardduty_rule.add_target(targets.SnsTopic(self.notifications_topic))

        # Security Hub findings rule
        security_hub_rule = events.Rule(self, "SecurityHubFindingsRule",
            rule_name=f"msb-security-hub-findings-{self.region}",
            description="Detects Security Hub findings",
            event_pattern=events.EventPattern(
                source=["aws.securityhub"],
                detail_type=["Security Hub Findings - Imported"]
            )
        )
        security_hub_rule.add_target(targets.SnsTopic(self.notifications_topic))

        # IAM changes rule
        iam_changes_rule = events.Rule(self, "IAMChangesRule",
            rule_name=f"msb-iam-changes-{self.region}",
            description="Detects IAM changes",
            event_pattern=events.EventPattern(
                source=["aws.iam"],
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    "eventSource": ["iam.amazonaws.com"],
                    "eventName": [
                        "DeleteGroupPolicy",
                        "DeleteRolePolicy",
                        "DeleteUserPolicy",
                        "PutGroupPolicy",
                        "PutRolePolicy",
                        "PutUserPolicy",
                        "CreatePolicy",
                        "DeletePolicy",
                        "CreateUser",
                        "DeleteUser",
                        "AttachRolePolicy",
                        "DetachRolePolicy",
                        "AttachUserPolicy",
                        "DetachUserPolicy",
                        "AttachGroupPolicy",
                        "DetachGroupPolicy"
                    ]
                }
            )
        )
        iam_changes_rule.add_target(targets.SnsTopic(self.notifications_topic))

        # Security group changes rule
        sg_changes_rule = events.Rule(self, "SecurityGroupChangesRule",
            rule_name=f"msb-security-group-changes-{self.region}",
            description="Detects changes to security groups",
            event_pattern=events.EventPattern(
                source=["aws.ec2"],
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    "eventSource": ["ec2.amazonaws.com"],
                    "eventName": [
                        "AuthorizeSecurityGroupIngress",
                        "AuthorizeSecurityGroupEgress",
                        "RevokeSecurityGroupIngress",
                        "RevokeSecurityGroupEgress",
                        "CreateSecurityGroup",
                        "DeleteSecurityGroup"
                    ]
                }
            )
        )
        sg_changes_rule.add_target(targets.SnsTopic(self.notifications_topic))

        # Network ACL changes rule
        nacl_changes_rule = events.Rule(self, "NetworkACLChangesRule",
            rule_name=f"msb-nacl-changes-{self.region}",
            description="Detects changes to network ACLs",
            event_pattern=events.EventPattern(
                source=["aws.ec2"],
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    "eventSource": ["ec2.amazonaws.com"],
                    "eventName": [
                        "CreateNetworkAcl",
                        "DeleteNetworkAcl",
                        "CreateNetworkAclEntry",
                        "DeleteNetworkAclEntry",
                        "ReplaceNetworkAclEntry",
                        "ReplaceNetworkAclAssociation"
                    ]
                }
            )
        )
        nacl_changes_rule.add_target(targets.SnsTopic(self.notifications_topic))

    def create_root_account_monitoring(self):
        """Create EventBridge rules to monitor root account activity"""
        if not self.notifications_topic:
            return

        # Root account sign-in rule
        root_activity_rule = events.Rule(self, "RootActivityMonitoringRule",
            rule_name=f"msb-root-activity-monitoring-{self.region}",
            description="Monitors and alerts on root account activity",
            event_pattern=events.EventPattern(
                source=["aws.signin"],
                detail_type=["AWS Console Sign In via CloudTrail"],
                detail={
                    "userIdentity": {
                        "type": ["Root"]
                    }
                }
            )
        )
        root_activity_rule.add_target(targets.SnsTopic(
            self.notifications_topic,
            message=events.RuleTargetInput.from_text(
                "ALERT: AWS Root account was used to sign in to the console. " +
                "Root account usage should be minimized. " +
                "Event details: ${event.detail}"
            )
        ))

        # Root account API calls rule
        root_api_rule = events.Rule(self, "RootAPIActivityRule",
            rule_name=f"msb-root-api-activity-monitoring-{self.region}",
            description="Monitors and alerts on root account API activity",
            event_pattern=events.EventPattern(
                source=["aws.cloudtrail"],
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    "userIdentity": {
                        "type": ["Root"]
                    }
                }
            )
        )
        root_api_rule.add_target(targets.SnsTopic(
            self.notifications_topic,
            message=events.RuleTargetInput.from_text(
                "ALERT: AWS Root account was used to make API calls. " +
                "Root account usage should be minimized. " +
                "Event details: ${event.detail}"
            )
        ))