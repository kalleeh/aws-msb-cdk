# Programmatic Security Controls for Residual Risk

This document outlines programmatic security controls that can be added to the AWS MSB CDK templates to address residual risk without requiring significant operational practices or adding many new AWS services.

## Implementable Controls

The following controls can be added to the MSB CDK implementation with minimal changes:

### 1. EBS Volume Encryption by Default (CIS 2.2.1)

**Risk Level**: Medium

**Implementation**: Add a custom resource to enable EBS encryption by default for the account.

```python
# Add to KMSStack or create a new EncryptionStack
from aws_cdk import custom_resources as cr

# Custom resource to enable EBS encryption by default
enable_ebs_encryption = cr.AwsCustomResource(self, "EnableEBSEncryptionByDefault",
    on_create=cr.AwsSdkCall(
        service="EC2",
        action="enableEbsEncryptionByDefault",
        parameters={},
        physical_resource_id=cr.PhysicalResourceId.of("enable-ebs-encryption-by-default")
    ),
    policy=cr.AwsCustomResourcePolicy.from_statements([
        iam.PolicyStatement(
            actions=["ec2:EnableEbsEncryptionByDefault"],
            resources=["*"]
        )
    ])
)
```

**Benefits**:
- Ensures all new EBS volumes are encrypted by default
- Addresses CIS AWS Foundations Benchmark v3.0.0 control 2.2.1
- No operational overhead once implemented

### 2. S3 Bucket Default Encryption (CIS 2.1.1)

**Risk Level**: Low

**Implementation**: Add a custom resource to set default encryption for S3 buckets.

```python
# Add to S3SecurityStack
bucket_default_encryption = cr.AwsCustomResource(self, "S3DefaultEncryption",
    on_create=cr.AwsSdkCall(
        service="S3Control",
        action="putPublicAccessBlock",
        parameters={
            "AccountId": cdk.Aws.ACCOUNT_ID,
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "BlockPublicPolicy": True,
                "IgnorePublicAcls": True,
                "RestrictPublicBuckets": True
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
```

**Benefits**:
- Ensures all new S3 buckets have encryption enabled by default
- Addresses CIS AWS Foundations Benchmark v3.0.0 control 2.1.1
- No operational overhead once implemented

### 3. IAM Access Key Rotation Monitoring (CIS 1.14)

**Risk Level**: Medium

**Implementation**: Add a Lambda function and EventBridge rule to monitor and alert on old IAM access keys.

```python
# Add to IAMStack
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as targets

# Lambda function to check for old access keys
access_key_checker = lambda_.Function(self, "AccessKeyChecker",
    runtime=lambda_.Runtime.PYTHON_3_9,
    handler="index.handler",
    code=lambda_.Code.from_asset("lambda/access_key_checker"),
    environment={
        "MAX_KEY_AGE_DAYS": "90",
        "NOTIFICATION_TOPIC_ARN": notifications_topic.topic_arn if notifications_topic else ""
    },
    timeout=Duration.seconds(60)
)

access_key_checker.add_to_role_policy(
    iam.PolicyStatement(
        actions=[
            "iam:ListUsers",
            "iam:ListAccessKeys",
            "iam:GetAccessKeyLastUsed"
        ],
        resources=["*"]
    )
)

if notifications_topic:
    access_key_checker.add_to_role_policy(
        iam.PolicyStatement(
            actions=["sns:Publish"],
            resources=[notifications_topic.topic_arn]
        )
    )

# Schedule the Lambda to run daily
events.Rule(self, "AccessKeyCheckerSchedule",
    schedule=events.Schedule.rate(Duration.days(1)),
    targets=[targets.LambdaFunction(access_key_checker)]
)
```

**Lambda Code (lambda/access_key_checker/index.py)**:
```python
import boto3
import os
import datetime
import json

def handler(event, context):
    iam = boto3.client('iam')
    sns = boto3.client('sns')
    max_age_days = int(os.environ.get('MAX_KEY_AGE_DAYS', 90))
    topic_arn = os.environ.get('NOTIFICATION_TOPIC_ARN', '')
    
    users = iam.list_users()['Users']
    old_keys = []
    
    for user in users:
        username = user['UserName']
        keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
        
        for key in keys:
            key_id = key['AccessKeyId']
            create_date = key['CreateDate']
            status = key['Status']
            
            # Calculate key age
            key_age = (datetime.datetime.now(datetime.timezone.utc) - create_date).days
            
            if key_age > max_age_days and status == 'Active':
                old_keys.append({
                    'username': username,
                    'key_id': key_id,
                    'age_days': key_age
                })
    
    if old_keys and topic_arn:
        message = {
            'subject': 'IAM Access Keys Rotation Required',
            'message': f'The following IAM access keys are older than {max_age_days} days and should be rotated:',
            'keys': old_keys
        }
        
        sns.publish(
            TopicArn=topic_arn,
            Subject=message['subject'],
            Message=json.dumps(message, indent=2)
        )
    
    return {
        'statusCode': 200,
        'old_keys_count': len(old_keys)
    }
```

**Benefits**:
- Monitors IAM access keys for rotation compliance
- Sends notifications for keys that need rotation
- Addresses CIS AWS Foundations Benchmark v3.0.0 control 1.14
- No manual monitoring required

### 4. Default Security Group Monitoring (CIS 5.4)

**Risk Level**: Low

**Implementation**: Add a Lambda function to continuously monitor and lock down default security groups.

```python
# Add to NetworkSecurityStack
secure_default_sg_function = lambda_.Function(self, "SecureDefaultSGFunction",
    runtime=lambda_.Runtime.PYTHON_3_9,
    handler="index.handler",
    code=lambda_.Code.from_asset("lambda/secure_default_sg"),
    timeout=Duration.seconds(60),
    environment={
        "NOTIFICATION_TOPIC_ARN": notifications_topic.topic_arn if notifications_topic else ""
    }
)

secure_default_sg_function.add_to_role_policy(
    iam.PolicyStatement(
        actions=[
            "ec2:DescribeSecurityGroups",
            "ec2:RevokeSecurityGroupIngress",
            "ec2:RevokeSecurityGroupEgress",
            "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
            "ec2:UpdateSecurityGroupRuleDescriptionsEgress"
        ],
        resources=["*"]
    )
)

if notifications_topic:
    secure_default_sg_function.add_to_role_policy(
        iam.PolicyStatement(
            actions=["sns:Publish"],
            resources=[notifications_topic.topic_arn]
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
```

**Lambda Code (lambda/secure_default_sg/index.py)**:
```python
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
```

**Benefits**:
- Continuously monitors and secures default security groups
- Automatically remediates non-compliant security groups
- Addresses CIS AWS Foundations Benchmark v3.0.0 control 5.4
- Provides notifications when remediation occurs

### 5. Root Account Activity Monitoring (CIS 1.7, IAM.7)

**Risk Level**: Medium

**Implementation**: Add EventBridge rules to monitor and alert on root account usage.

```python
# Add to SecurityMonitoringStack
root_activity_rule = events.Rule(self, "RootActivityMonitoringRule",
    rule_name="msb-root-activity-monitoring",
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

if notifications_topic:
    root_activity_rule.add_target(targets.SnsTopic(
        notifications_topic,
        message=events.RuleTargetInput.from_text(
            "ALERT: AWS Root account was used to sign in to the console. " +
            "Root account usage should be minimized. " +
            "Event details: " +
            events.RuleTargetInput.from_event("$.detail").to_string()
        )
    ))

# Also monitor root account API calls
root_api_rule = events.Rule(self, "RootAPIActivityRule",
    rule_name="msb-root-api-activity-monitoring",
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

if notifications_topic:
    root_api_rule.add_target(targets.SnsTopic(
        notifications_topic,
        message=events.RuleTargetInput.from_text(
            "ALERT: AWS Root account was used to make API calls. " +
            "Root account usage should be minimized. " +
            "Event details: " +
            events.RuleTargetInput.from_event("$.detail").to_string()
        )
    ))
```

**Benefits**:
- Provides real-time monitoring of root account usage
- Sends immediate alerts when root account is used
- Addresses CIS AWS Foundations Benchmark v3.0.0 control 1.7 and FSBP IAM.7
- No operational overhead once implemented

### 6. S3 Bucket-Level Public Access Blocks (CIS 2.1.5)

**Risk Level**: Low

**Implementation**: Add a Lambda function to monitor and enforce bucket-level public access blocks.

```python
# Add to S3SecurityStack
s3_bucket_public_access_checker = lambda_.Function(self, "S3BucketPublicAccessChecker",
    runtime=lambda_.Runtime.PYTHON_3_9,
    handler="index.handler",
    code=lambda_.Code.from_asset("lambda/s3_public_access_checker"),
    timeout=Duration.seconds(300),
    environment={
        "NOTIFICATION_TOPIC_ARN": notifications_topic.topic_arn if notifications_topic else ""
    }
)

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

if notifications_topic:
    s3_bucket_public_access_checker.add_to_role_policy(
        iam.PolicyStatement(
            actions=["sns:Publish"],
            resources=[notifications_topic.topic_arn]
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
```

**Lambda Code (lambda/s3_public_access_checker/index.py)**:
```python
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
```

**Benefits**:
- Ensures all S3 buckets have public access blocks enabled
- Automatically remediates non-compliant buckets
- Addresses CIS AWS Foundations Benchmark v3.0.0 control 2.1.5
- Provides notifications on enforcement actions

### 7. IAM Policy Governance (IAM.16)

**Risk Level**: Low

**Implementation**: Add a Lambda function to monitor and report on IAM policies attached directly to users.

```python
# Add to IAMStack
iam_policy_checker = lambda_.Function(self, "IAMPolicyChecker",
    runtime=lambda_.Runtime.PYTHON_3_9,
    handler="index.handler",
    code=lambda_.Code.from_asset("lambda/iam_policy_checker"),
    timeout=Duration.seconds(60),
    environment={
        "NOTIFICATION_TOPIC_ARN": notifications_topic.topic_arn if notifications_topic else ""
    }
)

iam_policy_checker.add_to_role_policy(
    iam.PolicyStatement(
        actions=[
            "iam:ListUsers",
            "iam:ListUserPolicies",
            "iam:ListAttachedUserPolicies"
        ],
        resources=["*"]
    )
)

if notifications_topic:
    iam_policy_checker.add_to_role_policy(
        iam.PolicyStatement(
            actions=["sns:Publish"],
            resources=[notifications_topic.topic_arn]
        )
    )

# Schedule the Lambda to run daily
events.Rule(self, "IAMPolicyCheckerSchedule",
    schedule=events.Schedule.rate(Duration.days(1)),
    targets=[targets.LambdaFunction(iam_policy_checker)]
)

# Also trigger on policy attachment events
policy_attachment_rule = events.Rule(self, "IAMPolicyAttachmentRule",
    event_pattern=events.EventPattern(
        source=["aws.iam"],
        detail_type=["AWS API Call via CloudTrail"],
        detail={
            "eventSource": ["iam.amazonaws.com"],
            "eventName": [
                "AttachUserPolicy",
                "PutUserPolicy"
            ]
        }
    ),
    targets=[targets.LambdaFunction(iam_policy_checker)]
)
```

**Lambda Code (lambda/iam_policy_checker/index.py)**:
```python
import boto3
import os
import json

def handler(event, context):
    iam = boto3.client('iam')
    sns = boto3.client('sns')
    topic_arn = os.environ.get('NOTIFICATION_TOPIC_ARN', '')
    
    # Get all users
    users = iam.list_users()['Users']
    
    users_with_policies = []
    
    for user in users:
        username = user['UserName']
        
        # Check for inline policies
        inline_policies = iam.list_user_policies(UserName=username)['PolicyNames']
        
        # Check for attached policies
        attached_policies = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
        
        if inline_policies or attached_policies:
            users_with_policies.append({
                'username': username,
                'inline_policies': inline_policies,
                'attached_policies': [p['PolicyName'] for p in attached_policies]
            })
    
    # Send notification if any users have directly attached policies
    if users_with_policies and topic_arn:
        message = {
            'subject': 'IAM Users with Directly Attached Policies',
            'message': 'The following IAM users have policies attached directly to them instead of through groups:',
            'users': users_with_policies,
            'recommendation': 'Consider moving these policies to groups and adding users to the appropriate groups instead.'
        }
        
        sns.publish(
            TopicArn=topic_arn,
            Subject=message['subject'],
            Message=json.dumps(message, indent=2)
        )
    
    return {
        'statusCode': 200,
        'users_with_policies_count': len(users_with_policies)
    }
```

**Benefits**:
- Identifies IAM users with directly attached policies
- Provides recommendations for better IAM governance
- Addresses FSBP IAM.16
- No operational overhead once implemented

## Implementation Strategy

To implement these controls in the MSB CDK project:

1. **Create Lambda Function Code**:
   - Create the necessary Lambda function code in a `lambda` directory within the project
   - Organize functions by security domain (IAM, S3, EC2, etc.)

2. **Update Existing Stacks**:
   - Add the new controls to the appropriate existing stacks
   - Ensure proper dependencies between resources

3. **Testing**:
   - Add unit tests for the new controls
   - Test the Lambda functions with sample events

4. **Documentation**:
   - Update the compliance matrix to reflect the newly addressed controls
   - Document the new controls in the control implementation details

## Conclusion

These programmatic controls can significantly reduce the residual risk in the AWS MSB CDK implementation without requiring extensive operational practices or adding many new AWS services. By focusing on automated monitoring, alerting, and remediation, these controls provide continuous security enforcement with minimal human intervention.