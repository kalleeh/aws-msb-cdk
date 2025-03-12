# Implemented Security Controls

This document lists the security controls that have been implemented in the MSB CDK project, along with their implementation details and test coverage.

## SNS.1 - SNS Topic Encryption

**Framework Reference**: FSBP, DAT.8

**Implementation**:
- SNS topics are encrypted using KMS keys
- Implemented in the `LoggingStack` class
- Uses the master KMS key from the KMS stack for encryption
- All notifications are sent through the encrypted SNS topic

**Test Coverage**:
- Tests verify that SNS topics are created with KMS encryption
- Tests verify that the correct KMS key is used for encryption
- Tests verify that email subscriptions are properly configured

## EC2.15 - VPC Endpoint Security

**Framework Reference**: FSBP, NET.6

**Implementation**:
- VPC endpoints are implemented in the `VpcStack` class
- Gateway endpoints for S3 and DynamoDB with restrictive policies
- Interface endpoints for 13+ AWS services with private DNS enabled
- Security group restricts access to endpoints from within the VPC only
- Endpoint policies enforce least privilege access

**Test Coverage**:
- Tests verify that gateway endpoints are created for S3 and DynamoDB
- Tests verify that interface endpoints are created for required services
- Tests verify that endpoint policies enforce least privilege
- Tests verify that security groups restrict access appropriately

## CloudWatch.2 - Unauthorized API Calls Monitoring

**Framework Reference**: FSBP, CIS 4.1

**Implementation**:
- Implemented in the `LoggingStack` class
- Creates a CloudWatch metric filter for unauthorized API calls
- Creates a CloudWatch alarm that triggers when unauthorized calls are detected
- Sends notifications to the SNS topic when the alarm triggers

**Test Coverage**:
- Tests verify that the metric filter is created with the correct pattern
- Tests verify that the alarm is configured with the correct threshold
- Tests verify that the alarm is connected to the SNS topic

## CIS 5.4 - Default Security Group Restrictions

**Framework Reference**: CIS 3.0.0

**Implementation**:
- Implemented in the `NetworkSecurityStack` class
- Lambda function that secures default security groups
- Removes all ingress and egress rules from default security groups
- Runs on a schedule and when security group changes are detected
- Sends notifications when default security groups are modified

**Test Coverage**:
- Tests verify that the Lambda function is created with the correct code
- Tests verify that the function has the necessary permissions
- Tests verify that the function is triggered on schedule and by events

## IAM.7 - Root Account Usage Monitoring

**Framework Reference**: FSBP, CIS 1.7

**Implementation**:
- Implemented in the `SecurityMonitoringStack` class
- EventBridge rules detect root account sign-in and API activity
- Sends immediate notifications when root account is used
- Provides details about the activity in the notification

**Test Coverage**:
- Tests verify that EventBridge rules are created with the correct patterns
- Tests verify that rules target the SNS topic for notifications
- Tests verify that notification messages include the necessary details