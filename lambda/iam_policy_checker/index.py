import boto3
import os
import json
import logging
from botocore.config import Config

logger = logging.getLogger()
logger.setLevel(logging.INFO)

config = Config(retries={'max_attempts': 3, 'mode': 'standard'})


def handler(event, context):
    iam = boto3.client('iam', config=config)
    sns = boto3.client('sns', config=config)
    topic_arn = os.environ.get('NOTIFICATION_TOPIC_ARN', '')

    try:
        # Get all users using pagination
        users = []
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            users.extend(page['Users'])

        logger.info(f"Found {len(users)} IAM users to check")

        users_with_policies = []

        for user in users:
            username = user['UserName']

            # Check for inline policies using pagination
            inline_policies = []
            inline_paginator = iam.get_paginator('list_user_policies')
            for page in inline_paginator.paginate(UserName=username):
                inline_policies.extend(page['PolicyNames'])

            # Check for attached policies using pagination
            attached_policies = []
            attached_paginator = iam.get_paginator('list_attached_user_policies')
            for page in attached_paginator.paginate(UserName=username):
                attached_policies.extend(page['AttachedPolicies'])

            if inline_policies or attached_policies:
                logger.info(f"User {username} has directly attached policies")
                users_with_policies.append({
                    'username': username,
                    'inline_policies': inline_policies,
                    'attached_policies': [p['PolicyName'] for p in attached_policies]
                })

        logger.info(f"Found {len(users_with_policies)} users with directly attached policies")

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
            logger.info(f"SNS notification sent to {topic_arn}")

        return {
            'statusCode': 200,
            'users_with_policies_count': len(users_with_policies)
        }

    except Exception as e:
        logger.error(f"Error checking IAM policies: {str(e)}")

        if topic_arn:
            try:
                sns.publish(
                    TopicArn=topic_arn,
                    Subject='IAM Policy Checker Error',
                    Message=f"An error occurred while checking IAM policies: {str(e)}"
                )
            except Exception as sns_error:
                logger.error(f"Failed to send error notification via SNS: {str(sns_error)}")

        raise
