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