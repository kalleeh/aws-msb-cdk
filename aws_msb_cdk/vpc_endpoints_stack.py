from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
    aws_iam as iam
)
from constructs import Construct

class VpcEndpointsStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, vpc=None, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        if not vpc:
            raise ValueError("VPC is required for VPC Endpoints Stack")

        # Create security group for VPC endpoints
        self.endpoint_security_group = ec2.SecurityGroup(self, "VpcEndpointSecurityGroup",
            vpc=vpc,
            description="Security group for VPC endpoints",
            allow_all_outbound=False
        )

        # Allow HTTPS from within the VPC
        self.endpoint_security_group.add_ingress_rule(
            ec2.Peer.ipv4(vpc.vpc_cidr_block),
            ec2.Port.tcp(443),
            "Allow HTTPS from within the VPC"
        )

        # Create VPC endpoints for commonly used services
        self.create_gateway_endpoints(vpc)
        self.create_interface_endpoints(vpc)

    def create_gateway_endpoints(self, vpc):
        """Create gateway endpoints for S3 and DynamoDB"""
        
        # S3 Gateway Endpoint
        self.s3_endpoint = ec2.GatewayVpcEndpoint(self, "S3Endpoint",
            vpc=vpc,
            service=ec2.GatewayVpcEndpointAwsService.S3,
            subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)]
        )

        # Add endpoint policy for S3
        self.s3_endpoint.add_to_policy(
            iam.PolicyStatement(
                principals=[iam.AnyPrincipal()],
                actions=[
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:ListBucket"
                ],
                resources=["*"],
                conditions={
                    "StringEquals": {
                        "aws:SourceVpc": vpc.vpc_id
                    }
                }
            )
        )

        # DynamoDB Gateway Endpoint
        self.dynamodb_endpoint = ec2.GatewayVpcEndpoint(self, "DynamoDBEndpoint",
            vpc=vpc,
            service=ec2.GatewayVpcEndpointAwsService.DYNAMODB,
            subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)]
        )

        # Add endpoint policy for DynamoDB
        self.dynamodb_endpoint.add_to_policy(
            iam.PolicyStatement(
                principals=[iam.AnyPrincipal()],
                actions=[
                    "dynamodb:GetItem",
                    "dynamodb:PutItem",
                    "dynamodb:Query",
                    "dynamodb:Scan"
                ],
                resources=["*"],
                conditions={
                    "StringEquals": {
                        "aws:SourceVpc": vpc.vpc_id
                    }
                }
            )
        )

    def create_interface_endpoints(self, vpc):
        """Create interface endpoints for various AWS services"""
        
        # List of services to create interface endpoints for
        interface_services = [
            "ssm",              # Systems Manager
            "ssmmessages",      # Systems Manager Messages
            "ec2messages",      # EC2 Messages
            "kms",              # Key Management Service
            "logs",             # CloudWatch Logs
            "monitoring",       # CloudWatch Monitoring
            "sqs",              # Simple Queue Service
            "sns",              # Simple Notification Service
            "secretsmanager",   # Secrets Manager
            "ecr.api",          # ECR API
            "ecr.dkr",          # ECR Docker Registry
            "ecs",              # ECS
            "lambda"            # Lambda
        ]

        # Create interface endpoints for each service
        self.interface_endpoints = {}
        for service in interface_services:
            endpoint_name = f"{service.replace('.', '')}Endpoint"
            
            self.interface_endpoints[service] = ec2.InterfaceVpcEndpoint(
                self, endpoint_name,
                vpc=vpc,
                service=ec2.InterfaceVpcEndpointAwsService(service),
                private_dns_enabled=True,
                security_groups=[self.endpoint_security_group],
                subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
            )