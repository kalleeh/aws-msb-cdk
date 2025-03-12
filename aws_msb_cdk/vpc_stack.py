from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
    aws_iam as iam,
    CfnParameter,
)
from constructs import Construct

class VpcStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, flow_logs_destination=None, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Parameters
        vpc_cidr = CfnParameter(self, "VpcCIDR",
            type="String",
            description="CIDR block for the VPC",
            default="10.0.0.0/16"
        )

        availability_zones = CfnParameter(self, "AvailabilityZones",
            type="Number",
            description="Number of Availability Zones to use",
            default="2",
            min_value=1,
            max_value=3
        )

        deploy_single_natgw = CfnParameter(self, "DeploySingleNATGW",
            type="String",
            description="If true, deploys a single NAT Gateway in the first AZ to save costs",
            default="true",
            allowed_values=["true", "false"]
        )

        # VPC using L2 construct
        vpc = ec2.Vpc(self, "MSB-VPC",
            vpc_name=f"msb-vpc-{self.region}",
            cidr="10.0.0.0/16",  # Using a concrete CIDR instead of a parameter
            max_azs=availability_zones.value_as_number,
            nat_gateways=1 if deploy_single_natgw.value_as_string == "true" else availability_zones.value_as_number,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="Public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24
                ),
                ec2.SubnetConfiguration(
                    name="Private",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=24
                ),
                ec2.SubnetConfiguration(
                    name="Isolated",
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                    cidr_mask=24
                )
            ]
        )
        
        # Security Group for bastion hosts
        bastion_sg = ec2.SecurityGroup(self, "BastionSecurityGroup",
            vpc=vpc,
            description="Security group for bastion hosts",
            security_group_name="msb-bastion-sg",
            allow_all_outbound=False
        )
        
        # Only allow SSH from trusted IPs (this should be customized)
        bastion_sg.add_ingress_rule(
            ec2.Peer.ipv4("10.0.0.0/8"),
            ec2.Port.tcp(22),
            "Allow SSH from internal networks only"
        )
        
        # Allow HTTPS outbound
        bastion_sg.add_egress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(443),
            "Allow HTTPS outbound"
        )
        
        # Security Group for application servers
        app_sg = ec2.SecurityGroup(self, "ApplicationSecurityGroup",
            vpc=vpc,
            description="Security group for application servers",
            security_group_name="msb-application-sg",
            allow_all_outbound=False
        )
        
        # Allow SSH from bastion only
        app_sg.add_ingress_rule(
            ec2.Peer.security_group_id(bastion_sg.security_group_id),
            ec2.Port.tcp(22),
            "Allow SSH from bastion hosts only"
        )
        
        # Allow web traffic
        app_sg.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(443),
            "Allow HTTPS inbound"
        )
        
        # Allow outbound to specific services
        app_sg.add_egress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(443),
            "Allow HTTPS outbound"
        )
        
        # Add VPC Flow Logs if destination is provided
        if flow_logs_destination:
            ec2.FlowLog(self, "VPCFlowLog",
                resource_type=ec2.FlowLogResourceType.from_vpc(vpc),
                destination=flow_logs_destination,
                traffic_type=ec2.FlowLogTrafficType.ALL
            )
        
        # Create VPC endpoints for commonly used services
        self.create_vpc_endpoints(vpc)
        
        # Export outputs
        self.vpc = vpc
        self.bastion_sg = bastion_sg
        self.app_sg = app_sg
    
    def create_vpc_endpoints(self, vpc):
        """Create VPC endpoints for commonly used services (EC2.15)"""
        
        # Create security group for VPC endpoints
        endpoint_security_group = ec2.SecurityGroup(self, "VpcEndpointSecurityGroup",
            vpc=vpc,
            description="Security group for VPC endpoints",
            allow_all_outbound=False
        )

        # Allow HTTPS from within the VPC
        endpoint_security_group.add_ingress_rule(
            ec2.Peer.ipv4(vpc.vpc_cidr_block),
            ec2.Port.tcp(443),
            "Allow HTTPS from within the VPC"
        )
        
        # Create gateway endpoints for S3 and DynamoDB
        s3_endpoint = ec2.GatewayVpcEndpoint(self, "S3Endpoint",
            vpc=vpc,
            service=ec2.GatewayVpcEndpointAwsService.S3,
            subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)]
        )

        # Add endpoint policy for S3
        s3_endpoint.add_to_policy(
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
        dynamodb_endpoint = ec2.GatewayVpcEndpoint(self, "DynamoDBEndpoint",
            vpc=vpc,
            service=ec2.GatewayVpcEndpointAwsService.DYNAMODB,
            subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)]
        )

        # Add endpoint policy for DynamoDB
        dynamodb_endpoint.add_to_policy(
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
                security_groups=[endpoint_security_group],
                subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
            )