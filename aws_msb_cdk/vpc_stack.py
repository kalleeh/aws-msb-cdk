from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
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
        
        # Export outputs
        self.vpc = vpc
        self.bastion_sg = bastion_sg
        self.app_sg = app_sg