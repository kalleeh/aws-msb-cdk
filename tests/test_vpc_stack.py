import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template, Match
from aws_msb_cdk.vpc_stack import VpcStack

class TestVpcStack:
    @pytest.fixture
    def app(self):
        return cdk.App()
    
    @pytest.fixture
    def vpc_stack(self, app):
        class MockVpcStack(VpcStack):
            def create_vpc_endpoints(self, vpc):
                # Override to avoid subnet issues in testing
                pass
        
        return MockVpcStack(app, "TestVpcStack")
    
    @pytest.fixture
    def template(self, vpc_stack):
        return Template.from_stack(vpc_stack)
    
    def test_vpc_created(self, template):
        # Verify VPC is created
        template.resource_count_is("AWS::EC2::VPC", 1)
        
        # Verify VPC properties
        template.has_resource_properties("AWS::EC2::VPC", {
            "CidrBlock": "10.0.0.0/16",
            "EnableDnsHostnames": True,
            "EnableDnsSupport": True
        })
    
    def test_vpc_subnets_created(self, template):
        # Verify subnets are created (6 subnets: 2 AZs x 3 subnet types)
        template.resource_count_is("AWS::EC2::Subnet", 6)
        
        # Verify public subnets
        public_subnets = template.find_resources("AWS::EC2::Subnet", {
            "Properties": {
                "MapPublicIpOnLaunch": True
            }
        })
        assert len(public_subnets) == 2
        
        # Verify route tables (at least 3)
        route_tables = template.find_resources("AWS::EC2::RouteTable")
        assert len(route_tables) >= 3
    
    def test_nat_gateway_created(self, template):
        # Verify NAT Gateway is created (only 1 as per configuration)
        template.resource_count_is("AWS::EC2::NatGateway", 1)
        
        # Verify Elastic IP for NAT Gateway
        template.resource_count_is("AWS::EC2::EIP", 1)
    
    def test_security_groups_created(self, template):
        # Verify security groups are created
        template.resource_count_is("AWS::EC2::SecurityGroup", 2)  # Bastion and App SGs
        
        # Verify bastion security group
        template.has_resource_properties("AWS::EC2::SecurityGroup", {
            "GroupDescription": "Security group for bastion hosts",
            "GroupName": "msb-bastion-sg"
        })
        
        # Verify application security group
        template.has_resource_properties("AWS::EC2::SecurityGroup", {
            "GroupDescription": "Security group for application servers",
            "GroupName": "msb-application-sg"
        })
    
    def test_security_group_rules(self, template):
        # Find the bastion security group
        bastion_sgs = template.find_resources("AWS::EC2::SecurityGroup", {
            "Properties": {
                "GroupName": "msb-bastion-sg"
            }
        })
        
        # Get the logical ID of the bastion security group
        bastion_sg_id = list(bastion_sgs.keys())[0]
        bastion_sg = bastion_sgs[bastion_sg_id]
        
        # Verify bastion security group ingress rules
        ingress_rules = bastion_sg["Properties"].get("SecurityGroupIngress", [])
        assert len(ingress_rules) > 0
        
        # Check for SSH ingress rule
        ssh_rule = next((rule for rule in ingress_rules if rule.get("FromPort") == 22), None)
        assert ssh_rule is not None
        assert ssh_rule.get("CidrIp") == "10.0.0.0/8"
        
        # Verify bastion security group egress rules
        egress_rules = bastion_sg["Properties"].get("SecurityGroupEgress", [])
        assert len(egress_rules) > 0
        
        # Check for HTTPS egress rule
        https_rule = next((rule for rule in egress_rules if rule.get("FromPort") == 443), None)
        assert https_rule is not None
        assert https_rule.get("CidrIp") == "0.0.0.0/0"
        
        # Find the application security group
        app_sgs = template.find_resources("AWS::EC2::SecurityGroup", {
            "Properties": {
                "GroupName": "msb-application-sg"
            }
        })
        
        # Get the logical ID of the application security group
        app_sg_id = list(app_sgs.keys())[0]
        app_sg = app_sgs[app_sg_id]
        
        # Verify application security group ingress rules
        ingress_rules = app_sg["Properties"].get("SecurityGroupIngress", [])
        assert len(ingress_rules) > 0
        
        # Check for HTTPS ingress rule
        https_rule = next((rule for rule in ingress_rules if rule.get("FromPort") == 443), None)
        assert https_rule is not None
        assert https_rule.get("CidrIp") == "0.0.0.0/0"
    
    def test_no_flow_logs_without_destination(self, template):
        # Verify no Flow Logs are created when destination is not provided
        flow_logs = template.find_resources("AWS::EC2::FlowLog")
        assert len(flow_logs) == 0