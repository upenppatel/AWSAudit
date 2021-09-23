import boto3
import os

# File to be saved with audit records
#FILE_ROOT = "c:\\repos\\Python\\audits.log"
FILE_ROOT = "/Users/upen/.aws/audit.log"
ec2 = boto3.client('ec2', 'us-east-1')
response = ec2.describe_regions()
region_list = []
with open(FILE_ROOT, mode='w') as iam_audit:
    pass
iam_audit.close()
for region in response['Regions']:
    region_list.append(region['RegionName'])
with open(FILE_ROOT, mode='a+') as vpcs_audit:
    for region in region_list:
        ec2 = boto3.client('ec2', region)
        region_security_groups = ec2.describe_security_groups()
        vpcs = ec2.describe_vpcs()
        subnets = ec2.describe_subnets()
        endpoints = ec2.describe_vpc_endpoints()
        vpn_peer_connections = ec2.describe_vpc_peering_connections()
        vpn_connections = ec2.describe_vpn_connections()
        vpn_gateways = ec2.describe_vpn_gateways()
        internet_gateways = ec2.describe_internet_gateways()
        nat_gateways = ec2.describe_nat_gateways()
        network_acls = ec2.describe_network_acls()
        route_tables = ec2.describe_route_tables()
        print("\t" * 6 + "Region:" + region + "\n" * 3)
        print("VPCs and Security Groups List:")
        vpcs_audit.write("\t" * 6 + "Region:" + region + "\nVPCs and Security Groups List:\n")
        vpcs_audit.write("\t" * 4 + "-" * 50 + "VPCs List" + "-" * 50 + "\n")
        if vpcs['Vpcs']:
            for response in vpcs['Vpcs']:
                print(response)
                vpcs_audit.write(str(response) + "\n")
        else:
            print("No VPC Found in Region:" + region)
            vpcs_audit.write("No VPC Found in Region:" + region + "\n")

        vpcs_audit.write("\t" * 4 + "-" * 50 + "Subnets List" + "-" * 50 + "\n")
        if subnets['Subnets']:
            for response in subnets['Subnets']:
                print(response)
                vpcs_audit.write(str(response) + "\n")
        else:
            print("No Subnet found in Region:" + region)
            vpcs_audit.write("No Subnet found Region:" + region + "\n")

        vpcs_audit.write("\t" * 4 + "-" * 50 + "VpcEndpoints List" + "-" * 50 + "\n")
        if endpoints['VpcEndpoints']:
            for response in endpoints['VpcEndpoints']:
                print(response)
                vpcs_audit.write(str(response) + "\n")
        else:
            print("No VPC Endpoint Found in Region:" + region)
            vpcs_audit.write("No VPC Endpoint Found in Region:" + region + "\n")

        vpcs_audit.write("\t" * 4 + "-" * 50 + "VPC Peering Connections List" + "-" * 50 + "\n")
        if vpn_peer_connections['VpcPeeringConnections']:
            for response in vpn_peer_connections['VpcPeeringConnections']:
                print(response)
                vpcs_audit.write(str(response) + "\n")
        else:
            print("No VPC Peering Connection Found in Region:" + region)
            vpcs_audit.write("No VPC Peering Connection Found in Region:" + region + "\n")

        vpcs_audit.write("\t" * 4 + "-" * 50 + "VPN Connections List" + "-" * 50 + "\n")
        if vpn_connections['VpnConnections']:
            for response in vpn_connections['VpnConnections']:
                print(response)
                vpcs_audit.write(str(response) + "\n")
        else:
            print("No VPN Connection Found in Region:" + region)
            vpcs_audit.write("No VPN Connection Found in Region:" + region + "\n")

        vpcs_audit.write("\t" * 4 + "-" * 50 + "VPN Gateways List" + "-" * 50 + "\n")
        if vpn_gateways['VpnGateways']:
            for response in vpn_gateways['VpnGateways']:
                print(response)
                vpcs_audit.write(str(response) + "\n")
        else:
            print("No VPN gateways found in Region:" + region)
            vpcs_audit.write("No VPN gateways found in Region:" + region + "\n")

        vpcs_audit.write("\t" * 4 + "-" * 50 + "Internet Gateways List" + "-" * 50 + "\n")
        if internet_gateways['InternetGateways']:
            for response in internet_gateways['InternetGateways']:
                print(response)
                vpcs_audit.write(str(response) + "\n")
        else:
            print("No Internet Gateway Found in Region:" + region)
            vpcs_audit.write("No Internet Gateway Found in Region:" + region + "\n")

        vpcs_audit.write("\t" * 4 + "-" * 50 + "NAT Gateways List" + "-" * 50 + "\n")
        if nat_gateways['NatGateways']:
            for response in nat_gateways['NatGateways']:
                print(response)
                vpcs_audit.write(str(response) + "\n")
        else:
            print("No NAT Gateway Found in Region:" + region)
            vpcs_audit.write("No NAT Gateway Found in Region:" + region +"\n")

        vpcs_audit.write("\t" * 4 + "-" * 50 + "Network ACLs List" + "-" * 50 + "\n")
        if network_acls['NetworkAcls']:
            for response in network_acls['NetworkAcls']:
                print(response)
                vpcs_audit.write(str(response) + "\n")
        else:
            print("No NetworkAcls Found in Region:" + region)
            vpcs_audit.write("No NetworkAcls Found in Region:" + region +"\n")

        vpcs_audit.write("\t" * 4 + "-" * 50 + "Route Tables List" + "-" * 50 + "\n")
        for response in route_tables['RouteTables']:
            print(response)
            vpcs_audit.write(str(response) + "\n")

        vpcs_audit.write("\t" * 4 + "-" * 50 + "Security Groups List" + "-" * 50 + "\n")
        if region_security_groups['SecurityGroups']:
            for response in region_security_groups['SecurityGroups']:
                print(response)
                vpcs_audit.write(str(response) + "\n")
        else:
            print("No Security Group Found.")
            vpcs_audit.write("No Security Group Found.\n")

vpcs_audit.close()

iam = boto3.client('iam', 'us-east-1')
users = iam.list_users()
groups = iam.list_groups()
roles = iam.list_roles()
policies = iam.list_policies()
pw_policies = iam.get_account_password_policy()


with open(FILE_ROOT, mode='a+') as iam_audit:
    iam_audit.write("\t" * 4 + "-" * 50 + "IAM User List" + "-" * 50 + "\n")
    print("IAM Users List:")
    iam_audit.write("IAM Users List:\n")
    if users['Users']:
        for response in users['Users']:
            print(response)
            iam_audit.write(str(response) + "\n")
    else:
        print("No IAM User Found.")
        iam_audit.write("No IAM User Found.\n")

    iam_audit.write("\t" * 4 + "-" * 50 + "IAM Group List" + "-" * 50 + "\n")
    print("IAM Groups List:")
    iam_audit.write("IAM Groups List:\n")
    if groups['Groups']:
        for response in groups['Groups']:
            print(response)
            iam_audit.write(str(response) + "\n")
    else:
        print("No IAM Group Found.")
        iam_audit.write("No IAM Group Found.\n")

    iam_audit.write("\t" * 4 + "-" * 50 + "IAM Roles List" + "-" * 50 + "\n")
    print("IAM Roles List:")
    iam_audit.write("IAM Roles List:\n")
    if roles['Roles']:
        for response in roles['Roles']:
            print(response)
            iam_audit.write(str(response) + "\n")
    else:
        print("No IAM Role Found.")
        iam_audit.write("No IAM Role Found.\n")

    iam_audit.write("\t" * 4 + "-" * 50 + "IAM Policies List" + "-" * 50 + "\n")
    print("IAM Policies List:")
    iam_audit.write("IAM Policies List:\n")
    if policies['Policies']:
        for response in policies['Policies']:
            print(response)
            iam_audit.write(str(response) + "\n")
    else:
        print("No IAM Policy Found.")
        iam_audit.write("No IAM Policy Found.\n")


    iam_audit.write("\t" * 4 + "-" * 50 + "IAM Password Policy List" + "-" * 50 + "\n")
    print("IAM Password Policies List:")
    iam_audit.write("IAM Password Policies List:\n")
    if pw_policies['Policies']:
        for response in policies['Policies']:
            print(response)
            iam_audit.write(str(response) + "\n")
    else:
        print("No IAM Password Policy Found.")
        iam_audit.write("No IAM Policy Found.\n")

    iam_audit.write("\t" * 4 + "-" * 50 + "Account Password Policy " + "-" * 50 + "\n")
    print("Account Password Policy List:")
    iam_audit.write("\t" * 4 + "-" * 50 + "Account Password Policy " + "-" * 50 + "\n")
    print("Account Password Policy List:")
    iam_audit.write("Account Password Policy List:\n")
    response = iam.get_account_password_policy()
    iam_audit.write(str(response) + "\n")

    iam_audit.write("\t" * 4 + "-" * 50 + "AWS Generate Credential Report  " + "-" * 50 + "\n")
    response = iam.generate_credential_report()
    print(response)

    iam_audit.write("\t" * 4 + "-" * 50 + "AWS Credential Report  " + "-" * 50 + "\n")
    response = iam.get_credential_report()
    print(response)


iam_audit.close()
