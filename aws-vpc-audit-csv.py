import sys
import os
import time
import datetime
import boto3
import csv

def unpack(a):
    if type(a)==type(list()) and len(a)!=0:
        return a[0]
    res={}
    for key,val in a.items():
        if type(val)==type(list()):
            if len(val)!=0:
                res[key]=val[0]
            else:
                res[key]=""
            continue
        if type(val)==type(dict()):
            for key1,val1 in val.items():
                res.update({str(key)+'_'+str(key1):val1})
        else:
            res.update({key:val})
    return res

def is_flat(a):
    if type(a)==type(list()):
        return False
    for key,val in a.items():
        if type(val)==type(dict()) or type(val)==type(list()):
            return False
    return True


#def lambda_handler(event, context):
    today = datetime.date.today()    
    # File to be saved with audit records
    FILE_ROOT = "/tmp/audits.csv"
    ec2 = boto3.client('ec2', 'us-east-1')
    response = ec2.describe_regions()

    region_list = []
    for region in response['Regions']:
        region_list.append(region['RegionName'])

    with open(FILE_ROOT,'w') as vpcs_audit:
        for region in region_list:
            ec2 = boto3.client('ec2', region)
            vpcs_audit.write("Region,"+str(region) + "\n")

            data = {'VPCs':                         ec2.describe_vpcs()['Vpcs'],
                    'Subnets':                      ec2.describe_subnets()['Subnets'],
                    'Endpoints':                    ec2.describe_vpc_endpoints()['VpcEndpoints'],
                    'VPC Peering Connections':      ec2.describe_vpc_peering_connections()['VpcPeeringConnections'],
                    'VPN Connections':              ec2.describe_vpn_connections()['VpnConnections'],
                    'VPN Gateways':                 ec2.describe_vpn_gateways()['VpnGateways'],
                    'Internet Gateways':            ec2.describe_internet_gateways()['InternetGateways'],
                    'NAT Gateways':                 ec2.describe_nat_gateways()['NatGateways'],
                    'Network ACLs':                 ec2.describe_network_acls()['NetworkAcls'],
                    'Route Tables':                 ec2.describe_route_tables()['RouteTables'],
                    'Security Groups ':             ec2.describe_security_groups()['SecurityGroups'],
                    }

            for key,val in data.items():
                if val:
                    vpcs_audit.write(f"{key} List\n")
                    fieldnames = val[0]
                    while not is_flat(fieldnames):
                        fieldnames=unpack(fieldnames)
                    writer = csv.DictWriter(vpcs_audit,fieldnames=fieldnames.keys())
                    writer.writeheader()        
                    for response in val:
                        while not is_flat(response):
                            response=unpack(response)
                        try:
                            writer.writerow(response)
                        except Exception as e:
                            e_response = response
                            e_fieldnames = e_response
                            while not is_flat(e_fieldnames):
                                e_fieldnames=unpack(e_fieldnames)
                            e_writer = csv.DictWriter(vpcs_audit,fieldnames=e_fieldnames.keys())
                            e_writer.writeheader()
                            while not is_flat(e_response):
                                e_response=unpack(e_response)
                            e_writer.writerow(e_response)
                else:
                    vpcs_audit.write(f"No {key} Found\n")    
            vpcs_audit.write("\n")

    # ##########################################################################

    iam = boto3.client('iam', 'us-east-1')    
    with open(FILE_ROOT, mode='a+') as iam_audit:
        credential = iam.generate_credential_report()
        
        summary = iam.get_credential_report()
        if summary['Content']:
            users = summary['Content'].decode("utf-8").split('\n')
            for user in users:
                data = user.split(',')
                if data[0] == '<root_account>' and data[7]=='false':
                    iam_audit.write("Root account don't have MFA")
                    iam_audit.write(user + "\n")
        else:
            iam_audit.write("No credential summary")
        iam_audit.write("\n")
            
        password = iam.get_account_password_policy()
        if password['PasswordPolicy']:
            iam_audit.write("IAM Account Password Policies\n")
            for key, value in password['PasswordPolicy'].items():
                iam_audit.write(str(key) + "," +  str(value) + "\n")
            else:
                iam_audit.write("No IAM Account Password Policies are Defined")
            iam_audit.write("\n")

            data = {'IAM Policies':             iam.list_policies()['Policies'],
                    'IAM Users':                iam.list_users()['Users'],
                    'IAM Groups':               iam.list_groups()['Groups'],
                    'IAM Roles':                iam.list_roles()['Roles']
                    }

            for key,val in data.items():
                if val:
                    iam_audit.write(f"{key} List\n")
                    fieldnames = val[0]
                    while not is_flat(fieldnames):
                        fieldnames=unpack(fieldnames)
                    writer = csv.DictWriter(iam_audit,fieldnames=fieldnames.keys())
                    writer.writeheader()        
                    for response in val:
                        while not is_flat(response):
                            response=unpack(response)
                        try:
                            writer.writerow(response)
                        except Exception as e:
                            e_response = response
                            e_fieldnames = e_response
                            while not is_flat(e_fieldnames):
                                e_fieldnames=unpack(e_fieldnames)
                            e_writer = csv.DictWriter(iam_audit,fieldnames=e_fieldnames.keys())
                            e_writer.writeheader()
                            while not is_flat(e_response):
                                e_response=unpack(e_response)
                            e_writer.writerow(e_response)
                else:
                    iam_audit.write(f"No {key} Found\n")            
    
    #BUCKET_NAME = "krazy-patel"
    #uploader = boto3.client('s3')
    #return uploader.upload_file(FILE_ROOT,BUCKET_NAME,"audits.csv")
