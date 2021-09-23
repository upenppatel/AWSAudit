"""

conda list |grep boto3
import boto3
session  = boto3.Session(profie_name = 'my_profile')

# To print all ec2 instances in your account, type:
ec2 = session.resource('ec2')
for i in ec2.instances.all():
    print(i)

try:
    value = init(users_input)
except ValueError:
    logging.error("Bad value from user: %r", user_input)
except TypeError:
    logging.error("Invalid type(probably a bug): %r", user_input)

import os
import logging
UPLOAD_ROOT = "/tmp/uploads"
# Logging the Directory
# FileExistsError objects have an attribute call filename
# Let's use that to create a useful log message.

def create_upload_dir(username):
    userdir = os.path.join(UPLOAD_ROOT, username)
    try:
        os.makedirs(usedir)
    except FileExistsError as err:
    
        logging.error("Upload dir already exists: %s", err.filename)

"""

""" 
The sys module provides information about constants, functions and methods of the Python interpreter. 
dir(system) gives a summary of the available constants, functions and methods. Another possibility is the help() function. 
Using help(sys) provides valuable detail information
"""

try:
    import sys
    print('The module imported is sys')
    print()
    print( '\n'.join(sys.path))
except ImportError:
    print('THe module is not imported sys')
print()

"""
This module defines functions and classes which implement a flexible event logging system for applications and libraries.
The key benefit of having the logging API provided by a standard library module is that all Python modules can participate
 in logging, so your application log can include your own messages integrated with messages from third-party modules.
"""
try: 
    import logging
    print('The module imported is  logging')
except ImportError:
    print('The module is not imported  logging')
print()

try: 
    import os 
    print('The module imported is  os')
except ImportError:
    print('The module is not imported  os')
print()

try: 
    import csv
    print('The module imported is  csv')
except ImportError:
    print('The module is not imported  csv')
    logging.warning('The module is not imported csv')
print()

try: 
    import requests
    print('The module imported is  requests')
except ImportError:
    print('The module is not imported  requests')
    logging.warning('The module is not imported requests')
print()

try: 
    import boto3
    print('The module imported is  boto3')
except ImportError:
    print('The module is not imported  boto3')
    logging.warning('The module is not imported boto3')
print()

def is_flat(a):
    if type(a)==type(list()):
        return False
    for key,val in a.items():
        if type(val)==type(dict()) or type(val)==type(list()):
            return False
    return True

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
    if is_flat(res):
    	return res
    else:
    	return unpack(res)


file=open('output.csv','w')

try: 
    import boto3
    print('The module imported is  boto3')
except ImportError:
    print('The module is not imported  boto3')
print()

client = boto3.client('iam')

iam_client=boto3.client('iam')
Roles = iam_client.list_roles()
Users = iam_client.list_users()
Groups= iam_client.list_groups()

file.write('Roles\nRoleName,')

if Roles['Roles']:
	fieldnames = unpack(iam_client.list_attached_role_policies(RoleName=Roles['Roles'][0]['RoleName'])).keys()
	writer = csv.DictWriter(file,fieldnames=fieldnames)
	writer.writeheader()  	
	for role in Roles['Roles']:
		file.write(role['RoleName']+',')
		data=unpack(iam_client.list_attached_role_policies(RoleName=role['RoleName']))
		writer.writerow(data)

file.write('\nUsers\nUserName,')
if Users['Users']:
	fieldnames = unpack(iam_client.list_attached_user_policies(UserName=Users['Users'][0]['UserName'])).keys()
	writer = csv.DictWriter(file,fieldnames=fieldnames)
	writer.writeheader()  	
	for user in Users['Users']:
		file.write(user['UserName']+',')
		data=unpack(iam_client.list_attached_user_policies(UserName=user['UserName']))
		writer.writerow(data)

file.write('\nGroups\nGroupName,')
if Groups['Groups']:
	fieldnames = unpack(iam_client.list_attached_group_policies(GroupName=Groups['Groups'][0]['GroupName'])).keys()
	writer = csv.DictWriter(file,fieldnames=fieldnames)
	writer.writeheader()  	
	for Group in Groups['Groups']:
		file.write(Group['GroupName']+',')
		data=unpack(iam_client.list_attached_group_policies(GroupName=Group['GroupName']))
		writer.writerow(data)
