# Get-Command –CommandType Function
# 
#  The Get-OUSCPAudit function will connect to the AWS Master Accounts and 
#  gather the information related to Organization Unit.
#  It will also collect the AWS Service Control Policies information.   
#  It provides information on what SCP policy is attached to the Organization Unit
#
#  To run the function type 
#  
# "Get-IAMAudit 123456789012:role/SecurityAuditor"
#
########################################################################

$AWSAccount = '123456789012'

#  Beginning of the Function
#  
function Get-IAMAudit {

    [CmdletBinding()]
    param(

    #The ValidateSet attribute enables you to specify a list of values allowed for the parameter.
    [Parameter(Mandatory)]
    [ValidateSet('123456789012:role/SecurityAuditor')]
    $Profile

    )

     # ----------------------EXCEL Settings------------------------
 
    $R1 = New-ConditionalText Effective DarkBLUE -BackgroundColor White
    $R2 = New-ConditionalText True  DarkBLUE -BackgroundColor White
    $R3 = New-ConditionalText Ineffective Darkred -BackgroundColor White                               
    $R4 = New-ConditionalText False Darkred -BackgroundColor White    
           
    # ----PROXY SETTING TO CONNECT TO AWS -----------------------------------------------------
    
	$webclient=New-Object System.Net.WebClient
    $webclient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    [Net.ServicePointManager]::SecurityProtocol = "tls12"
    
    $Port = '1234'

    Set-AWSProxy -Hostname localhost -Port $Port -Credential ([System.Net.CredentialCache]::DefaultCredentials)
    
	
	# ----------------------------------------------------------------------------------------------
	# https://signin.aws.amazon.com/
	
     $Accounts =     '11111111111', '22222222222', '333333333333', '444444444444', '555555555555', 
    
	#-----------------------------------------------------------------------------------------------
		
    Write-Host "To run the function type Get-IAMAudit 123456789012:role/SecurityAuditor"
    
    Start-Sleep -Seconds 30
    
    #  NOW CONNECTING TO AWS Master Account
	try{
    
    Set-AWSCredential -ProfileName $Profile -ErrorAction Stop
    
    $AWSNAME = Get-IAMAccountAlias
    }
    catch{
    Write-Warning "$_.Exception.Message"
    }
    Finally{
    Write-Host "Done with Aws Account: $AWSNAME " -ForegroundColor Green
    } 
 
    Start-Sleep -Seconds 30
	$Accounts 
    # ------------------------------------------------------------------------------

    #  The Script part goes here.
                                              
    #----------------------------------------------------------------------

    # OUTPUT FILE: 
    
    $D = (Get-Date -Format "MM-dd-yyyy")
 
    $FileName = "C:\temp\IAM-Audit-$($D).xlsx"

    Write-Host "The Output of the script $FileName"
    
	Start-Sleep -Seconds 20
    
    $Date = (Get-Date -UFormat "%B-%d-%Y|%T")

    #-------------------------------------------------------------------------- 
    foreach($Account in $Accounts) {
    $Account
    $Credentials = (Use-STSRole -RoleArn "arn:aws:iam::${Account}:role/SecurityAuditor" -RoleSessionName "MyRoleSessionName").Credentials
 
    Set-AWSCredential - -Credential $Credentials
	
    Get-IAMAccountAlias
    Start-Sleep -Seconds 5

    #$Regions = "us-east-1", "us-west-2"

    # { START OF REGIONS FOREACH 
    # foreach ( $Region in $Regions) {
    #   Set-DefaultAWSRegion -Region $Region

        $Region = (Get-DefaultAWSRegion).Region 
        $Region
        $Date   = (Get-Date -UFormat "%B-%d-%Y|%T")
        $AWSNAME  = Get-IAMAccountAlias
        Write-Host " $($AWSNAME) in $($Region) "

        # -------------------------------------------------------
        
        #-----------------------------------------------------------------------

        # Collecting the AWS Account Password Policy 

	    <# 411 Information Security Policy	Access Control	AC 8	
        # "Ensure that strong passwords and password rules are enforced. The following requirement(s) must be addressed:
        # a. Account password rules must be enforced such that passwords have minimum password 
        # complexity of organization-defined requirements for case sensitivity, number of characters, 
        # mix of upper-case letters, lower-case letters, numbers, and special characters, 
        # including minimum requirements for each type. 
        # b. Account password rules must be enforced to prevent reuse of previous passwords and use of default passwords.
        # c. Accounts must be protected from attempts to guess the password.
        # d. Account password rules must be enforced to maximize the likelihood of detecting the use of a compromised account.
        # e. Accounts must be configured to time out after a defined period of inactivity and require them to re-authenticate."
        #>

        $IDate = (Get-Date -UFormat "%B-%d-%Y|%T")	
         
        $PWPolicy = IAMAccountPasswordPolicy
        $P1 = If($PWPolicy.AllowUsersToChangePassword -eq "True"){"Effective"} else {"Ineffective"}
        $P2 = If($PWPolicy.ExpirePasswords -eq "True"){"Effective"} else {"Ineffective"}
        $P3 = If($PWPolicy.MaxPasswordAge -eq "90"){"Effective"} else {"Ineffective"}
        $P4 = If($PWPolicy.MinimumPasswordLength -eq "14"){"Effective"} else {"Ineffective"}
        $P5 = If($PWPolicy.PasswordReusePrevention -eq "24"){"Effective"} else {"Ineffective"}
        $P6 = If($PWPolicy.RequireLowercaseCharacters -eq "True"){"Effective"} else {"Ineffective"}
        $P7 = If($PWPolicy.RequireNumbers -eq "True"){"Effective"} else {"Ineffective"}
        $P8 = If($PWPolicy.RequireSymbols -eq "True"){"Effective"} else {"Ineffective"}
        $P9 = If($PWPolicy.RequireUppercaseCharacters -eq "True"){"Effective"} else {"Ineffective"}
        
        Get-IAMAccountSummary | 
        ForEach-Object { 
            $PasswordPolicy                             = [PSCustomObject]@{
            Date                                        =(Get-Date -UFormat "%B-%d-%Y|%T")
            AWSName                                     = $AWSName
			AllowUsersToChangePassword                  = $PWPolicy.AllowUsersToChangePassword
            PWPolicy_AllowUsersToChangePassword         = $P1
			ExpirePasswords                             = $PWPolicy.ExpirePasswords
            AC_PWPolicy_ExpirePasswords                 = $P2
			MaxPasswordAge                              = $PWPolicy.MaxPasswordAge
            AC_PWPolicy_MaxPasswordAge                  = $P3
			MinimumPasswordLength                       = $PWPolicy.MinimumPasswordLength
            AC_PWPolicy_MinimumPasswordLength           = $P4
			PasswordReusePrevention                     = $PWPolicy.PasswordReusePrevention
            AC_PWPolicy_PasswordReuse                   = $P5
			RequireLowercaseCharacters                  = $PWPolicy.RequireLowercaseCharacters
            AC_PWPolicy_RequireLowercase                = $P6
			RequireNumbers                              = $PWPolicy.RequireNumbers
            AC_PWPolicy_RequireNumbers                  = $P7
			RequireSymbols                              = $PWPolicy.RequireSymbols
            AC_PWPolicy_RequireSymbols                  = $P8
			RequireUppercaseCharacters                  = $PWPolicy.RequireUppercaseCharacters
			AC_PWPolicy_RequireUppercase                = $P9
            }
            # $IAMAccountSummary
		    $PasswordPolicyOut =@()
            $PasswordPolicyOut = $PasswordPolicy
            $PasswordPolicyOut | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'PasswordPolicy' -ConditionalText $R1,$R2,$R3,$R4
            } #  ForEach-Object { 

        #---------------------------------------------------------------------------------------------------
        # Collecting the AWS Account Password Policy 
	  
	    $IDate = (Get-Date -UFormat "%B-%d-%Y|%T")	 
        Get-IAMAccountSummary | 
        ForEach-Object { 
            $IAMAccountSummary      = [PSCustomObject]@{
            Date                                        =(Get-Date -UFormat "%B-%d-%Y|%T")
            AWSName                                     = $AWSName
            AccountMFAEnabled                  		    = $_.AccountMFAEnabled
			MFADevices                           		= $_.MFADevices
			MFADevicesInUse                       		= $_.MFADevicesInUse
			Users                                		= $_.Users 
			Groups                               		= $_.Groups  
			Roles                               		= $_.Roles   
            Policies                            		= $_.Policies					
            GroupPolicySizeQuota              		    = $_.GroupPolicySizeQuota              
            InstanceProfilesQuota             		    = $_.InstanceProfilesQuota                                                            
            GroupsPerUserQuota                 		    = $_.GroupsPerUserQuota                 
            InstanceProfiles                    		= $_.InstanceProfiles                    
            AttachedPoliciesPerUserQuota        		= $_.AttachedPoliciesPerUserQuota                                       
            PoliciesQuota                     		    = $_.PoliciesQuota                  
            Providers                             		= $_.Providers                                             
            AccessKeysPerUserQuota                		= $_.AccessKeysPerUserQuota                
            AssumeRolePolicySizeQuota          		    = $_.AssumeRolePolicySizeQuota          
            PolicyVersionsInUseQuota          		    = $_.PolicyVersionsInUseQuota          
            GlobalEndpointTokenVersion            		= $_.GlobalEndpointTokenVersion            
            VersionsPerPolicyQuota                		= $_.VersionsPerPolicyQuota                
            AttachedPoliciesPerGroupQuota        		= $_.AttachedPoliciesPerGroupQuota        
            PolicySizeQuota                    		    = $_.PolicySizeQuota                    
            AccountSigningCertificatesPresent    		= $_.AccountSigningCertificatesPresent    
            UsersQuota                         		    = $_.UsersQuota                         
            ServerCertificatesQuota             		= $_.ServerCertificatesQuota             
            UserPolicySizeQuota               		    = $_.UserPolicySizeQuota               
            PolicyVersionsInUse                  		= $_.PolicyVersionsInUse                  
            ServerCertificates                    		= $_.ServerCertificates                    
            RolesQuota                         		    = $_.RolesQuota                         
            SigningCertificatesPerUserQuota       		= $_.SigningCertificatesPerUserQuota       
            RolePolicySizeQuota               		    = $_.RolePolicySizeQuota               
            AttachedPoliciesPerRoleQuota         		= $_.AttachedPoliciesPerRoleQuota         
            AccountAccessKeysPresent              		= $_.AccountAccessKeysPresent              
            GroupsQuota    		                        = $_.GroupsQuota}
            # $IAMAccountSummary
		    $IAMAccountSummaryout =@()
            $IAMAccountSummaryout = $IAMAccountSummary
            $IAMAccountSummaryout | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'IAMAccountSummary'
            } #  ForEach-Object { 

    # Collecting the information related to SAML. 
    # Lists the SAML provider resource objects defined in IAM in the account. 
    # IAM resource-listing operations return a subset of the available attributes for the resource. 
    # 
         
        Get-IAMSAMLProviderList |
        ForEach-Object { 
        $IAMSAMLProviderList                          = [PSCustomObject]@{
            Date                                        = (Get-Date -UFormat "%B-%d-%Y|%T")
            AWSName                                     = $AWSName
			Arn                                         = $_.Arn
            CreateDate                                  = $_.CreateDate
            SAMLMetadataDocument                        = $_.ValidUntil}
            $IAMSAMLProviderList 
            $IAMSAMLProviderListOUT =@()
            $IAMSAMLProviderListOUT =  $IAMSAMLProviderList
            $IAMSAMLProviderListOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'SAMLProviderLIST'
        } #  ForEach-Object { 


    # -----------------------------------------------------------------------------------
    #  Collecting CredentialReport
 
       # Request the Credential report
       Request-IAMCredentialReport
       
       # Wait for report generation
       Start-Sleep -Seconds 10
       
       # Get the report as CSV
       $Report = Get-IAMCredentialReport -AsTextArray | ConvertFrom-Csv
       #  $Report | Where user -eq '<root_account>' 
       # (Get-IAMAccountAuthorizationDetails).UserDetailList | Where UserName -eq alice
       
        foreach( $I in $Report) {
        $I 
        ForEach-Object { 
            $IAMCredentialReport     = [PSCustomObject]@{
            Date                                        = (Get-Date -UFormat "%B-%d-%Y|%T")
            AWSName                                     = $AWSName
			User                                        = $I.user
			Arn                                         = $I.arn
            UserCreationTime                            = $I.user_creation_time
            PasswordEnabled                             = $I.password_enabled
            PasswordLastUsed                            = $I.password_last_used
            PasswordLastChanged                         = $I.password_last_changed
            PasswordNextRotation                        = $I.password_next_rotation
            MFAActive                                   = $I.mfa_active
            accesskey1active            	            = $I.access_key_1_active            
            accesskey1lastrotated      	                = $I.access_key_1_last_rotated      
            accesskey1lastuseddate              	    = $I.access_key_1_last_used_date    
            accesskey1lastusedregion  	                = $I.access_key_1_last_used_region  
            accesskey1lastusedservice 	                = $I.access_key_1_last_used_service 
            accesskey2active            	            = $I.access_key_2_active            
            accesskey2lastrotated                 	    = $I.access_key_2_last_rotated      
            accesskey2lastuseddate    	                = $I.access_key_2_last_used_date    
            accesskey2lastused_region  	                = $I.access_key_2_last_used_region  
            accesskey2lastusedservice 	                = $I.access_key_2_last_used_service 
            cert1active                  	            = $I.cert_1_active                  
            cert1last_rotated            	            = $I.cert_1_last_rotated            
            cert2active                  	            = $I.cert_2_active                  
            cert2lastrotated  	                        = $I.cert_2_last_rotated} 
            $IAMCredentialReport
		    $IAMCredentialReportOUT =@()
            $IAMCredentialReportOUT = $IAMCredentialReport
            $IAMCredentialReportOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'CredentialReport'
        } #  ForEach-Object { 
        }
            
        
        (Get-IAMAccountAuthorizationDetails).UserDetailList | 
        ForEach-Object { 
        $UserDetailList         = [PSCustomObject]@{
            Date                    = (Get-Date -UFormat "%B-%d-%Y|%T")
            AWSName                 = $AWSName
            UserName                = $_.UserName
            UserId                  = $_.UserId
            Arn                     = $_.Arn
            AttachedManagedPolicies = $_.AttachedManagedPolicies
            CreateDate              = $_.CreateDate
            GroupList               = $_.GroupList
            Path                    = $_.Path
            PermissionsBoundary     = $_.PermissionsBoundary
            Tags                    = $_.Tags
            UserPolicyList          = $_.UserPolicyList}
            $UserDetailList
		    $UserDetailListOUT =@()
            $UserDetailListOUT = $UserDetailList
            $UserDetailListOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'UserDetailList'
        } #  ForEach-Object { 
   
#   Collect the Users Information 
#---------------------------------------------------------------------------------------------
    
    foreach( $I in (Get-IAMUserList).UserName | sort  ) {
        
        $Tags  = (Get-IAMUser -UserName $I).Tags
        $Tags
        
		$ResourceOwner  = ($Tags | Where {$_.Key -eq 'mufg:resource-owner-email'}).Value
        $ResourceOwner
        
        $SvcRoleOwner = ($Tags | Where {$_.Key -eq 'mufg:svc_role_owner'}).Value
        $SVcRoleOwner
     
        $SvcRoleOwnerName = ($Tags | Where {$_.Key -eq 'mufg:svc_role_owner_name'}).Value
        $SVcRoleOwnerName
            
	    Get-IAMUser -UserName $I |
        ForEach-Object { 
        $User  = [PSCustomObject]@{
            Date                    = (Get-Date -UFormat "%B-%d-%Y|%T")
            AWSName                 = $AWSName
            UserName                = $_.UserName
            UserId                  = $_.UserId
            Arn                     = $_.Arn
            CreateDate              = $_.CreateDate
            PasswordLastUsed        = $_.PasswordLastUsed
            #Path                   = $_.Path
            Tags                    = $_.Tags
            ResourceOwner           = $ResourceOwner
            SVcRoleOwner            = $SVcRoleOwner
            SVcRoleOwnerName        = $SVcRoleOwnerName
            PermissionsBoundary     = $_.PermissionsBoundary}
            $User             
            $Userout =@()
            $Userout = $User
            $Userout | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'Users'
            if($?){"command succeeded"}else{"command failed"}
        } #  ForEach-Object { 
               
        $UserGroupCounts = ((Get-IAMGroupForUser -UserName $I).GroupName).count
        $UserGroupCounts 
    
     	Get-IAMGroupForUser -UserName $I | sort | 
        ForEach-Object { 
        $UserGroups  = [PSCustomObject]@{
            Date                    = (Get-Date -UFormat "%B-%d-%Y|%T")
            AWSName                 = $AWSName
            User                    = $I
            UserGroupCounts         = $UserGroupCounts
            GroupName               = $_.GroupName
            GroupId                 = $_.GroupId
            GroupArn                = $_.Arn
            GroupPath               = $_.Path}
            #$UserGroups     
            $UserGroupsout =@()
            $UserGroupsout = $UserGroups
            $UserGroupsout | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'UserGroups'
            if($?){"command succeeded"}else{"command failed"}
        } #  ForEach-Object { 


        # 1.16 Ensure IAM policies are attached only to groups or roles (Scored)
            
        Get-IAMUserPolicyList -UserName $I
            $P  = if($? -eq "false") 
            {"Ensure IAM policies are attached only to groups or roles: $($I): PASS"} 
            else { "Ensure IAM policies are attached only to groups or roles $($I): FAIL"}  
              
    } #foreach( $U in (Get-IAMUserList).UserName )
       
    #   Collect the Group Information  
    #  -------------------------------------------------------------------------------------------

    $Groups = (Get-IAMGroupList).GroupName | sort 
        
    $GroupCounts = $Groups.count
		
       
    foreach( $I in (Get-IAMGroupList).GroupName | sort) {    
        
        $Users = ((Get-IAMGroup -GroupName $I).Users).UserName 
        $NmbofUsers  = $Users.count
              
        Get-IAMGroup -GroupName $I | sort | 
        ForEach-Object { 
        $Groups  = [PSCustomObject]@{
            Date                    = (Get-Date -UFormat "%B-%d-%Y|%T")
            AWSName                 = $AWSName
	        GroupCounts             = $GroupCounts
            GroupName               = $I
            Group                   = $_.Group
            #Users                  = $_.Users
            Users                   = $Users
            UsersInGroup            = $NumofUsers
            IsTruncated             = $_.IsTruncated
            Marker                  = $_.Marker}
            $Groups            
            $Groupout =@()
            $Groupout = $Groups
            $Groupout | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'Groups'
            if($?){"command succeeded"}else{"command failed"}
        } #  ForEach-Object {  

            
        $GroupPcontent  = Get-IAMAttachedGroupPolicyList -GroupName $I |Select -expand PolicyName | sort
        $GroupPolicyContent              = [string]::join(",  ",$GroupPcontent)
        $GroupPolicyContent  

        $GroupArncontent  = Get-IAMAttachedGroupPolicyList -GroupName  $I |Select -expand PolicyArn | sort
        $GroupPolicyArnContent              = [string]::join(",  ",$GroupArncontent)
        $GroupPolicyArnContent

         
        foreach( $P in $GroupArncontent) {
            Get-IAMPolicy -PolicyArn $P
            ForEach-Object { 
                $GroupPolicyAttached  = [PSCustomObject]@{
                Date                    = (Get-Date -UFormat "%B-%d-%Y|%T")
                AWSName                 = $AWSName
                GroupName               = $I
                PolicyArn               = $P
				PolicyName              = $_.PolicyName
                PolicyID                = $_.PolicyId
                Arn                     = $_.Arn
                AttachmentCount         = $_.AttachmentCount
                CreateDate              = $_.CreateDate
                UpdateDate              = $_.UpdateDate
                DefaultVersionId        = $_.DefaultVersionId
                Description             = $_.Description
                IsAttachable            = $_.IsAttachable
                Path                    = $_.Path
                PermissionsBoundaryUsageCount = $_.PermissionsBoundaryUsageCount}
                $GroupPolicyAttachedout = $GroupPolicy
                $GroupPolicyAttachedout | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'PolicyAttached2Group'
                if($?){"command succeeded"}else{"command failed"}
            } #  ForEach-Object { 
               
        } #foreach( $P in $GroupArncontent) {

            
        Get-IAMAttachedGroupPolicyList -GroupName $I | sort | 
        ForEach-Object { 
        $GroupPolicy  = [PSCustomObject]@{
            Date                    = (Get-Date -UFormat "%B-%d-%Y|%T")
            AWSName                 = $AWSName
            GroupName               = $I
            PolicyName              = $GroupPolicyContent
            PolicyArn               = $GroupPolicyArnContent}
            #$GroupPolicy            
            $GroupPolicyout =@()
            $GroupPolicyout = $GroupPolicy
            $GroupPolicyout | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'GroupPolicyAttached'
            if($?){"command succeeded"}else{"command failed"}
        } #  ForEach-Object { 

    }   # foreach( $I in (Get-IAMGroupList).GroupName) {   
	

    #   Collecting the Roles related Information
    #   ---------------------------------------------------IDate = (Get-Date -Format "MM-dd-yyyy-HH:MM")

        
        # Privilged Roles
        $Roles = "SystemAdministrator",
                 "SecurityAdministrator",
                 "Developer",
                 "BreakGlass",
                 "IAMAdministrator",
                 "KMSAdmin",
                 "NetworkAdministrator"
                 
        $Roles 
		Foreach($I in $Roles) { 
	
	        $Pcontent  = Get-IAMAttachedRolePolicies -RoleName $I |Select -expand PolicyName | sort
            $PolicyContent              = [string]::join("  , ",$Pcontent)
  
            $Arncontent  = Get-IAMAttachedRolePolicies -RoleName $I |Select -expand PolicyArn | sort
            $PolicyArnContent              = [string]::join("  , ",$Arncontent)
        
		    Get-IAMRole -RoleName $I | 
            ForEach-Object { 
                $Role  = [PSCustomObject]@{
                Date                    = (Get-Date -UFormat "%B-%d-%Y|%T")
                AWSName                 = $AWSName
                RoleName                = $I
                RoleId                  = $_.RoleId
                CreateDate              = $_.CreateDate
                Description             = $_.Description
                Path                    = $_.Path}
                $Role            
                $Roleout =@()
                $Roleout = $Role
                $Roleout | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'Roles'
                if($?){"command succeeded"}else{"command failed"}
            } #  ForEach-Object { 

    #   Collecting the Policies related Information
    #   -----------------------------------------------------------------------------	
           
            Get-IAMAttachedRolePolicies -RoleName $I | sort | Select -expand PolicyName 
            ForEach-Object { 
                $RolePolicies  = [PSCustomObject]@{
                Date                    = (Get-Date -UFormat "%B-%d-%Y|%T")
                AWSName                 = $AWSName
                RoleName                = $I
                PolicyName              = $PolicyContent
                PolicyArn               = $PolicyArnContent} 
                $RolePolicies            
                $RolePoliciesout =@()
                $RolePoliciesout = $RolePolicies
                $RolePoliciesout | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'RolePolicies'
                if($?){"command succeeded"}else{"command failed"}
            } #  ForEach-Object { 

        } #Foreach($I in $Roles) { 

        Get-IAMPolicies -Scope local | sort |
        ForEach-Object { 
        $CustomerManagedPolicies  = [PSCustomObject]@{
            Date                    = (Get-Date -UFormat "%B-%d-%Y|%T")
            AWSName                 = $AWSName
            PolicyName              = $_.PolicyName
            PolicyID                = $_.PolicyId
            Arn                     = $_.Arn
            AttachmentCount         = $_.AttachmentCount
            CreateDate              = $_.CreateDate
            UpdateDate              = $_.UpdateDate
            DefaultVersionId        = $_.DefaultVersionId
            Description             = $_.Description
            IsAttachable            = $_.IsAttachable
            Path                    = $_.Path
            PermissionsBoundaryUsageCount = $_.PermissionsBoundaryUsageCount}
            $CustomerManagedPolicies
            $CustomerManagedPoliciesOUT =@()
            $CustomerManagedPoliciesOUT = $CustomerManagedPolicies
            $CustomerManagedPoliciesOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'CustomerManagedPolicies'
        } #  ForEach-Object { 

        #  --------------------------------------------------------
        #  
 
        Clear-AWSCredential 
        Start-Sleep Seconds 10
    #End foreach($Account in $Accounts) {} 
    # 	
    } 

    # ----------------------------------------------------------------------------------

#  End of the Function
#  
}
