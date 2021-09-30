<#
  When you switch roles in the AWS Management Console, the console always uses your original
  credentials to authorize the switch. This applies whether you sign in as an IAM user, 
  as a SAML-federated role, or as a web-identity federated role. 
  For example, if you switch to RoleA, IAM uses your original user or 
  federated role credentials to determine whether you are allowed to assume RoleA. 
  If you then switch to RoleB while you are using RoleA, 
  AWS still uses your original user or federated role credentials to authorize the switch, 
  not the credentials for RoleA.
  Important
  The permissions of your IAM user and any roles that you switch to are not cumulative. 
  Only one set of permissions is active at a time. When you switch to a role, 
  you temporarily give up your user permissions and work with the permissions that are 
  assigned to the role. When you exit the role, your user permissions are automatically 
  restored. 
 --------------------------------------------------------------------------------- 
#> 
$Port = 3333
# Your proxy server which allows you to access outside from your company.

$proxyString = "http://localhost:$Port"

$proxyUri = new-object System.Uri($proxyString)

[Net.ServicePointManager]::SecurityProtocol = "tls12"
[System.Net.WebRequest]::DefaultWebProxy = new-object System.Net.WebProxy ($proxyUri, $true)
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials

# To test your proxy settings are working.
try{ Invoke-WebRequest "http://example.org" }
catch{ Write-Host "Error occured" -BackgroundColor DarkRed}
 

# -----------------------------------------------------------------------------
$webclient=New-Object System.Net.WebClient

$webclient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

[Net.ServicePointManager]::SecurityProtocol = "tls12"

#
# This command configures a proxy with default credentials. 
# The -Credentials parameter can be used for any credentials object that implements 
# the ICredentials interface.

try{Set-AWSProxy -Hostname localhost -Port XXXX -Credential ([System.Net.CredentialCache]::DefaultCredentials)}
catch{ Write-Host "Error occured Set-AWSProxy" -BackgroundColor DarkRed}

#---------------------------------------------------------------------

<# Defining Variable
$SAML_URL = "https://signin.aws.amazon.com/"
# 
$WebResponse = Invoke-WebRequest -UseDefaultCredentials -Uri $SAML_URL

$WebResponse.StatusCode

$WebResponse = Invoke-WebRequest -proxy http://localhost:XXXX -UseDefaultCredentials -Uri $SAML_URL

$WebResponse.StatusCode

$SAMLResponse = $WebResponse.Forms.Fields

$SAMLResponse

$MyKeys = $WebResponse.Forms.Fields.Keys

$MyKeys

$saml_token = $WebResponse.Forms.Fields.Values

$saml_token

#>

$AWSRoleName = "SecurityAuditor"

# 1) Login to the AWS Master Account   "123456789012:role/AWSRoleName"

try{Set-AWSCredential -ProfileName 123456789012:role/$AWSRoleName}
catch{ Write-Host "Error occured Set-AWSCredential" -BackgroundColor DarkRed}

try{Set-DefaultAWSRegion -Region us-east-1}
catch{ Write-Host "Error occured Set-DefaultAWSRegion" -BackgroundColor DarkRed}

try{Get-IAMAccountAlias}
catch{ Write-Host "Error occured Get-IAMAccountAlias" -BackgroundColor DarkRed}

try{Get-DefaultAWSRegion}
catch{ Write-Host "Error occured Get-DefaultAWSRegion" -BackgroundColor DarkRed}


# Now from the Master Account loops through listed AWS Accounts which are listed as variable $Accounts.

$Accounts =   "111111111111", "222222222222", "333333333333", "444444444444", "555555555555"


# ---------------------------------------------------

foreach($Account in $Accounts) {
  
   $Account

   # Returns a set of temporary security credentials that you can use to access AWS resources that 
   # you might not normally have access to. These temporary credentials consist of an access key ID, 
   # a secret access key, and a security token. 

   # Now from the Master Account loops through listed AWS Accounts which are listed as variable $Accounts.
   # 
    try{$Credentials = (Use-STSRole -RoleArn "arn:aws:iam::${Account}:role/$AWSRoleName" -RoleSessionName "MyRoleSessionName").Credentials}
    catch{ Write-Host "Error occured" -BackgroundColor DarkRed}

    $Credentials.AccessKeyId

    $Credentials.SecretAccessKey

    $Credentials.SessionToken

    $Credentials.Expiration


    try{Set-AWSCredential - -Credential $Credentials}
    catch{ Write-Host "Error occured Set-AWSCredential" -BackgroundColor DarkRed}

    try{Get-IAMAccountAlias}
    catch{ Write-Host "Error occured Get-IAMAccountAlias" -BackgroundColor DarkRed}
 
	Start-Sleep -seconds 5
    #-------------------------------------
    $Regions = "us-east-2", "us-west-1"

    # { START OF REGIONS FOREACH 
    
    foreach ( $Region in $Regions) {
        
        try{Set-DefaultAWSRegion -Region $Region}
        catch{ Write-Host "Error occured Set-DefaultAWSRegion" -BackgroundColor DarkRed} 

        try{$Region = (Get-DefaultAWSRegion).Region}
        catch{ Write-Host "Error occured (Get-DefaultAWSRegion" -BackgroundColor DarkRed} 
        
        $Date   = (Get-Date -Format "MM-dd-yyyy-HH:MM-tt") 

        try{$AWSNAME  = Get-IAMAccountAlias}
        catch{ Write-Host "Error occured Get-IAMAccountAlias" -BackgroundColor DarkRed}

        #try{Write-Host " $($AWSNAME) in $($Region) "}
        #catch{ Write-Host "Error occured" -BackgroundColor DarkRed}

        #===============================================================
        #  Now add your command or code below, which you want to check verify.
        #  This way, you can check across all the AWS accounts.        
        # Below the example, I am checking if the VPC exists or not in each AWS Accounts 
        # in each region.  ( us-east-2 and us-west-1)
		# ===================================================================
        # Example
		
		try{(Get-EC2Vpc | Format-Table VpcId, Cidrblock, state)}
        catch{ Write-Host "Error occured" -BackgroundColor DarkRed}
        

		
		
		

		
        #=============================================================
        #   You add your command above.
        #==============================================================
           

    #---END OF EACH REGION -----------------------------------------------
       
	    }  # foreach ( $Region in $Regions) {

# ------------------------------------------

    try{Clear-AWSCredential}
    catch{ Write-Host "Error occured" -BackgroundColor DarkRed} 

    Start-Sleep -Seconds 5

	# ---END OF EACH ACCOUNTS --------------------------
	
}   # foreach($Account in $Accounts) {

