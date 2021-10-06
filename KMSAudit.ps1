$webclient=New-Object System.Net.WebClient
$webclient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
[Net.ServicePointManager]::SecurityProtocol = "tls12"

$Port = 1234
Set-AWSProxy -Hostname localhost -Port $Port -Credential ([System.Net.CredentialCache]::DefaultCredentials)

# AWS Key Management Service (KMS) makes it easy for you to create and manage cryptographic 
# keys and control their use across a wide range of AWS services and in your applications. 
# AWS KMS is a secure and resilient service that uses hardware security modules that have 
# been validated under FIPS 140-2, or are in the process of being validated, to protect 
# your keys. AWS KMS is integrated with AWS CloudTrail to provide you with logs of all 
# key usage to help meet your regulatory and compliance needs.


# 1) Login to the AWS Account

$RoleName = SecurityAuditor
try{Set-AWSCredential -ProfileName 123456789012:role/$Rolename}
catch{ Write-Host "Error occured" -BackgroundColor DarkRed}

try{Set-DefaultAWSRegion -Region us-east-1}
catch{ Write-Host "Error occured" -BackgroundColor DarkRed}

try{Get-IAMAccountAlias}
catch{ Write-Host "Error occured" -BackgroundColor DarkRed}

try{Get-DefaultAWSRegion}
catch{ Write-Host "Error occured" -BackgroundColor DarkRed}

# https://signin.aws.amazon.com/switchrole

# Now from the Master Account loops through listed AWS Accounts which are listed as variable $Accounts.

$Accounts =   '111111111111', '111222333444', '555666777888'

try{$Accounts}
catch{ Write-Host "Error occured" -BackgroundColor DarkRed}

# ---------------------------------------------------

foreach($Account in $Accounts) {
  
  $Account

# Returns a set of temporary security credentials that you can use to access AWS resources that 
# you might not normally have access to. These temporary credentials consist of an access key ID, 
# a secret access key, and a security token. 

# Now from the Master Account loops through listed AWS Accounts which are listed as variable $Accounts.
# 
try{$Credentials = (Use-STSRole -RoleArn "arn:aws:iam::${Account}:role/SecurityAuditor" -RoleSessionName "MyRoleSessionName").Credentials}
catch{ Write-Host "Error occured" -BackgroundColor DarkRed}

try{Set-AWSCredential - -Credential $Credentials}
catch{ Write-Host "Error occured" -BackgroundColor DarkRed}

try{Get-IAMAccountAlias}
catch{ Write-Host "Error occured" -BackgroundColor DarkRed}
 
Start-Sleep 5

 
    $Regions = "us-east-2", "us-west-1"

    # { START OF REGIONS FOREACH 
    
    foreach ( $Region in $Regions) {
        
        try{Set-DefaultAWSRegion -Region $Region}
        catch{ Write-Host "Error occured" -BackgroundColor DarkRed} 

        try{$Region = (Get-DefaultAWSRegion).Region}
        catch{ Write-Host "Error occured" -BackgroundColor DarkRed} 
        
        $Date   = (Get-Date -Format "MM-dd-yyyy-HH:MM-tt") 

        try{$AWSNAME  = Get-IAMAccountAlias}
        catch{ Write-Host "Error occured" -BackgroundColor DarkRed}

        try{Write-Host " $($AWSNAME) in $($Region) "}
        catch{ Write-Host "Error occured" -BackgroundColor DarkRed}

        #------------------------------------------------------------
        #  Now add your command or code below, which you want to check verify.
        #  This way, you can check across all the AWS accounts.
        #
        # Below the example, I am checking if the VPC exists or not in each AWS Accounts 
        # in each region.  ( us-east-1 and us-west-2)
       
        try{(Get-EC2Vpc | Format-Table VpcId, Cidrblock, state)}
        catch{ Write-Host "Error occured" -BackgroundColor DarkRed}

        # OUTPUT FILE: 
    
        $D = (Get-Date -Format "MM-dd-yyyy")
 
        $FileName = "C:\TEMP\KMSAudit-$($D).xlsx"    


        $keys = (Get-KMSKeyList).Keyid 
        $keys.count

        # Gets a list of all KMS keys in the caller's Amazon Web Services account and Region.
        #  Cross-account use: No.
        $KMSKEYSLISTCOUNT = (Get-KMSKeyList).count 
            Get-KMSKeyList | 
            ForEach-Object { 
            $KMSKeyList                = [PSCustomObject]@{
            Date                       = (Get-Date -UFormat "%B-%d-%Y|%T")
            AWSName                    = $AWSName
            Region                     = $Region
            NumofKeys                  = $KMSKEYSLISTCOUNT
            KeyId                      = $_.KeyId
            KeyArn                     = $_.KeyArn}
            $KMSKeyList
            $KMSKeyListOUT =@()
            $KMSKeyListOUT = $KMSkeyList

            try{$KMSKeyListOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'KMSKeysList'}
            catch{$_.Exception.Message | Export-Excel $filename  -WorksheetName 'ERROR'}

            }

    # Provides detailed information about a KMS key. You can run DescribeKey on a customer 
    # managed key or an Amazon Web Services managed key.
    $KEYS = Get-KMSKeys| ForEach-Object{$_.KeyId}
    $KEYS
    ForEach($Key in $KEYS) { 
	
	        Get-KMSKey -KeyId $KEY | 
            ForEach-Object { 
            $KMSKey                = [PSCustomObject]@{
            Date                        = (Get-Date -UFormat "%B-%d-%Y|%T")
            AWSName                     = $AWSName
            Region                      = $Region
            NumofKeys                   = $KMSKEYSLISTCOUNT
            Key                         = $Key 
            Arn                   		= $_.Arn     
            KeyId                 		= $_.KeyId              
            AWSAccountId          		= $_.AWSAccountId          
            CloudHsmClusterId     		= $_.CloudHsmClusterId     
            CreationDate          		= $_.CreationDate          
            CustomerMasterKeySpec 		= $_.CustomerMasterKeySpec 
            CustomKeyStoreId      		= $_.CustomKeyStoreId      
            DeletionDate          		= $_.DeletionDate          
            Description         		= $_.Description         
            Enabled               		= $_.Enabled               
            EncryptionAlgorithms  		= $_.EncryptionAlgorithms  
            ExpirationModel       		= $_.ExpirationModel                 
            KeyManager            		= $_.KeyManager            
            KeyState              		= $_.KeyState              
            KeyUsage              		= $_.KeyUsage              
            Origin                		= $_.Origin                
            SigningAlgorithms     		= $_.SigningAlgorithms     
            ValidTo     		        = $_.ValidTo}                  
            $KMSKey
            $KMSKeyOUT =@()
            $KMSKeyOUT = $KMSKey
            
            try{$KMSKeyOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'KEY'}
            catch{$_.Exception.Message | Export-Excel $filename  -WorksheetName 'ERROR'}

            } #  ForEach-Object { 
 

            # Get-KMSKeyPolicyList -KeyId $Key | 
            $Result = Get-KMSKeyPolicyList -KeyId $Key 
            ForEach-Object { 
            $PolicyList            = [PSCustomObject]@{
            Date                        = (Get-Date -UFormat "%B-%d-%Y|%T")
            AWSName                     = $AWSName
            Region                      = $Region
            NumofKeys                   = $KMSKEYSLISTCOUNT
            Key                         = $Key 
            Result                      = $Result}
            $PolicyList
            $PolicyList =@()
            $PolicyListOUT = $PolicyList
            
            try{$PolicyListOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'PolicyList'}
            catch{$_.Exception.Message | Export-Excel $filename  -WorksheetName 'ERROR'}

            } #  ForEach-Object { 
                  

        #[System.Reflection.Assembly]::LoadWithPartialName("System.Web.HttpUtility")
        #$policyjson  = [System.Web.HttpUtility]::UrlDecode($results.Document)

		$POLICY = Get-KMSKeyPolicyList  -KeyId $KEY
        $POLICY 
                
        $Result = Get-KMSKeyPolicy -KeyId $KEY -PolicyName $POLICY | ConvertFrom-Json 
        $Result.GetType()
        $policyjson  = [System.Web.HttpUtility]::UrlDecode($results.Document)
      
        $Resultversion = $Result.Version
        $ResultId      = $Result.Id
        $ResultStatement = $Result.Statement | Select Sid

        $ResultStatementSid                 = $Result.Statement.Sid
        $ResultStatementEffect              = $Result.Statement.Effect
        $ResultStatementPrincipal           = $Result.Statement.Principal 
        $ResultStatementAction              = $Result.Statement.Action
        $ResultStatementResource            = $Result.Statement.Resource
        
		    Get-KMSKeyPolicy -KeyId $KEY -PolicyName $POLICY | 
            ForEach-Object { 
            $KMSKeyPolicy               = [PSCustomObject]@{
            Date                        = (Get-Date -UFormat "%B-%d-%Y|%T")
            AWSName                     = $AWSName
            Region                      = $Region
            NumofKeys                   = $KMSKEYSLISTCOUNT
            Key                         = $Key 
            Policy                      = $Result
            Version                     = $ResultVersion
            Id                          = $ResultId
            Statement                   = $ResultStatement
            ResultStatement             = $ResultStatement 
            ResultStatementSid          = $ResultStatementSid                 
            ResultStatementEffect       = $ResultStatementEffect             
            ResultStatementPrincipal    = $ResultStatementPrincipal           
            ResultStatementAction       = $ResultStatementAction              
            ResultStatementResource     = $ResultStatementResource}
            $KMSKeyPolicy
            $KMSKeyPolicyOUT =@()
            $KMSKeyPolicyOUT = $KMSKeyPolicy
            
            try{$KMSKeyPolicyOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'KMSKeyPolicy'}
            catch{$_.Exception.Message | Export-Excel $filename  -WorksheetName 'ERROR'}

            } #  ForEach-Object { 

            # Gets a Boolean value that indicates whether automatic rotation of the key material 
            # is enabled for the specified KMS key. You cannot enable automatic rotation of 
            # asymmetric KMS keys, KMS keys with imported key material, or KMS keys in a custom 
            # key store. To enable or disable automatic rotation of a set of related multi-Region keys, 
            # set the property on the primary key. The key rotation status for these KMS keys
            # is always false. The KMS key that you use for this operation must be in a compatible key state. 
            
            $RotationStatus = Get-KMSKeyRotationStatus -KeyId $KEY 
            
            $RotationStatus |  
            ForEach-Object { 
            $KMSKeyRotationStatus   = [PSCustomObject]@{
            Date                    = (Get-Date -UFormat "%B-%d-%Y|%T")
            AWSName                 = $AWSName
            Region                  = $Region
            NumofKeys               = $KMSKEYSLISTCOUNT
            Key                     = $key
            RotationStatus          = $RotationStatus }
            $KMSKeyRotationStatus
            $KMSKeyRotationStatusOUT =@()
            $KMSKeyRotationStatusOUT = $KMSKeyRotationStatus
            
            try{$KMSKeyRotationStatusOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'KMSKeyRotationStatus'}
            catch{$_.Exception.Message | Export-Excel $filename  -WorksheetName 'ERROR'}

            } #  ForEach-Object { 


            # Returns all tags on the specified KMS key. 
            # For information about using tags in KMS, see Tagging keys. 
            # Cross-account use: No. 
            # You cannot perform this operation on a KMS key in a different Amazon Web Services account. 
            # Required permissions: kms:ListResourceTags (key policy) Related operations:
         
            $Tags = Get-KMSResourceTag -KeyId $Key 
            $Tags 
            if ($Tags -ne $null){
                Write-Output "It isn't empty:  $($Key)"
               
                Get-KMSResourceTag -KeyId $Key 
                ForEach-Object { 
                $KMSResourceTag         = [PSCustomObject]@{
                Date                    = (Get-Date -UFormat "%B-%d-%Y|%T")
                AWSName                 = $AWSName
                Region                  = $Region
                NumofKeys               = $KMSKEYSLISTCOUNT
                Key                     = $key}
                $KMSResourceTag
                $KMSResourceTagOUT =@()
                $KMSResourceTagOUT = $KMSResourceTag

                try{$KMSResourceTagOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'KMSResourceTag'}
                catch{$_.Exception.Message | Export-Excel $filename  -WorksheetName 'ERROR'}

                
                } #  ForEach-Object { 
                  } # end of IF
             else {
                  Write-Output "It's empty: $($Key)"
                  } # else {
		


        #
        #   You add your command above.
        #---------------------------------------------------------
           

        #------------------------------------------------------
       }  # foreach ( $Region in $Regions) {


# ------------------------------------------

try{Clear-AWSCredential}
catch{ Write-Host "Error occured" -BackgroundColor DarkRed} 

Start-Sleep 5


}

}
