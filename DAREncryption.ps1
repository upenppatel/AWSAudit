#--------------------------------------------------------------
# Create our various Excel parameters

$params = @{
    # Spreadsheet Properties
    Path                 = $path
    BoldTopRow           = $true
    FreezeTopRow         = $true
    AutoSize             = $true
    Append               = $true
    #ConditionalFormat    = $IconSet
    PassThru             = $true
}  
$params

$ErroAtionPreference = 'Continue'
#-----------------------------------------------------------------------------
# EXCEL FORMAT 
$T1 = New-ConditionalText -Text 'Effective' -ConditionalTextColor DarkGreen -BackgroundColor Cyan
$T2 = New-ConditionalText -Text 'Ineffective' -ConditionalTextColor DarkRed -BackgroundColor LightPink
$T3 = New-ConditionalText -Text 'True'  -ConditionalTextColor DarkGreen -BackgroundColor Cyan
$T4 = New-ConditionalText -Text 'False' -ConditionalTextColor DarkRed -BackgroundColor LightPink
$T5 = New-ConditionalText -Text 'us-east-1' -ConditionalTextColor DarkBlue -BackgroundColor White
$T6 = New-ConditionalText -Text 'us-west-2' -ConditionalTextColor DarkBlack -BackgroundColor White

# -ConditionalFormat $T1,$T2,$T3,$T4.$T5,$6
#-------------------------------------------------------------------------------

# OUTPUT FILE: 
$D = (Get-Date -Format "MM-dd-yyyy")

$FileName = "C:\Temp\DAR-Encryption-Audit-$($D).xlsx"


# ----PROXY SETTING TO CONNECT TO AWS -----------------------------------------------------
    
	$webclient=New-Object System.Net.WebClient
    $webclient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    [Net.ServicePointManager]::SecurityProtocol = "tls12"
    $Port  = 1234
    Set-AWSProxy -Hostname localhost -Port 1234  -Credential ([System.Net.CredentialCache]::DefaultCredentials)
# ----------------------------------------------------------------------------------------------
	# https://signin.aws.amazon.com/switchrole?account=account_id_number&roleName=role_name&displayName=text_to_display
	$Accounts =     '111111111111', '222222222222' 
    #-----------------------------------------------------------------------------------------------

    Start-Sleep -Seconds 5
    
    #  NOW CONNECTING TO AWS Master Account
	try{
    
    Set-AWSCredential -ProfileName 123456789012:role/SecurityAuditor -ErrorAction Stop
    
    $AWSNAME = Get-IAMAccountAlias
    }
    catch{
    Write-Warning "$_.Exception.Message"
    }
    Finally{
    Write-Host "Done with Aws Account: $AWSNAME " -ForegroundColor Green
    } 
 
    Start-Sleep -Seconds 10
	
	$Accounts 
#------------------------------------------------------------------------------


#-----------------SCRIPT START -------------------------------------

foreach($Account in $Accounts) {
    
	    $Account
    
	    try{$Credentials = (Use-STSRole -RoleArn "arn:aws:iam::${Account}:role/SecurityAuditor" -RoleSessionName "MyRoleSessionName").Credentials}
        catch{Write-Warning "$_.Exception.Message"}
        
        $Credentials
        
        $AccessKeyId = $Credentials.AccessKeyId
        $SecretAccessKey = $Credentials.SecretAccessKey
        $SessionToken = $Credentials.SessionToken
        $Expiration = $Credentials.Expiration
        
        Write-Host "$AccessKeyId" -ForegroundColor Blue
        Write-Host "$SecretAccessKey" -ForegroundColor Blue
        Write-Host "$SessionToken"  -ForegroundColor Blue
        Write-Host "$Expiration" -ForegroundColor Blue

        try{ Set-AWSCredential - -Credential $Credentials
        $AWSNAME = Get-IAMAccountAlias}
        catch{Write-Warning "$_.Exception.Message"}
        Finally{Write-Host "Done with Aws Account: Get-IAMAccountAlias" -ForegroundColor Green} 
    
        Get-IAMAccountAlias
        Start-Sleep -Seconds 5
		
        #---------------------------------------------------------------------------------

        # --------------------S3Buckets -----------------------------------------------------
    $Buckets = (Get-S3Bucket).BucketName

    foreach($Bucket in $Buckets) { 
        $iBucket = ("$Bucket")
        $iBucket 

        try{$BucketList =  (Get-S3Bucket).BucketName | Where {$_ -clike "*$Region*" }}
        catch{$_.Exception.Message |  Export-Excel  $filename -AutoSize  -Append -WorksheetName 'ERROR'}
	        
        try{$BucketRegion = (Get-S3BucketLocation -BucketName $Bucket).Value}
        catch [system.exception] { Write-Output "Error: Get-S3BucketLocation $AWSNAME $Bucket" $_.Exception.Message | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'ERROR'}
        if ($BucketRegion -eq "") {
        $Location = 'us-east-1'

            $tags = (Get-S3BucketTagging -BucketName $Bucket)
           
        
		    try{Get-S3BucketTagging -BucketName $Bucket -Region us-east-1 | 
            ForEach-Object { 
            $S3BucketTagging        = [PSCustomObject]@{
            Date                    =  (Get-Date -UFormat "%B-%d-%Y|%T")
            AWSName                 = $AWSName
            Region                  = 'us-east-1'
            BucketName              = $Bucket}
           $S3BucketTagging 
           $S3BucketTaggingout =@()
           $S3BucketTaggingout = $S3BucketTagging
           $S3BucketTaggingout | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'S3Tags'
           }  # Foreach-Object  {  
           }  # try
           catch [system.exception] {Write-Output "Error: Get-S3BucketEncryption $AWSNAME $Bucket" $_.Exception.Message | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'ERROR'}
           
           (Get-S3BucketEncryption -BucketName $Bucket).ServerSideEncryptionRules |  
	       ForEach-Object { 
	            $S3BucketEncryption = [PSCustomObject]@{
	            Date                          = (Get-Date -UFormat "%B-%d-%Y|%T")
	            AWSName                       = $AWSName
	            Region                        = $Region
	            BucketName                    = $Bucket
	            ServerSideEncryptionByDefault = $_.ServerSideEncryptionByDefault
                S3BucketResult   = if ( $_.ServerSideEncryptionByDefault -like 'Amazon.S3.Model.ServerSideEncryptionByDefault') {"Effective"} else {"Ineffective"}
	            BucketKeyEnabled           = $_.BucketKeyEnabled}           
	            $S3BucketEncryption
	            $S3BucketEncryptionOUT =@()
	            $S3BucketEncryptionOUT = $S3BucketEncryption
	            $S3BucketEncryptionOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'S3buckets'
	            } #ForEach-Object { 
	          
           
           } # End of If
           else 
           {
           $Location = 'us-west-2'	       
           
           
          
           try{Get-S3BucketTagging -BucketName $Bucket -Region us-west-2 | 
           ForEach-Object { 
           $S3BucketTagging        = [PSCustomObject]@{
           Date                    =  (Get-Date -UFormat "%B-%d-%Y|%T")
           AWSName                 = $AWSName
           Region                  = 'us-west-2'
           BucketName              = $Bucket}
           $S3BucketTagging 
           $S3BucketTaggingout =@()
           $S3BucketTaggingout = $S3BucketTagging
           $S3BucketTaggingout | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'S3Tags'
           } # Foreach-Object  {  
           }  # try
           catch [system.exception] {Write-Output "Error: Get-S3BucketEncryption $AWSNAME $Bucket" $_.Exception.Message | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'ERROR'}
           
           (Get-S3BucketEncryption -BucketName $Bucket).ServerSideEncryptionRules |  
	       ForEach-Object { 
	            $S3BucketEncryption = [PSCustomObject]@{
	            Date                          =  (Get-Date -UFormat "%B-%d-%Y|%T")
	            AWSName                       = $AWSName
	            Region                        = $Region
	            BucketName                    = $Bucket
	            ServerSideEncryptionByDefault = $_.ServerSideEncryptionByDefault
                S3BucketResult   = if ( $_.ServerSideEncryptionByDefault -like 'Amazon.S3.Model.ServerSideEncryptionByDefault') {"Effective"} else {"Ineffective"}
	            BucketKeyEnabled           = $_.BucketKeyEnabled}           
	            $S3BucketEncryption
	            $S3BucketEncryptionOUT =@()
	            $S3BucketEncryptionOUT = $S3BucketEncryption
	            $S3BucketEncryptionOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'S3buckets'
	            } #ForEach-Object { 
           
           } # End of Else
				
          }




        #----------------------------------------------------------------------

        # We are only using these two Regions.

        $Regions = "us-east-1", "us-west-2"

        # { START OF REGIONS FOREACH 
        foreach ( $Region in $Regions) 
        {

        Set-DefaultAWSRegion -Region $Region
  
        $AWSName = Get-IAMAccountAlias
        $Region  = (Get-DefaultAWSRegion).Region 
        $Date = (Get-Date -Format "MM/dd/yyyy") 
     
    # -------------------------------------------------
        try{Get-EC2Volume -Verbose| Export-Excel  $filename -AutoSize -AutoFilter -Append -WorksheetName 'VPC'}
        catch{$_.Exception.Message |  Export-Excel  $filename -AutoSize  -Append -WorksheetName 'ERROR'}
        
        $EC2VolumeCount = (Get-EC2Volume).Count
        Get-EC2Volume -Verbose |  
	    ForEach-Object { 
	        $EC2VolumeEncrypt       = [PSCustomObject]@{
	        Date                    = (Get-Date -UFormat "%B-%d-%Y|%T")
	        AWSName                 = $AWSName
	        Region                  = $Region
            VolumeCountRegion       = $EC2VolumeCount
	        VolumeId                = $_.VolumeId
	        VolumeType              = $_.VolumeType
	        Attachments             = $_.Attachment
	        Encrypted               = $_.Encrypted
            VolumeResult            = if ($_.Encrypted -eq "True") {"Effective"} else {"Ineffective"}
	        KmsKeyId                = $_.KmsKeyId}
            $EC2VolumeEncrypt
            $EC2VolumeEncryptOUT    = @()
	        $EC2VolumeEncryptOUT    = $EC2VolumeEncrypt	 
            try{$EC2VolumeEncryptOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'EC2Volume'}
            catch{$_.Exception.Message |  Export-Excel  $filename -AutoSize  -Append -WorksheetName 'ERROR'}
            }
	
	    
	    
	    # -----------------------------------------------------------
        $DBInstances = (Get-RDSDBInstance).DBInstanceIdentifier
        $DBInstances 
        $DBInstanceCount =  ($DBInstances).Count
        $DBInstanceCount
     
        foreach($I in (Get-RDSDBInstance).DBInstanceIdentifier) {
	            
	        Get-RDSDBInstance -DBInstanceIdentifier $I | 
.	        Foreach-Object  { 
	        $RDSDB                 = [PSCustomObject]@{
	        Date                   =  (Get-Date -UFormat "%B-%d-%Y|%T")
	        AWSName                = $AWSName
	        Region                 = $Region
            DBInstanceCount        = $DBInstanceCount
	        RDSDB                  = $I
	        AllocatedStorage       = $_.AllocatedStorage                       
	        AssociatedRoles        = $_.AssociatedRoles                                              
	        StorageEncrypted       = $_.StorageEncrypted
            RDSStorageResult       = if ( $_.StorageEncrypted -eq "TRUE") {"Effective"} else {"Ineffective"}                         
	        StorageType            = $_.StorageType                                                            
	        VpcSecurityGroups      = $_.VpcSecurityGroups}
	        $RDSDB 
	        $RDSDBOUT =@()
	        $RDSDBOUT = $RDSDB
	        $RDSDBOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'RDSDB' 
	        } # Foreach-Object  { 
	    } # foreach($I in (Get-RDSDBInstance).DBInstanceIdentifier { 

        #--------------------------------------------------------------------
        $EC2Snapshot = (Get-EC2snapshot -Owner self)
        $EC2snapshotCount = ($EC2snapshot).count
        $EC2snapshotCount
        <#
        Get-EC2Snapshot -Owner self | 
            Foreach-Object  { 
	        $EC2Snapshot               = [PSCustomObject]@{
	        Date                       =  (Get-Date -UFormat "%B-%d-%Y|%T")
	        AWSName                    = $AWSName
	        Region                     = $Region
	        SnapshotId                 = $_.SnapshotId
            State                      = $_.State
            Encrypted                  = $_.Encrypted
            EC2SnapshotResult          = if ($_.Encrypted -eq "True") {"Effective"} else {"Ineffective"}
            KmsKeyId                   = $_.KmsKeyId
            StartTime                  = $_.StartTime
            VolumeId                   = $_.VolumeId}
            $EC2Snapshot 
	        $EC2SnapshotOUT =@()
	        $EC2SnapshotOUT= $EC2Snapshot
	        $EC2SnapshotOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'EC2SnapShot'              
	        } # Foreach-Object  { 
        #>

        # ---------------------------------------------------------------
        $RDSDBSnapshot = (Get-RDSDBSnapshot)
        $RDSDBSnapshotCount = ($RDSDBSnapshot).count
                
	    Get-RDSDBSnapshot  | 
            Foreach-Object  { 
	        $RDSDBSnapshot             = [PSCustomObject]@{
	        Date                       =  (Get-Date -UFormat "%B-%d-%Y|%T")
	        AWSName                    = $AWSName
	        Region                     = $Region
            RDSDBSnapshotCount         = $RDSDBSnapshotCount
            DBSnapshotIdentifier       = $_.DBInstanceIdentifier
            DBSnapshorArn              = $_.DBSnapshotArn
            SnapshotCreateTime         = $_.SnapshotCreationTime
            SnapshotType               = $_.SnapshotType
            Encrypted                  = $_.Encrypted
            RDSSnapShotResult          = if ($_.Encrypted -eq "True") {"Effective"} else {"Ineffective"}
            Engine                     = $_.Engine
            EngineVersion              = $_.EngineVersion
            KmsKeyId                   = $_.KmsKeyId
            StorageType                = $_.StorageType
            VpcId                      = $_.VpcId}
            $RDSDBSnapshot 
	        $RDSDBSnapshotOUT =@()
	        $RDSDBSnapshotOUT=  $RDSDBSnapshot
	        $RDSDBSnapshotOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'RDSDBSnapShot' 
            } # Foreach-Object  { 


            #------------------------------------------------------------

            $FireHose = (Get-KINFDeliveryStreamList).DeliveryStreamNames
            $FireHoseCount  = ($FireHose).Count

         foreach ( $I in (Get-KINFDeliveryStreamList).DeliveryStreamNames) { 
                  $I

            try{(Get-KINFDeliveryStream -DeliveryStreamName $I).DeliveryStreamEncryptionConfiguration}
            catch [system.exception] { Write-Output "Error:Get-KINFDeliveryStream -DeliveryStreamName $I" $_.Exception.Message |  Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'Error'  -ConditionalFormat $T1,$T2,$T3,$T4,$T5}
            
            $Status= ((Get-KINFDeliveryStream -DeliveryStreamName $I -Verbose).DeliveryStreamEncryptionConfiguration).Status.Value
            $StatusResult =  If($Status -eq "ENABLED") {"effective"} else {"Ineffective"} 
            $StatusResult

            $KeyType = ((Get-KINFDeliveryStream -DeliveryStreamName $I -Verbose).DeliveryStreamEncryptionConfiguration).KeyType.Value
            $KeyArn = ((Get-KINFDeliveryStream -DeliveryStreamName $I -Verbose).DeliveryStreamEncryptionConfiguration).KeyARN.Value
            $FailureDescription = ((Get-KINFDeliveryStream -DeliveryStreamName $I -Verbose).DeliveryStreamEncryptionConfiguration).FailureDescription.Value
            $Status
            $KeyType
            $KeyArn
            $FailureDescription
            
            Get-KINFDeliveryStream -DeliveryStreamName $I | 
            ForEach-Object { 
                $FIREHOSEDeliveryStream       = [PSCustomObject]@{
                Date                                        = $Date
                AWSName                                     = $AWSName
                Region                                      = $Region
                FireHoseStreamName                          = $I
                DAREncryption                               = $StatusResult
                CreateTimestamp                      	    = $_.CreateTimestamp                      
                DeliveryStreamARN                     		= $_.DeliveryStreamARN                     
                DeliveryStreamEncryptionConfiguration 		= $_.DeliveryStreamEncryptionConfiguration 
                EncryptionStatus                            = $Status
                EncryptionKeyType                           = $KeyType
                EncryptionKeyArn                            = $KeyArn
                EncryptionFailureDescription                = $FailureDescription
                DeliveryStreamName                    		= $_.DeliveryStreamName                    
                DeliveryStreamStatus                  		= $_.DeliveryStreamStatus                  
                DeliveryStreamType                   		= $_.DeliveryStreamType                   
                Destinations                          		= $_.Destinations                          
                FailureDescription                    		= $_.FailureDescription                    
                HasMoreDestinations                  		= $_.HasMoreDestinations                  
                LastUpdateTimestamp                  		= $_.LastUpdateTimestamp                  
                Source                                		= $_.Source                                
                VersionId  		                            = $_.VersionId}
                $FIREHOSEDeliveryStream
                $FIREHOSEDeliveryStreamout = @()
                $FIREHOSEDeliveryStreamout = $FIREHOSEDeliveryStream
                try{$FIREHOSEDeliveryStreamout | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'FIREHOSE' -ConditionalFormat $T1,$T2,$T3,$T4,$T5}
                catch [system.exception] { Write-Output "Error:" $_.Exception.Message | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'ERROR'}
                } # ForEach-Object 
                } #foreach ( $I in (Get-KINFDeliveryStreamList).DeliveryStreamNames) { 

                # ---------------------------------------------------

                
        foreach( $i in (Get-KINStreamList).StreamNames) {
            
		    $STATUS = (Get-KINStream -StreamName $I).EncryptionType.Value
            $StatusResult =  If($Status -eq "KMS") { "effective"} else { "Ineffective"}  
            $StatusResult 

            Get-KINStream -StreamName $i | 
            ForEach-Object { 
                $KINStream               = [PSCustomObject]@{
                Date                      = $Date
                AWSName                   = $AWSName
                Region                    = $Region
                StreamName                = $_.StreamName
                EncryptionType            = $_.EncryptionType
                DAREncryption             = $StatusResult
                StreamCreationTimeStamp   = $_.StreamCreationTimestamp
                StreamStatus              = $_.StreamStatus
                StreamARN                 = $_.StreamARN 
                RetentionPeriodHours      = $_.RetentionPeriodHours
                Shards                    = $_.Shards
                HasMoreShards             = $_.HasMoreShards
                EnhancedMonitoring        = $_.EnhancedMonitoring
                KeyId                     = $_.KeyId}
                $KinStreamout =@()
                $KinStreamout = $KinStream
                try{$KinStreamout | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'StreamNames' -ConditionalFormat $T1,$T2,$T3,$T4,$T5}
                catch [system.exception] { Write-Output "Error:" $_.Exception.Message | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'ERROR'}
                $KinStream
            } # ForEach-Object { 
        } #  Get-KINStream -StreamName $i

        # --------------------------- Elasticache --------------------------------
        #  AWS Elasticache
        # 
               Get-ECCacheCluster |
               ForEach-Object { 
               $ECCacheCluster                   = [PSCustomObject]@{
               Date                              = (Get-Date -UFormat "%B-%d-%Y|%T")
               AWSName                            = $AWSName
               Region                             = $Region
               Arn                                = $_.Arn
               AtRestEncryptionEnabled            = $_.AtRestEncryptionEnabled
               EncryptionDataAtRest               = If($_.AtRestEncryptionEnabled -eq "True"){"Effective"} else {"Ineffective"}
               TransitEncryptionEnabled           = $_.TransitEncryptionEnabled
               EncryptionInTransit                = If($_.TransitEncryptionEnabled -eq "True"){"Effective"} else {"Ineffective"}
               }
               $ECCacheCluster
               $ECCacheClusterout =@()
               $ECCacheClusterout = $ECCacheCluster
               try{$ECCacheClusterout | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'ECCacheCluster' -ConditionalFormat $T1,$T2,$T3,$T4,$T5}
               catch [system.exception] { Write-Output "Error:" $_.Exception.Message | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'ERROR'}
                
               } # ForEach-Object { 

        # --------------------------------------------------------------------------
        


      
        # ---------- END OF REGIONS FOREACH --------
        }
 
# -------- END OF EACH PROFILE -----------------

 Clear-AWSCredential 
 
 Start-Sleep 5

}

                                   
             