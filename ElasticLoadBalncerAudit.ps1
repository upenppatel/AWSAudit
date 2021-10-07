function Get-ELBAudit {

    [CmdletBinding()]
    param(

    #The ValidateSet attribute enables you to specify a list of values allowed for the parameter.
    [Parameter(Mandatory)]
    [ValidateSet('123456789012:role/SecurityAuditor')]
    $Profile

    )

    # ----PROXY SETTING TO CONNECT TO AWS -----------------------------------------------------
    
	$webclient=New-Object System.Net.WebClient
    $webclient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    [Net.ServicePointManager]::SecurityProtocol = "tls12"
    
    $Port = 1234
    Set-AWSProxy -Hostname localhost -Port $PORT -Credential ([System.Net.CredentialCache]::DefaultCredentials)
    
	
	# ----------------------------------------------------------------------------------------------
	# https://signin.aws.amazon.com/switchrole

	$Accounts =     '111111111111', '222222222222'
	#-----------------------------------------------------------------------------------------------
		
    Write-Host "To run the function type Get-ELBAudit 123456789012:role/SecurityAuditor"
    
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
 
    $FileName = "C:\temp\ElasticLoadBalancer-Audit-$($D).xlsx"

    Write-Host "The Output of the script $FileName"
    
	Start-Sleep -Seconds 20
    
    $Date = (Get-Date -UFormat "%B-%d-%Y|%T")

    #--------------------------------------------------------------------------

    #----------------------------------------------------------------- 

    foreach($Account in $Accounts) {
    
	$Account
    
	    $Credentials = (Use-STSRole -RoleArn "arn:aws:iam::${Account}:role/SecurityAuditor" -RoleSessionName "MyRoleSessionName").Credentials
 
        try{ Set-AWSCredential - -Credential $Credentials
        $AWSNAME = Get-IAMAccountAlias}
        catch{
        Write-Warning "$_.Exception.Message"
        }
        Finally
        {
        Write-Host "Done with Aws Account: $AWSNAME " -ForegroundColor Green
        } 
    
        Get-IAMAccountAlias
        Start-Sleep -Seconds 5
		
        # Setting the Region 
        $Regions = "us-east-1", "us-west-2"

        # { Start with Region
        Foreach ($Region In $Regions) {  # { Start for Region  
   
            Set-DefaultAWSRegion $($Region) 
            
			$Region = (Get-DefaultAWSRegion).Region 

            #####################################################

            $Date = (Get-Date -UFormat "%B-%d-%Y|%T")

            $ELBCOUNT = (Get-ELB2LoadBalancer -Region $Region).Count 

            if( $ELBCOUNT  -ne 0) {
             
               $BalArns = (Get-ELB2LoadBalancer).LoadBalancerArn 
                 
               $Names = (Get-ELB2LoadBalancer).LoadBalancerName 
                       
               foreach( $BalArn in $BalArns) { 
               
                   $LNAME = (Get-ELB2LoadBalancer -LoadBalancerArn $BalArn).LoadBalancerName

                   Get-ELB2LoadBalancer | 
                   ForEach-Object { 
                   $ELB2LoadBalancer               = [PSCustomObject][ordered]@{
                   Date                            = (Get-Date -UFormat "%B-%d-%Y|%T")
                   AWSName                         = $AWSName
                   Region                          = $Region
                   LoadBalancerName                = $_.LoadBalancerName 
                   State                           = $_.State
                   AvailabilityZones               = $_.AvailabilityZones -join ", "
                   CanonicalHostedZoneId           = $_.CanonicalHostedZoneId
                   CreatedTime                     = $_.CreatedTime
                   CustomerOwnedIpv4Pool           = $_.CustomerOwnedIpv4Pool
                   DNSName                         = $_.DNSName
                   IpAddressType                   = $_.IpAddressType
                   LoadBalancerArn                 = $_.LoadBalancerArn
                   Scheme                          = $_.Scheme
                   SecurityGroups                  = $_.SecurityGroup
                   Type                            = $_.Type
                   VpcId                           = $_.VpcId}
               
                   $ELB2LoadBalancer
                   $ELB2LoadBalancerOUT = @()
                   $ELB2LoadBalancerOUT = $ELB2LoadBalancer
                   $ELB2LoadBalancer | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'ELB2LoadBalancer' 
                   } #  ForEach-Object {
                   
                   $A = Get-ELB2LoadBalancerAttribute -LoadBalancerArn $BalArn                 
                   Get-ELB2LoadBalancerAttribute -LoadBalancerArn $BalArn  |
                   ForEach-Object { 
                   $ELB2LoadBalancerAttribute      = [PSCustomObject][ordered]@{
                   Date                            = (Get-Date -UFormat "%B-%d-%Y|%T")
                   AWSName                         = $AWSName
                   Region                          = $Region
                   LoadBalancerName                = $LNAME
                   accesslogss3enabled             = ($A | Where {$_.Key -eq "access_logs.s3.enabled"}).Value
                   accesslogss3prefix              = ($A | Where {$_.Key -eq "access_logs.s3.prefix"}).Value
                   deletionprotectionenabled       = ($A | Where {$_.Key -eq "deletion_protection.enabled"}).Value
                   accesslogss3bucket              = ($A | Where {$_.Key -eq "access_logs.s3.bucket"}).Value   
                   loadbalancingcrosszoneenabled   = ($A | Where {$_.Key -eq "load_balancing.cross_zone.enabled"}).Value
                   }
                   $ELB2LoadBalancerAttribute
                   $ELB2LoadBalancerAttributeOUT = @()
                   $ELB2LoadBalancerAttributeOUT = $ELB2LoadBalancerAttribute
                   $ELB2LoadBalancerAttributeOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'ELB2LoadBalancerAttribute' 
                   } #  ForEach-Object {
                   
                   

                   Get-ELB2Listener -LoadBalancerArn $BalArn | 
                   ForEach-Object { 
                   $ELB2Listener                   = [PSCustomObject][ordered]@{
                   Date                            = (Get-Date -UFormat "%B-%d-%Y|%T")
                   AWSName                         = $AWSName
                   Region                          = $Region
                   LoadBalancerName                = $LNAME
                   AlpnPolicy                      = $_.AlpnPolicy
                   Certificates                    = $_.Certificates
                   DefaultActions                  = $_.DefaultActions
                   ListenerArn                     = $_.ListenerArn
                   LoadBalancerArn                 = $_.LoadBalancerArn
                   Port                            = $_.Port
                   Protocol                        = $_.Protocol
                   SslPolicy                       = $_.SslPolicy}
                   $ELB2Listener 
                   $ELB2ListenerOUT = @()
                   $ELB2ListenerOUT = $ELB2Listener 
                   $ELB2ListenerOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName '$ELB2Listener' 
                   } #  ForEach-Object {


                   Get-ELB2TargetGroup -LoadBalancerArn $BalArn | 
                   ForEach-Object { 
                   $ELB2TargetGroup                = [PSCustomObject][ordered]@{
                   Date                            = (Get-Date -UFormat "%B-%d-%Y|%T")
                   AWSName                         = $AWSName
                   Region                          = $Region
                   LoadBalancerName                = $LNAME
                   HealthCheckEnabled              = $_.HealthCheckEnabled
                   HealthCheckIntervalSeconds      = $_.HealthCheckIntervalSeconds
                   HealthCheckPath                 = $_.HealthCheckPath  
                   HealthCheckPort                 = $_.HealthCheckPort
                   HealthCheckProtocol             = $_.HealthCheckProtocol  
                   HealthCheckTimeoutSeconds       = $_.HealthCheckTimeoutSeconds
                   HealthyThresholdCount           = $_.HealthyThresholdCount  
                   LoadBalancerArns                = $_.LoadBalancerArns
                   Matcher                         = $_.Matcher 
                   Port                            = $_.Port
                   Protocol                        = $_.Protocol  
                   ProtocolVersion                 = $_.ProtocolVersion 
                   TargetGroupArn                  = $_.TargetGroupArn
                   TargetGroupName                 = $_.TargetGroupName
                   TargetType                      = $_.TargetType 
                   UnhealthyThresholdCount         = $_.UnhealthyThresholdCount
                   VpcId                           = $_.VpcId}   
                   $ELB2TargetGroup 
                   $ELB2TargetGroupOUT = @()
                   $ELB2TargetGroupOUT = $ELB2TargetGroup
                   $ELB2TargetGroupOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'ELB2TargetGroup' 
                   } #  ForEach-Object {                  

                   $TarArn = (Get-ELB2TargetGroup -LoadBalancerArn $BalArn).TargetGroupArn 
                   $TarArn

                   $T = Get-ELB2TargetGroupAttribute -TargetGroupArn $TarArn
                   Get-ELB2TargetGroup -LoadBalancerArn $BalArn | 
                   ForEach-Object { 
                   $ELB2TargetGroupAttribute                = [PSCustomObject][ordered]@{
                   Date                            = (Get-Date -UFormat "%B-%d-%Y|%T")
                   AWSName                         = $AWSName
                   Region                          = $Region
                   LoadBalancerName                = $LNAME
                   TargetGroupArn                  = $TarArn
                   'preserveclientipenabled'    = ($T | Where {$_.Key -eq "proxy_protocol_v2.enabled"}).Value
                   'proxyprotocolv2enabled'     = ($T | Where {$_.Key -eq "preserve_client_ip.enabled"}).Value
                   'stickinessenabled'            = ($T | Where {$_.Key -eq "stickiness.enabled"}).Value
                   'deregistrationdelaytimeoutseconds'= ($T | Where {$_.Key -eq "deregistration_delay.timeout_seconds"}).Value
                   'stickinesstype'               = ($T | Where {$_.Key -eq "stickiness.type"}).Value
                   'deregistrationdelayconnectionterminationenabled'= ($T | Where {$_.Key -eq "deregistration_delay.connection_termination.enabled"}).Value
                   }
                   $ELB2TargetGroupAttribute 
                   $ELB2TargetGroupAttributeOUT = @()
                   $ELB2TargetGroupAttributeOUT = $ELB2TargetGroupAttribute
                   $ELB2TargetGroupAttributeOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'ELB2TargetGroupAttribute' 
                   } #  ForEach-Object {                 
                         

                   
     
             } # foreach( $BalArn in $BalArns) { 
    
    } # if( $ELBCOUNT  -ne 0) {
    
    else 
    { 
    Write-Host "$AWSName $Region does not have the Elastic Load Balancer" | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'NOELB' 
    }
   
   
        
 
	
		
        ###############################################################################
        # ---------- END OF REGIONS FOREACH --------
  
        }
 
   #####################################################################
   # -------- END OF EACH  AWS Account PROFILE -----------------

    Clear-AWSCredential 
 
    Start-Sleep 5
    }


# ------------------------------------------
# End for the function

}



