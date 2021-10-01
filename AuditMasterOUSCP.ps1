$webclient=New-Object System.Net.WebClient
$webclient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
[Net.ServicePointManager]::SecurityProtocol = "tls12"
$PORT = 1234
Set-AWSProxy -Hostname localhost -Port $PORT -Credential ([System.Net.CredentialCache]::DefaultCredentials)


Import-Module -Name ImportExcel

# https://aws-cli-eq-pwsh.shibata.tech/organizations/
#
Set-AWSCredential -ProfileName 12345678912:role/SecurityAuditor
                                          
#----------------------------------------------------------------------
    
# OUTPUT FILE: 
    
$D = (Get-Date -Format "MM-dd-yyyy")
 
$FileName = "C:\TEMP\Master-OU-SCP-Audit-$($D).xlsx"
    
$Date = (Get-Date -UFormat "%B-%d-%Y|%T")

Set-AWSCredential -ProfileName 123456789012:role/SecurityAuditor

$AWSName = Get-IAMAccountAlias

Set-DefaultAWSRegion -Region us-east-1

$Region = (Get-DefaultAWSRegion).Region 

#--------------------------------------------------------------------------

try{Get-ORGOrganization}
catch{" $_.Exception.Message" |Export-Excel $FileName -AutoSize -Append -WorksheetName 'ERROR'}

catch[system.exception]{Write-Output"Error:" $_.Exception.Message |Export-Excel $FileName -AutoSize -Append -WorksheetName 'ERROR'}

# Retrieves information about the organization that the user's account belongs to. 
# This operation can be called from any account in the organization.
Get-ORGOrganization |
    ForEach-Object { 
    $ORGOrganization      = [PSCustomObject]@{
    Date                               = (Get-Date -UFormat "%B-%d-%Y|%T")
    AWSName                            = $AWSName
    Id                                 = $_.Id
    MasterAccount                      = $_.MasterAccountArn
    MasterAccountId                    = $_.MasterAccountId
    MasterAccountEmail                 = $_.MasterAccountEmail
    FeatureSet                         = $_.FeatureSet
    Arn                                = $_.Arn
    AvailablePolicyTypes               = $_.AvailablePolicyTypes} 
    $ORGOrganization  
    $ORGOrganizationOUT = @()
    $ORGOrganizationOUT = $ORGOrganization
    $ORGOrganizationOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'Master' 
            } #  ForEach-Object {

try{Get-ORGRoot}
catch{" $_.Exception.Message" |Export-Excel $FileName -AutoSize -Append -WorksheetName 'ERROR'}
# Lists the roots that are defined in the current organization.

$Root = Get-ORGRoot  
# r-mhfd

$RootOUId = $Root.Id
$RootOUId

$OURoot = New-Object -TypeName System.Management.Automation.PSObject -Property ([ordered]@{
   Date     = (Get-Date -UFormat "%B-%d-%Y|%T")
   AWSName  = $AWSName
   RootId   = $Root.Id
   Name     = $Root.Name
   PolicyType = $Root.PolicyTypes
   Arn        = $Root.Arn
   })

$OURoot |Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'ROOT' 

#-------------------------------------------------------------------------------

$RootId = (Get-ORGRoot).ID
$RootId 


try{$ChildOUs = Get-ORGOrganizationalUnitList -ParentId $RootId}
catch{" $_.Exception.Message" |Export-Excel $FileName -AutoSize -Append -WorksheetName 'ERROR'}
$ChildOUs

Get-ORGOrganizationalUnitList -ParentId $RootId |          
    ForEach-Object { 
    $ORGOrganizationalUnitList         = [PSCustomObject]@{
    Date                               = (Get-Date -UFormat "%B-%d-%Y|%T")
    AWSName                            = $AWSName
    Name                               = $_.Name
    Id                                 = $_.Id
    Arn                                = $_.Arn}
    $ORGOrganizationalUnitList
    $ORGOrganizationalUnitListOUT = @()
    $ORGOrganizationalUnitListOUT = $ORGOrganizationalUnitList
    $ORGOrganizationalUnitListOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'ChildOU' 
    } #  ForEach-Object {

# ----------------------------------------------------------------------------
try{$ChildOUs = Get-ORGOrganizationalUnitList -ParentId $RootId}
catch{" $_.Exception.Message" |Export-Excel $FileName -AutoSize -Append -WorksheetName 'ERROR'}

foreach( $ChildOUId in $ChildOUIds) {
Get-ORGAccountForParent -ParentId $ChildOUId | 
    ForEach-Object { 
    $ORGAccountForParent               = [PSCustomObject]@{
    Date                               = (Get-Date -UFormat "%B-%d-%Y|%T")
    AWSName                            = $AWSName
    ChildOUId                          = $ChildOUId
    Name                               = $_.Name
    Id                                 = $_.Id
    Email                              = $_.Email
    JoinedMethod                       = $_.JoinedMethod
    JoinedTimeStamp                    = $_.JoinedTimestamp
    Status                             = $_.Status
    Arn                                = $_.Arn}
    $ORGAccountForParent
    $ORGAccountForParentOUT = @()
    $ORGAccountForParentOUT = $ORGAccountForParent
    $ORGAccountForParentOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'ORGAccountForParent' 
    } # ForEach-Object 
}

# --------------------------------------------------------------------------------------

# Calls the AWS Organizations ListAWSServiceAccessForOrganization API operation.
# Returns a list of the AWS services that you enabled to integrate with your organization. # After a service on this list creates the resources that it requires for the integration, 
# it can perform operations on your organization and its accounts. # For more information about integrating other services with AWS Organizations, including the list of services that currently work with Organizations, 
# see Integrating AWS Organizations with Other AWS Services in the AWS Organizations User Guide. This operation can be called only from the organization's master account. 

# Get-ORGAWSServiceAccessForOrganization
try{Get-ORGAWSServiceAccessForOrganization}
catch{" $_.Exception.Message" |Export-Excel $FileName -AutoSize -Append -WorksheetName 'ERROR'}

Get-ORGAWSServiceAccessForOrganization | 
    ForEach-Object { 
    $ORGAWSServiceAccessForOrganization   = [PSCustomObject]@{
    Date                               = (Get-Date -UFormat "%B-%d-%Y|%T")
    AWSName                            = $AWSName
    ServicePrincipal                   = $_.ServicePrincipal
    DateEnabled                        = $_.DateEnabled}
    $ORGAWSServiceAccessForOrganization
    $ORGAWSServiceAccessForOrganizationOUT = @()
    $ORGAWSServiceAccessForOrganizationOUT = $ORGAWSServiceAccessForOrganization
    $ORGAWSServiceAccessForOrganizationOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'ServiceAccess' 
            } #  ForEach-Object {

# --------------------------------------------------------------------

# GeRetrieves the list of all policies in an organization of a specified type. 
# Always check the NextToken response parameter for a null value when calling a List* operation. 
# These operations can occasionally return an empty set of results even when there are more results available. 
# The NextToken response parameter value is nullonly when there are no more results to display. 
# This operation can be called only from the organization's master account. t-ORGPolicyList -Filter SERVICE_CONTROL_POLICY   
# Get-ORGPolicyList -Filter SERVICE_CONTROL_POLICY

try{Get-ORGPolicyList -Filter SERVICE_CONTROL_POLICY}
catch{" $_.Exception.Message" |Export-Excel $FileName -AutoSize -Append -WorksheetName 'ERROR'}

Get-ORGPolicyList -Filter SERVICE_CONTROL_POLICY | 
    ForEach-Object { 
    $SERVICE_CONTROL_POLICY   = [PSCustomObject]@{
    Date                               = (Get-Date -UFormat "%B-%d-%Y|%T")
    AWSName                            = $AWSName
    Name                               = $_.Name
    Id                                 = $_.Id
    Description                        = $_.Description
    Type                               = $_.Type
    AwsManaged                         = $_.AwsManaged
    Arn                                = $_.Arn}
    $SERVICE_CONTROL_POLICY
    $SERVICE_CONTROL_POLICYOUT = @()
    $SERVICE_CONTROL_POLICYOUT = $SERVICE_CONTROL_POLICY
    $SERVICE_CONTROL_POLICYOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'SCPOLICY' 
     } #  ForEach-Object {

#--------------------------------------------------------------------------

(Get-ORGPolicyList -Filter SERVICE_CONTROL_POLICY).ID

$SCPIds = (Get-ORGPolicyList -Filter SERVICE_CONTROL_POLICY).ID
try{$SCPIds = (Get-ORGPolicyList -Filter SERVICE_CONTROL_POLICY).ID}
catch{" $_.Exception.Message" |Export-Excel $FileName -AutoSize -Append -WorksheetName 'ERROR'}

$SCPIds

foreach($I in $SCPIds)  {
  
    Get-ORGTargetForPolicy -PolicyId $I |
    ForEach-Object {
    $ORGTargetForPolicy   = [PSCustomObject]@{
    Date                               = (Get-Date -UFormat "%B-%d-%Y|%T")
    AWSName                            = $AWSName
    Name                               = $_.Name
    TargetId                           = $_.TargetId
    Type                               = $_.Type
    Arn                                = $_.Arn}
    $ORGTargetForPolicy
    $ORGTargetForPolicyOUT = @()    
    $ORGTargetForPolicyOUT = $ORGTargetForPolicy 
    $ORGTargetForPolicyOUT | Export-Excel $FileName -AutoSize -AutoFilter -Append -WorksheetName 'ORGTargetPolicy'
    } #  ForEach-Object {

    }

# ---------------------------------------------------------------

try{$SCPIds = (Get-ORGPolicyList -Filter SERVICE_CONTROL_POLICY).ID}
catch{" $_.Exception.Message" |Export-Excel $FileName -AutoSize -Append -WorksheetName 'ERROR'}

$SCPIds

foreach($I in $SCPIds)  {
  
   $Content = Get-ORGPolicy -PolicyId $I 
   $Content.Content
   $Content.PolicySummary

   $Contentjson = $Content.Content
   $ContentObj = ConvertFrom-Json -InputObject $Contentjson 

   Get-ORGPolicy -PolicyId $I | 
   ForEach-Object {
   $ORGPOLICYSCP       = [PSCustomObject]@{
   Date                               = (Get-Date -UFormat "%B-%d-%Y|%T")
   AWSName                            = $AWSName
   ORGPolicyId                        = $Content.PolicySummary.Id
   ORGPolicyName                      = $Content.PolicySummary.Name
   ORGPolicyDescription               = $Content.PolicySummary.Description
   ORGPolicyType                      = $Content.PolicySummary.Type
   ORGPolicyAwsManaged                = $Content.PolicySummary.AwsManaged
   ORGPolicyVersion                   = $ContentObj.Version 
   ORGPolicySid                       = $ContentObj.Statement.sid -join ', '
   ORGPolicyEffect                    = $ContentObj.Statement.Effect -join ', ' 
   ORGPolicyAction                    = $ContentObj.Statement.Action -join ', '
   ORGPolicyResource                  = $ContentObj.Statement.Resource -join ', '
   ORGPolicyArn                       = $Content.PolicySummary.Arn
   Content                            = $_.Content -join ', '}
   $ORGPOLICYSCP    
   $ORGPOLICYSCPOUT = @()
   $ORGPOLICYSCPOUT = $ORGPOLICYSCP   
   $ORGPOLICYSCPOUT | Export-Excel $FileName -AutoSize -Append -WorksheetName 'OrgPolicySCP' 
   } #  ForEach-Object {
    
}
# --------------------------------------------------------

$RootId = (Get-ORGRoot).ID
$RootId 

try{Get-ORGPolicyForTarget -TargetId  $RootId  -Filter SERVICE_CONTROL_POLICY}
catch{" $_.Exception.Message" |Export-Excel $FileName -AutoSize -Append -WorksheetName 'ERROR'}

Get-ORGPolicyForTarget -TargetId  r-mhfd -Filter SERVICE_CONTROL_POLICY | 
ForEach-Object {
   $ORGPolicyForTarget        = [PSCustomObject]@{
   Date                       = (Get-Date -UFormat "%B-%d-%Y|%T")
   AWSName                    = $AWSName
   ChildOUId                  = $RootId
   NameofOU                   = RootOU 
   PolicyId                   = $_.Id
   Name                       = $_.Name
   Description                = $_.Description 
   Type                       = $_.Type
   AwsManaged                 = $_.AwsManaged
   Arn                        = $_.Arn}
   $ORGPolicyForTarget   
   $ORGPolicyForTargetOUT = @()
   $ORGPolicyForTargetOUT = $ORGPolicyForTarget    
   $ORGPolicyForTargetOUT | Export-Excel $FileName -AutoSize -Append -WorksheetName 'ORGPolicyForTarget' 
   } #  ForEach-Object {


#-----------------------------------------------------

try{$ChildOUIds = (Get-ORGOrganizationalUnitList -ParentId $RootId).Id}
catch{" $_.Exception.Message" |Export-Excel $FileName -AutoSize -Append -WorksheetName 'ERROR'}


foreach( $ChildOUId in $ChildOUIds) {

   $NameOfOU = (Get-ORGOrganizationalUnit -OrganizationalUnitId $ChildOUId).Name
   
   $NameOfOU

   Get-ORGPolicyForTarget -TargetId $ChildOUId -Filter SERVICE_CONTROL_POLICY |
   ForEach-Object {
   $ORGPolicyForTarget        = [PSCustomObject]@{
   Date                       = (Get-Date -UFormat "%B-%d-%Y|%T")
   AWSName                    = $AWSName
   ChildOUId                  = $ChildOUId
   NameofOU                   = $NameOfOU
   PolicyId                   = $_.Id
   Name                       = $_.Name
   Description                = $_.Description 
   Type                       = $_.Type
   AwsManaged                 = $_.AwsManaged
   Arn                        = $_.Arn}
   $ORGPolicyForTarget   
   $ORGPolicyForTargetOUT = @()
   $ORGPolicyForTargetOUT = $ORGPolicyForTarget    
   $ORGPolicyForTargetOUT | Export-Excel $FileName -AutoSize -Append -WorksheetName 'ORGPolicyForTarget' 
   } #  ForEach-Object {

   }