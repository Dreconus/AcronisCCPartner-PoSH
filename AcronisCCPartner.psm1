[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


function Get-AcronisCCPartnerUri ([string]$UserName) {
  # Try and resolve the DC the tenant\account belongs to.
  # This may Deprecate due to being version 1
  try {
    Write-Host "Attempting to resolve DC based on UserName." -f Yellow
    $returnData = ((Invoke-WebRequest -Uri "https://cloud.acronis.com/api/1/accounts?login=$($UserName)").content | convertfrom-json).server_url
    Write-Host "Resolved Acronis DC: $($returnData)" -f DarkGreen
    return $returnData
  }
  catch {
    Write-Error "Failed to locate Acronis DC based on UserName."
  }
}

function New-AcronisCCPartnerInitialToken {

  [CmdletBinding(DefaultParameterSetName="TOTPCode")]
  param(

    [Parameter(Mandatory=$true, Position = 0,
      ParameterSetName="TOTPCode",
      HelpMessage="Pass a credential object with either client or user credentials.'")]
    [Parameter(Mandatory=$true, Position = 0,
      ParameterSetName="TOTPSharedSecret",
      HelpMessage="Pass a credential object with either client or user credentials.'")]
    [pscredential]$Credential,

    [Parameter(Mandatory=$false, Position = 1,
      ParameterSetName="TOTPCode")]
    [string]$TOTPCode,

    [Parameter(Mandatory=$false, Position = 1,
      ParameterSetName="TOTPSharedSecret")]
    [string]$TOTPSharedSecret,

    [Parameter(Mandatory=$false, Position = 2,
      ParameterSetName="TOTPCode")]
    [Parameter(Mandatory=$false, Position = 2,
      ParameterSetName="TOTPSharedSecret")]
    [ValidateSet(
      "client_credentials"
      ,"password")]
    [string]$GrantType = "password",

    [Parameter(Mandatory=$false, Position = 4,
      ParameterSetName="TOTPCode",
      HelpMessage="Enter your Acronis datacenter uri.")]
    [Parameter(Mandatory=$false, Position = 4,
      ParameterSetName="TOTPSharedSecret",
      HelpMessage="Enter your Acronis datacenter uri.")]
    [string]$DataCenterURI,

    [Parameter(Mandatory=$false, Position = 3,
      ParameterSetName="TOTPCode")]
    [Parameter(Mandatory=$false, Position = 3,
      ParameterSetName="TOTPSharedSecret")]
    [ValidateSet(
      "root_admin"
      ,"partner_admin"
      ,"company_admin"
      ,"unit_admin"
      ,"readonly_admin"
      ,"tenant_viewer"
      ,"users_admin")]
    [string]$AccessScope = "readonly_admin"
    
  )



  function Private:Get-TOTP
  # When writing the Posh HMAC TOTP return i found somoene already did it.
  # No use in reinventing the wheel.
  # Credit to: https://github.com/HumanEquivalentUnit
  {

    [CmdletBinding()]
    Param(

      [Parameter(Mandatory=$true, Position = 0,
        ValueFromPipelineByPropertyName=$true)]
      [string]$Secret,

      $TimeWindow = 30

    )

    $Script:Base32Charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

    $bigInteger = [Numerics.BigInteger]::Zero
    foreach ($char in ($secret.ToUpper() -replace '[^A-Z2-7]').GetEnumerator()) {
      $bigInteger = ($bigInteger -shl 5) -bor ($Script:Base32Charset.IndexOf($char))
    }

    [byte[]]$secretAsBytes = $bigInteger.ToByteArray()
    
    if ($secretAsBytes[-1] -eq 0) {
      $secretAsBytes = $secretAsBytes[0..($secretAsBytes.Count - 2)]
    }

    [array]::Reverse($secretAsBytes)
    
    $epochTime = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    
    $timeBytes = [BitConverter]::GetBytes([int64][math]::Floor($epochTime / $TimeWindow))
    if ([BitConverter]::IsLittleEndian) { 
      [array]::Reverse($timeBytes) 
    }

    $hmacGen = [Security.Cryptography.HMACSHA1]::new($secretAsBytes)
    $hash = $hmacGen.ComputeHash($timeBytes)

    $offset = $hash[$hash.Length-1] -band 0xF

    $fourBytes = $hash[$offset..($offset+3)]
    if ([BitConverter]::IsLittleEndian) {
      [array]::Reverse($fourBytes)
    }

    $num = [BitConverter]::ToInt32($fourBytes, 0) -band 0x7FFFFFFF
    
    $TOTPResult = ($num % 1000000).ToString().PadLeft(6, '0')

    return $TOTPResult
  }
    
  $Headers = @{
      'Accept'='application/json'
      'content-type'='application/x-www-form-urlencoded'
  }
  
  $body = @{
      'grant_type'=$GrantType
    }

  if ($TOTPSharedSecret) {
    $body.'totp_code' = Get-TOTP -Secret $TOTPSharedSecret
  } elseif ($TOTPCode) {
    $body.'totp_code' = $TOTPCode
  }

  switch ($GrantType) {
    "client_credentials" {
      $base64Encoding = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($Credential.UserName):$($Credential.GetNetworkCredential().Password)"))
      $Headers.'Authorization' = "Basic $base64Encoding"
    }
    Default {
      $body.'username' = $Credential.UserName
      $body.'password' = $Credential.GetNetworkCredential().Password
    }
  }

  switch ($AccessScope) {
    "root_admin"      {$body.'scope' = 'urnacronis.comaccount-serverroot_admin'}
    "partner_admin"   {$body.'scope' = 'urnacronis.comaccount-serverpartner_admin'}
    "company_admin"   {$body.'scope' = 'urnacronis.comaccount-servercompany_admin'}
    "unit_admin"      {$body.'scope' = 'urnacronis.comaccount-serverunit_admin'}
    "tenant_viewer"   {$body.'scope' = 'urnacronis.comaccount-servertenant_viewer'}
    "users_admin"     {$body.'scope' = 'urnacronis.comaccount-serverusers_admin'}
    Default           {$body.'scope' = 'urnacronis.comaccount-serverreadonly_admin'}
  }
  

  if (!($DataCenterURI) -and ($GrantType -eq "password")) {
    $DataCenterURI = Get-AcronisCCPartnerUri -UserName $Credential.UserName
  } elseif (!$DataCenterURI) {
    Write-Error "You must include DataCenterURI when not using GrantType password."
    exit
  }

  $returnData = Invoke-RestMethod -Method Post -Uri "$($DataCenterURI):443/api/2/idp/token" -Headers $Headers -Body $body
  $returnData | Add-Member -NotePropertyName DataCenterURI -NotePropertyValue $DataCenterURI
  $returnData | Add-Member -NotePropertyName Scope -NotePropertyValue $AccessScope

  return $returnData
}

function Get-AcronisCCPartnerAccountInfo {
  
  [CmdletBinding()]
  param(

    [Parameter(Mandatory=$true, Position = 0,
      ValueFromPipelineByPropertyName=$true,
      HelpMessage="Enter your Acronis datacenter uri.")]
    [string]$DataCenterURI,

    [Parameter(Mandatory=$true, Position = 1,
      ValueFromPipelineByPropertyName=$true,
      HelpMessage="Enter access token from New-AcronisCCPartnerInitialToken.'")]
    [Alias('access_token')]
    [string]$accessToken

  )

  $Headers = @{
    'Accept'='application/json'
    'Authorization'="Bearer $accessToken"
  }

  $returnData = Invoke-RestMethod -Method Get -Uri "$($DataCenterURI):443/api/2/users/me" -Headers $Headers
  return $returnData
}

function Get-AcronisCCPartnerTenant {

  [CmdletBinding()]
  param(


    [Parameter(Mandatory=$true, Position = 0,
      HelpMessage="Enter tenant ID.")]
    [string]$TenantID,

    [Parameter(Mandatory=$true, Position = 1,
      ValueFromPipelineByPropertyName=$true,
      HelpMessage="Enter your Acronis datacenter uri.")]
    [string]$DataCenterURI,
  
    [Parameter(Mandatory=$true, Position = 2,
      ValueFromPipelineByPropertyName=$true,
      HelpMessage="Enter access token from New-AcronisCCPartnerInitialToken.'")]
    [Alias('access_token')]
    [string]$accessToken

  )

  $Headers = @{
    'Accept'='application/json'
    'Authorization'="Bearer $accessToken"
  }

  $returnData = Invoke-RestMethod -Method Get -Uri "$($DataCenterURI):443/api/2/tenants/$($TenantID)" -Headers $Headers
  return $returnData
}

function Get-AcronisCCPartnerTenantUsage {

  [CmdletBinding()]
  param(

    [Parameter(Mandatory=$true, Position = 0,
      HelpMessage="Enter tenant ID.")]
    [string]$TenantID,

    [Parameter(Mandatory=$true, Position = 1,
      ValueFromPipelineByPropertyName=$true, 
      HelpMessage="Enter your Acronis datacenter uri.")]
    [string]$DataCenterURI,
  
    [Parameter(Mandatory=$true, Position = 2,
      ValueFromPipelineByPropertyName=$true,
      HelpMessage="Enter access token from New-AcronisCCPartnerInitialToken.'")]
    [Alias('access_token')]
    [string]$accessToken

  )

  $Headers = @{
    'Accept'='application/json'
    'Authorization'="Bearer $accessToken"
  }

  $returnData = Invoke-RestMethod -Method Get -Uri "$($DataCenterURI):443/api/2/tenants/$($TenantID)/usages" -Headers $Headers
  return $returnData.items
}

function Get-AcronisCCPartnerChildren {

  [CmdletBinding()]
  param(

    [Parameter(Mandatory=$true, Position = 0,
      HelpMessage="Enter tenant ID.")]
    [string]$TenantID,

    [Parameter(Mandatory=$false, Position= 1)]
    [switch]$Detailed,

    [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true,
      ParameterSetName='DataCenterURI', Position = 2,
      HelpMessage="Enter your Acronis datacenter uri.")]
    [string]$DataCenterURI,
  
    [Parameter(Mandatory=$true, Position = 3,
      ValueFromPipelineByPropertyName=$true,
      HelpMessage="Enter access token from New-AcronisCCPartnerInitialToken.'")]
    [Alias('access_token')]
    [string]$accessToken

  )

  $Headers = @{
    'Accept'='application/json'
    'Authorization'="Bearer $accessToken"
  }

  $returnData = Invoke-RestMethod -Method Get -Uri "$($DataCenterURI):443/api/2/tenants/$($TenantID)/children?include_details=$($Detailed)" -Headers $Headers
  return $returnData.items
}

function New-AcronisCCPartnerClient {

  [CmdletBinding()]
  param(

    [Parameter(Mandatory=$true, Position = 0,
      HelpMessage="Enter tenant ID to create client in.")]
    [string]$TenantID,

    [Parameter(Mandatory=$true, Position = 1,
      HelpMessage="Enter a name for the new agent.")]
    [string]$AgentName,

    [Parameter(Mandatory=$true, Position = 2,
      ValueFromPipelineByPropertyName=$true,
      HelpMessage="Enter your Acronis datacenter uri.")]
    [string]$DataCenterURI,
  
    [Parameter(Mandatory=$true, Position = 3,
      ValueFromPipelineByPropertyName=$true,
      HelpMessage="Enter access token from New-AcronisCCPartnerInitialToken.'")]
    [Alias('access_token')]
    [string]$accessToken

  )

  $Headers = @{
    'Accept'='application/json'
    'Authorization'="Bearer $accessToken"
    'Content-Type'='application/json'
  }

  $body = [ordered]@{
    'type'='agent'
    'tenant_id'=$TenantID
    'data'= @{
      'name'=$AgentName
    }
    'token_endpoint_auth_method'='client_secret_basic'
  } | ConvertTo-Json

  $returnData = Invoke-RestMethod -Method Post -Uri "$($DataCenterURI):443/api/2/clients" -Headers $Headers -Body $body
  return $returnData
}

function Get-AcronisCCPartnerClient {

  [CmdletBinding()]
  param(

    [Parameter(Mandatory=$true, Position = 0,
      HelpMessage="Enter tenant ID to create client in.")]
    [string]$ClientID,

    [Parameter(Mandatory=$true, Position = 1,
      ValueFromPipelineByPropertyName=$true,
      HelpMessage="Enter your Acronis datacenter uri.")]
    [string]$DataCenterURI,
  
    [Parameter(Mandatory=$true, Position = 2,
      ValueFromPipelineByPropertyName=$true,
      HelpMessage="Enter access token from New-AcronisCCPartnerInitialToken.'")]
    [Alias('access_token')]
    [string]$accessToken

  )

  $Headers = @{
    'Accept'='application/json'
    'Authorization'="Bearer $accessToken"
  }

  $returnData = Invoke-RestMethod -Method Get -Uri "$($DataCenterURI):443/api/2/clients/$($ClientID)" -Headers $Headers
  return $returnData
}

function Remove-AcronisCCPartnerClient {

  [CmdletBinding()]
  param(

    [Parameter(Mandatory=$true, Position = 0,
      HelpMessage="Enter tenant ID to create client in.")]
    [string]$ClientID,

    [Parameter(Mandatory=$true, Position = 1,
      ValueFromPipelineByPropertyName=$true,
      HelpMessage="Enter your Acronis datacenter uri.")]
    [string]$DataCenterURI,
  
    [Parameter(Mandatory=$true, Position = 2,
      ValueFromPipelineByPropertyName=$true,
      HelpMessage="Enter access token from New-AcronisCCPartnerInitialToken.'")]
    [Alias('access_token')]
    [string]$accessToken

  )

  $Headers = @{
    'Accept'='application/json'
    'Authorization'="Bearer $accessToken"
  }

  $returnData = Invoke-RestMethod -Method Delete -Uri "$($DataCenterURI):443/api/2/clients/$($ClientID)" -Headers $Headers
  return $returnData
}