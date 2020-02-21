# AcronisCCPartner-PoSH
Acronis Cyber Cloud Partner Rest API for PowerShell

Initial upload, this version is mostly for easy auth when using PowerShell. No help or error handling has been added yet.

Token Examples:

1. First set credenials for either client auth or user auth.
2. Assign new token to variable. This variable can be piped to all commands and will pass the token as well as the URI. 
3. Optionally enter your TOTP code or the shared secret. 
4. DC is optional with user account and required with client account.
  ```
  $creds = Get-Credential
  $token = New-AcronisCCPartnerToken -Credential $cred -TOTPCode 416716
  ------
  $creds = Get-Credential
  $token = New-AcronisCCPartnerToken -Credential $cred -GrantType client_credentials -DataCenterURI "https://dev-cloud.acronis.com"
  ```
Account information of current account
  ```
  $token | Get-AcronisCCPartnerAccountInfo
  ```
  
To be continued
