#Requires -Version 4
#Requires -Module @{ ModuleName = 'MSAL.PS'; ModuleVersion = '4.7.1.2'  }


<# 
 
.SYNOPSIS
	ADFS2AADUtils.psm1 is a Windows PowerShell module to help migrating AD FS configuration to Azure AD

.DESCRIPTION

	Version: 0.0.1

    ADFS2AADUtils.psm1 is a Windows PowerShell module to help migrating AD FS configuration to Azure AD.
    
    This module uses MSAL.PS. Check https://www.powershellgallery.com/packages/MSAL.PS/ for instructions


.DISCLAIMER
	THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
	ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
	THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
	PARTICULAR PURPOSE.

	Copyright (c) Microsoft Corporation. All rights reserved.
#>


$global:authHeader = $null
$global:msgraphToken = $null
$global:tokenRequestedTime = [DateTime]::MinValue

function Get-MSCloudIdAccessToken {
    [CmdletBinding()]
    param (
        [string]
        $TenantId,
        [string]
        $ClientID,
        [string]
        $RedirectUri,
        [string]
        $Scopes,
        [switch]
        $Interactive
    )
    
    $msalToken = $null
    if ($Interactive)
    {
        $msalToken = get-msaltoken -ClientId $ClientID -TenantId $TenantId -RedirectUri $RedirectUri -Scopes $Scopes -Resource          
    }
    else
    {
        try {
            $msalToken = get-msaltoken -ClientId $ClientID -TenantId $TenantId -RedirectUri $RedirectUri -Scopes $Scopes -Silent  
        }
        catch [Microsoft.Identity.Client.MsalUiRequiredException] 
        {
            $MsalToken = get-msaltoken -ClientId $ClientID -TenantId $TenantId -RedirectUri $RedirectUri -Scopes $Scopes               
        }
    }

    Write-Output $MsalToken
}

<# 
 .Synopsis
  Creates a new Azure AD Application from and AD FS Relying party trust and the Application Gallery
  as documented in aka.ms/aadgallery-sso-api


 .Description
  This function queries the Azure AD Gallery App using MS Graph
 .Parameter TenantId
  Tenant ID we want to connect
  .Parameter ClientID
  Client ID of the Client used to connect
  .Parameter RedirectUri
  Redirect URI of the Client used to connect
  .Parameter Scopes
  Scopes requested in the connection

  .Example
  Connect to MS Graph with defaults
  Connect-MSGraphAPI
#>
function Connect-MSGraphAPI {
    [CmdletBinding()]
    param (
        [string]
        $TenantId,
        [string]
        $ClientID = "1b730954-1685-4b74-9bfd-dac224a7b894",
        [string]
        $RedirectUri = "urn:ietf:wg:oauth:2.0:oob",
        [string]
        $Scopes = "https://graph.microsoft.com/.default",
        [switch]
        $Interactive
    )
    
    $token = Get-MSCloudIdAccessToken -TenantId $TenantId -ClientID $ClientID -RedirectUri $RedirectUri -Scopes $Scopes -Interactive:$Interactive
    $Header = @{ }
    $Header.Authorization = "Bearer {0}" -f $token.AccessToken
    $Header.'Content-type' = "application/json"
    
    $global:msgraphToken = $token
    $global:authHeader = $Header
}

function Invoke-MSGraphQuery {
    [CmdletBinding()]
    param (
        # Base URI
        [string]
        $BaseURI = "https://graph.microsoft.com/",
        # endpoint
        [string]
        $endpoint,
        [ValidateSet("v1.0", "beta")]
        [string]
        $APIVersion = "v1.0",
        [string]
        $QueryParameters,
        # HTTP Method
        [Parameter(Mandatory = $true)]
        [ValidateSet("GET", "POST", "PUT", "DELETE", "PATCH")]
        [string]
        $Method,
        [string]
        $Body

    )
    
    begin {
        # Header
        $CurrentDate = [DateTime](Get-Date)
        $Delta= ($CurrentDate - $global:tokenRequestedTime).TotalMinutes
        
        if ($Delta -gt 55)
        {
            Connect-MSGraphAPI
            $global:tokenRequestedTime = $CurrentDate
        }
        $Headers = $global:authHeader        
    }
    
    process {

        if ($null -notlike $QueryParameters) {
            $URI = ("{0}{1}/{2}?{3}" -f $BaseURI, $APIVersion, $endpoint, $QueryParameters)
            
        }
        else {
            $URI = ("{0}{1}/{2}" -f $BaseURI, $APIVersion, $endpoint)
        }
        
        switch ($Method) {
            "GET" {

                $queryUrl = $URI
                Write-Verbose ("Invoking $Method request on $queryUrl...")
                while (-not [String]::IsNullOrEmpty($queryUrl)) {
                    
                    try {                            
                        $pagedResults = Invoke-RestMethod -Method $Method -Uri $queryUrl -Headers $Headers -ErrorAction Stop
                    
                    }
                    catch {
                    
                        $StatusCode = [int]$_.Exception.Response.StatusCode
                        $message = $_.Exception.Message
                        throw "ERROR During Request -  $StatusCode $message"

                    }

                
                    if ($pagedResults.value -ne $null) {
                        $queryResults += $pagedResults.value
                    }
                    else {
                        $queryResults += $pagedResults
                    }
                    $queryCount = $queryResults.Count
                    Write-Progress -Id 1 -Activity "Querying directory" -CurrentOperation "Retrieving results ($queryCount found so far)" 
                    $queryUrl = ""

                    $odataNextLink = $pagedResults | Select-Object -ExpandProperty "@odata.nextLink" -ErrorAction SilentlyContinue

                    if ($null -ne $odataNextLink) {
                        $queryUrl = $odataNextLink
                    }
                    else {
                        $odataNextLink = $pagedResults | Select-Object -ExpandProperty "odata.nextLink" -ErrorAction SilentlyContinue
                        if ($null -ne $odataNextLink) {
                            $absoluteUri = [Uri]"https://bogus/$odataNextLink"
                            $skipToken = $absoluteUri.Query.TrimStart("?")
                            
                        }
                    }
                }

                Write-Verbose ("Returning {0} total results" -f $queryResults.count)
                Write-Output $queryResults

            }

            "POST" {
                $queryUrl = $URI
                Write-Verbose ("Invoking $Method request on $queryUrl using $Headers with Body $body...")

                $qErr = $Null
                try {                    
                    $queryResults = Invoke-RestMethod -Method $Method -Uri $queryUrl -Headers $Headers -Body $Body -UseBasicParsing -ErrorVariable qErr -ErrorAction Stop
                    Write-Output $queryResults
                }
                catch {
                    $StatusCode = [int]$_.Exception.Response.StatusCode
                    $message = $_.Exception.Message
                    throw "ERROR During Request -  $StatusCode $message"


                }
            }

            "PATCH" {
                $queryUrl = $URI
                Write-Verbose ("Invoking $Method request on $queryUrl using $Headers with Body $body...")

                $qErr = $Null
                try {                    
                    $queryResults = Invoke-RestMethod -Method $Method -Uri $queryUrl -Headers $Headers -Body $Body -UseBasicParsing -ErrorVariable qErr -ErrorAction Stop
                    Write-Output $queryResults
                }
                catch {
                    $StatusCode = [int]$_.Exception.Response.StatusCode
                    $message = $_.Exception.Message
                    throw "ERROR During Request -  $StatusCode $message"


                }
            }


            "PUT" {
                $queryUrl = $URI
                Write-Verbose ("Invoking $Method request on $queryUrl...")
                $pagedResults = Invoke-RestMethod -Method $Method -Uri $queryUrl -Headers $Headers -Body $Body
            }
            "DELETE" {
                $queryUrl = $URI
                Write-Verbose ("Invoking $Method request on $queryUrl...")
                $pagedResults = Invoke-RestMethod -Method $Method -Uri $queryUrl -Headers $Headers
            }
        }
    }
    
    end {
        
    }
}

<# 
 .Synopsis
  Start a session  to AzureAD and MS Graph Client Library

 .Description
  This function prompts for authentication using MSAL.PS and reuses the same token to connect
  to Azure AD Powershell

#>
function Start-ADFS2AADSession		
{
    #Connect to MS Graph using MSAL.PS
    Connect-MSGraphAPI
    $msGraphToken = $global:msgraphToken
    
    #Get an Azure AD Graph silently
    $aadTokenPsh = Get-MSCloudIdAccessToken -ClientID 1b730954-1685-4b74-9bfd-dac224a7b894 -Scopes "https://graph.windows.net/.default"  -RedirectUri "urn:ietf:wg:oauth:2.0:oob" 

    #Connect to AzureAD Powershell Module with MS Graph and Azure AD Graph tokens 
    Connect-AzureAD -AadAccessToken $aadTokenPsh.AccessToken  -MsAccessToken $msGraphToken.AccessToken -AccountId $msGraphToken.Account.UserName -TenantId $msGraphToken.TenantID  | Out-Null

    $global:tokenRequestedTime = [DateTime](Get-Date)

    Write-Output "Session Started!"
}

#################################################################################
# Wrappers for app management  as documented in https://aka.ms/aadgallery-sso-api 
#################################################################################

<# 
 .Synopsis
  Creates a new Azure AD Application from and AD FS Relying party trust and the Application Gallery
  as documented in aka.ms/aadgallery-sso-api


 .Description
  This function queries the Azure AD Gallery App using MS Graph
 .Parameter DisplayNameFilter
  Filter for the search in the gallery . This is case sensitive and will be used as a "startsWith" filter

  .Example
  Get-AzureADApplicationTemplate -DisplayNameFilter ContosoERP
#>
function Get-AzureADApplicationTemplate {
    [CmdletBinding()]
    param (
        $DisplayNameFilter
    )
   
    $endpoint = "applicationTemplates"
    if (-not [String]::IsNullOrWhiteSpace($DisplayNameFilter))
    {
        $endpoint += "/?`$filter=startswith(displayName,'$DisplayNameFilter')"
    }
    Invoke-MSGraphQuery -endpoint $endpoint  -Method GET -APIVersion "beta"   
}

function New-AzureADApplicationTemplateInstance
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]    
        $AppTemplateId,
        [Parameter(Mandatory = $true)]
        $DisplayName
    )

    $endpoint = "applicationTemplates/$AppTemplateId/instantiate"
    $body = ""
    if (-not [String]::IsNullOrWhiteSpace($DisplayName))
    {
        $body += @{
            "displayName" = $DisplayName
        } | ConvertTo-Json
    }
    Invoke-MSGraphQuery -endpoint $endpoint -Method "POST" -Body $body -APIVersion "beta"
}


<#
-------------------------------------------------------------
AD FS Specific functionality
-------------------------------------------------------------
#>


###########################################
# RP Trust Claim Rule checks
###########################################

Add-Type -Language CSharp @"
public class MigrationTestResult
{
	public string TestName;
    public string ADFSObjectType;
    public string ADFSObjectIdentifier;

	public ResultType Result;
	public string Message;
	public string ExceptionMessage;
    public System.Collections.Hashtable Details;

    public MigrationTestResult()
	{
		Result = ResultType.Pass;
        Details = new System.Collections.Hashtable();        
	}
}

public enum ResultType
{
	Pass = 0,
	Warning = 1,
	Fail = 2
}
"@;


##########
#templatized claim rules
##########


$IssuanceTransformMigratableRules =
@{ 
"Extract Attributes from AD" = 
@"
@RuleTemplate = "LdapClaims"
@RuleName = "__ANYVALUE__"
c:[Type == "__ANYVALUE__", Issuer == "AD AUTHORITY"]
 => issue(store = "Active Directory", types = (__ANYVALUE__), query = ";__ANYVALUE__;{0}", param = c.Value);
"@
}

Function Invoke-ADFSClaimRuleAnalysis
{
 [CmdletBinding()]
    param
    (    
        [String]
        $RuleSetName,
        [String]
        $ADFSRuleSet,
        [Parameter(Mandatory=$true)]
        [System.Collections.Hashtable]
        $KnownRules
    )

    #Task 1: Compare rule against known patterns of migratable rules

    $ADFSRuleArray = @()

    if (-not [String]::IsNullOrEmpty($ADFSRuleSet))
    {
        $ADFSRuleArray = New-AdfsClaimRuleSet -ClaimRule $ADFSRuleSet 
    } 

    
    $Details = ""
    $ruleIndex = 0
    $AnalysisPassed = $true

    foreach($Rule in $ADFSRuleArray.ClaimRules)
    {
        #Create result object
        $Result = new-object PSObject
        $Result | Add-Member -NotePropertyName "RuleSet" -NotePropertyValue $RuleSetName
        $Result | Add-Member -NotePropertyName "Rule" -NotePropertyValue $Rule
        $ruleIndex++


        #Task 1: Find Match to known pattern
        $matchFound = $false
        $migratablePatternName = "N/A"

        foreach($knownRuleKey in $KnownRules.Keys)
        {
            $knownRuleRegex = $KnownRules[$knownRuleKey]
            $knownRuleRegex = [Regex]::Escape($knownRuleRegex).Replace("__ANYVALUE__", ".*").TrimEnd() 


            #JSON files have \r\n instead or \n ... adding flexibility to match these
            $knownRuleRegex = $knownRuleRegex.Replace("\n", "\r?\n*") 

            if ($rule -match $knownRuleRegex)
            {
                $migratablePatternName = $knownRuleKey
                $matchFound = $true
            }
        }

        $Result | Add-Member -NotePropertyName "IsKnownRuleMigratablePattern" -NotePropertyValue $matchFound
        $Result | Add-Member -NotePropertyName "KnownRulePatternName" -NotePropertyValue $migratablePatternName


        #Task 2: Break down condition and issuance statement        
        #Assumption: There is only one "=>" unambigous match in the rule
        $separatorIndex = $Rule.IndexOf("=>") 
        $conditionStatement = $Rule.Substring(0,$separatorIndex).Trim();
        $issuanceStatement = $Rule.Substring($separatorIndex+2).Trim();

        $Result | Add-Member -NotePropertyName "ConditionStatement" -NotePropertyValue $conditionStatement
        $Result | Add-Member -NotePropertyName "IssuanceStatement" -NotePropertyValue $issuanceStatement

        #Task 3: Find claim types in the condition statement
        $TypeRegex = '(?i)type\s+={1,2}\s+"(.*?)"'
        $ConditionTypeMatch = [Regex]::Match($conditionStatement, $TypeRegex)
        if ($ConditionTypeMatch.Success)
        {
            #TODO: How does this work with claims with multiple condition in the types (eg. c:[Type=="foo"] && c1:[Type=="bar"]
            $ConditionClaimType = $ConditionTypeMatch.Groups[1].ToString()
            $Result | Add-Member -NotePropertyName "ConditionClaimType" -NotePropertyValue $ConditionClaimType

            $GroupFilter = "N/A"

            if ($ConditionClaimType -eq "http://schemas.xmlsoap.org/claims/Group")
            {
                $GroupFilterRegex = '(?i)Value\s+(=(~|=)\s+"(.*?)")'
                $GroupFilterMatch = [Regex]::Match($conditionStatement, $GroupFilterRegex)
                if ($GroupFilterMatch.Success)
                {
                    $GroupFilter = $GroupFilterMatch.Groups[1].ToString()
                }
            }

            $Result | Add-Member -NotePropertyName "GroupFilter" -NotePropertyValue $GroupFilter
        }

        #Task 4: Find claim types in the issuance statement -- explicit Type = .* 

        $IssuanceClaimTypes = @()

        $IssuanceTypeMatch = [Regex]::Match($issuanceStatement, $TypeRegex)
        if ($IssuanceTypeMatch.Success)
        {
            $IssuanceClaimTypes += $IssuanceTypeMatch.Groups[1].ToString()
        }

        #Task 4a : Find claim types in the issuance statement from the Attribute Store
        $AttributeStoreRuleRegex = '(?i).*store\s*=\s*"(.*?)"'
        $AttributeStoreName = "N/A"
        $AttributeStoreQuery = "N/A"
        $ActiveDirectoryAttributesSplit = @()


        $AttributeStoreRuleMatch = [Regex]::Match($issuanceStatement, $AttributeStoreRuleRegex)
        if ($AttributeStoreRuleMatch.Success)
        {
            $AttributeStoreName = $AttributeStoreRuleMatch.Groups[1].ToString()
            $AttributeStoreRuleTypesRegex = '(?i)types\s*=\s*\("(.*?)"\)'
            $AttributeStoreRuleTypesMatch = [Regex]::Match($issuanceStatement, $AttributeStoreRuleTypesRegex)
            
            if ($AttributeStoreRuleTypesMatch.Success)
            {
                $IssuanceClaimTypes += $AttributeStoreRuleTypesMatch.Groups[1].ToString().Split(',').Trim().Trim('"');
            }

            #Task 4b: Extract the attributes retrieved from the store
            $AttributeStoreQueryRegex = '(?i)query\s*=\s*"(.*?)"'
            $AttributeStoreQueryMatch = [Regex]::Match($issuanceStatement, $AttributeStoreQueryRegex)
            
            if ($AttributeStoreQueryMatch.Success)
            {
                $AttributeStoreQuery = $AttributeStoreQueryMatch.Groups[1].ToString();
                if ($AttributeStoreName -ieq "Active Directory")
                {
                    $AttributeStoreQuerySplit = $AttributeStoreQuery.Split(';');
                    $ActiveDirectoryAttributes = $AttributeStoreQuerySplit[1];
                    $ActiveDirectoryAttributesSplit = $ActiveDirectoryAttributes.Split(',')
                }
            }
        }

        $Result | Add-Member -NotePropertyName "IssuanceClaimTypes" -NotePropertyValue $IssuanceClaimTypes
        $Result | Add-Member -NotePropertyName "AttributeStoreName" -NotePropertyValue $AttributeStoreName                
        $Result | Add-Member -NotePropertyName "AttributeStoreQuery" -NotePropertyValue $AttributeStoreQuery
        $Result | Add-Member -NotePropertyName "ADAttributes" -NotePropertyValue $ActiveDirectoryAttributesSplit

        Write-Output $Result
    }

}

Function Test-ADFSRPRuleset
{
    [CmdletBinding()]
    param
    (   
        [Parameter(Mandatory=$true)]
        [String]
        $RulesetName, 
        [String]
        $ADFSRuleSet,
        [Parameter(Mandatory=$true)]
        [System.Collections.Hashtable]
        $KnownRules,
        [Parameter(Mandatory=$true)]
        [ResultType]
        $ResultTypeIfUnknownPattern
    )

    $TestResult = New-Object MigrationTestResult

    $RuleAnalysisResult = Invoke-ADFSClaimRuleAnalysis -ADFSRuleSet $ADFSRuleSet -KnownRules $KnownRules -RuleSetName $RulesetName

    #Capture the expanded details of each rule as a result
    $TestResult.Details.Add("ClaimRuleProperties", $RuleAnalysisResult)

    #Insight 1: Did we find claim rules that don't match any template

    $UnknownClaimRulePatternFound = @($RuleAnalysisResult | where {$_.IsKnownRuleMigratablePattern -eq $false}).Count -gt 0
    $TestResult.Details.Add("UnkwnownPatternFound", $UnknownClaimRulePatternFound)

    if ($UnknownClaimRulePatternFound)
    {
        $TestResult.Result = $ResultTypeIfUnknownPattern
        $TestResult.Message = "At least one non-migratable rule was detected"        
    }

    Return $TestResult
}

Function Test-ADFSRPIssuanceTransformRules
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    Test-ADFSRPRuleset `
        -RulesetName "IssuanceTransform" `
        -ADFSRuleSet $ADFSRelyingPartyTrust.IssuanceTransformRules `
        -KnownRules $IssuanceTransformMigratableRules `
        -ResultTypeIfUnknownPattern Warning

}


###########################################
# AD FS and Azure AD cross-over functions
###########################################

function Get-AzureADClaimsMappingFromADFSRPTrust {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $ADFSRelyingPartyTrust
    )
   
    $testResult = Test-ADFSRPIssuanceTransformRules -ADFSRelyingPartyTrust $ADFSRelyingPartyTrust

    if ($testResult.Result -ne "Pass")
    {
        throw "Issuance transform rules for RP Trust are not migratable"
    }
    
    #redundant with the one above ??
    if ($testResult.Details.UnkwnownPatternFound)
    {
        throw "Issuance transform rules for RP Trust have at least one non-migratable pattern"
    }

    $ClaimsSchema = @()

    foreach ($r in $testResult.Details.ClaimRuleProperties) 
    {
        if ($r.KnownRulePatternName -ne "Extract Attributes from AD")
        {
            throw "Pattern is migratable, but creating the claims policy is not supported"
        }

        $ADAttributes = $r.ADAttributes
        $ClaimTypes = $r.IssuanceClaimTypes

        for ($i=0;$i -lt $ADAttributes.Count;$i++)
        {
            $ADAttribute = $ADAttributes[$i]
            $ClaimType = $ClaimTypes[$i]
            
            #TODO: Logic to find out if the attribute is a schema extension in Azure AD
            #that requires looking up the Azure AD Connect config

            $ClaimsSchema += new-Object PSObject -Property @{
                Source="user";
                ID=$ADAttribute;
                SamlClaimType=$ClaimType
            }
        }
    }

    $ClaimsMappingPolicy = New-Object PSObject -Property @{
        Version=1;
        IncludeBasicClaimSet="true";
        ClaimsSchema=$ClaimsSchema
    }

    $rootPolicy = New-Object PSObject -Property @{ClaimsMappingPolicy=$ClaimsMappingPolicy}

    Write-Output $rootPolicy 
}

function New-TempSelfSignedCertificate
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]    
        $CertificateSubject    
    )

    $certStore = "Cert:\CurrentUser\My"
    $cert = New-SelfSignedCertificate  -Subject $CertificateSubject -CertStoreLocation $certStore
    $certThumbprint = $cert.Thumbprint
    
    #generate a random string as a pfx file password 
    $pfxPassword =  -join ((0x30..0x39) + ( 0x41..0x5A) + ( 0x61..0x7A)  | Get-Random -Count 16  | % {[char]$_})
    $pfxPasswordSecureString = ConvertTo-SecureString -String $pfxPassword -Force -AsPlainText

    $certStorePath = [System.IO.Path]::Combine($certStore,$certThumbprint)
    $certFilePath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(),$certThumbprint + ".pfx")
    
    Get-ChildItem -Path $certStorePath | Export-PfxCertificate -FilePath $certFilePath -Password $pfxPasswordSecureString | Out-Null

    $result = new-object PSObject -Property @{
        Thumbprint = $certThumbprint;
        Certificate = $cert
        PfxFilePath = $certFilePath;
        PfxPassword = $pfxPassword;
        CertStorePath = $certStorePath
    }

    Write-Output $result
}

function Remove-TempSelfSignedCertificate
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]    
        $CertificateInfo
    )

    Remove-Item $CertificateInfo.PfxFilePath
    Remove-Item $CertificateInfo.CertStorePath
}

function New-AzureADCustomSigningKeyFromPfx
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]    
        $CertificateInfo
    )


    #calculate key identifier
    $thumbprintBytes = [System.Text.Encoding]::ASCII.GetBytes($CertificateInfo.Thumbprint)
    $sha256 = [System.Security.Cryptography.HashAlgorithm]::Create("sha256")
    $thumbprintHash = $sha256.ComputeHash($thumbprintBytes)
    $customKeyIdentifier = [Convert]::ToBase64String($thumbprintHash)

    $signingKeyId = [Guid]::NewGuid().ToString()
    $signingEncodedKey = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($CertificateInfo.PfxFilePath))
    $signingKey = New-Object PSObject -Property @{
        customKeyIdentifier = $customKeyIdentifier;
        endDateTime = $CertificateInfo.Certificate.NotAfter.ToUniversalTime().ToString("o");
        keyId=$signingKeyId;
        startDateTime = $CertificateInfo.Certificate.NotBefore.ToUniversalTime().ToString("o");
        type="AsymmetricX509Cert";
        usage="Sign";
        key=$signingEncodedKey;
        displayName=$CertificateInfo.Certificate.Subject
    }

    $verifyKeyId = [Guid]::NewGuid().ToString()    
    $verifyEncodedKey = [Convert]::ToBase64String($CertificateInfo.Certificate.Export("Cert"))
    $verifyKey = New-Object PSObject -Property @{
        customKeyIdentifier = $customKeyIdentifier;
        endDateTime = $CertificateInfo.Certificate.NotAfter.ToUniversalTime().ToString("o");
        keyId=$verifyKeyId;
        startDateTime = $CertificateInfo.Certificate.NotBefore.ToUniversalTime().ToString("o");
        type="AsymmetricX509Cert";
        usage="Verify";
        key=$verifyEncodedKey;
        displayName=$CertificateInfo.Certificate.Subject
    }
    
    $passwordCredential = New-Object PSObject -Property @{
        customKeyIdentifier = $customKeyIdentifier;
        endDateTime = $CertificateInfo.Certificate.NotAfter.ToUniversalTime().ToString("o");
        keyId=$signingKeyId;
        startDateTime = $CertificateInfo.Certificate.NotBefore.ToUniversalTime().ToString("o");
        secretText = $CertificateInfo.PfxPassword
    }

    $result = new-Object PSObject -Property @{
        keyCredentials = @($signingKey,$verifyKey);
        passwordCredentials = @($passwordCredential)
    }

    Write-Output $result
}

<# 
 .Synopsis
  Creates a new Azure AD Application from and AD FS Relying party trust and the Application Gallery
  as documented in aka.ms/aadgallery-sso-api


 .Description
  This function creates an Azure AD Application from an AD FS Relying Party Trust as follows:
  * It instantiates the app gallery template, which creates an Application and a Service Principal Object using
    Microsoft Graph
  * It reads the AD FS RP trust issuance transformation rules and creates the claims mapping policy; it  
    supports basic attribute to claim mapping. 
  * It copies identifiers and endpoints from the AD FS Relying party trust
  * It creates a self-signed certificate for token signing 
  * Takes a group and assigns it to the created app with the specified role

  To call this function, you should have started a session with 

 .Parameter AzureADAppTemplateId
  Object Id of the app gallery. This can be retrieved using the Get-AzureADApplicationTemplate function in this module

  .Parameter ADFSRelyingPartyTrust
  RP Trust object, returned by the AD FS Get-ADFSRelyingPartyTrust Powershell cmdlet

  .Parameter TestGroupAssignmentObjectId
  Object ID of the Azure AD Group that will be assigned to the application. This can be retrieved by the Get-AzureADGroup 
  cmdlet from the AzureAD Poweshell module. 

  .Parameter TestGroupAssignmentRoleName
  Name of the role that will be assigned. 

 .Example
    Start-ADFS2AADSession

    $targetGalleryApp = "GalleryAppName"
    $targetGroup = Get-AzureADGroup -SearchString "TestGroupName"
    $targetAzureADRole = "TestRoleName"
    $targetADFSRPId = "ADFSRPIdentifier"

    $galleryApp = Get-AzureADApplicationTemplate -DisplayNameFilter $targetGalleryApp

    $RP=Get-AdfsRelyingPartyTrust -Identifier $targetADFSRPId

    New-AzureADAppFromADFSRPTrust `
        -AzureADAppTemplateId $galleryApp.id `
        -ADFSRelyingPartyTrust $RP `
        -TestGroupAssignmentObjectId $targetGroup.ObjectId `
        -TestGroupAssignmentRoleName $targetAzureADRole
#>

function New-AzureADAppFromADFSRPTrust {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]    
        $AzureADAppTemplateId,    
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $ADFSRelyingPartyTrust,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $TestGroupAssignmentObjectId,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $TestGroupAssignmentRoleName
    )
    $DisplayName = $ADFSRelyingPartyTrust.Name
    # This script follows the documentation for creating Azure AD gallery applications using MS Graph APIs: aka.ms/aadgallery-sso-api
    #STEP 1: Instantiate App Gallery Template
    Write-Progress -Activity "Exporting AD FS RP $DisplayName to Azure AD" -Status "Instantiating app gallery template"
    $templateInstance = New-AzureADApplicationTemplateInstance -AppTemplateId $AzureADAppTemplateId -DisplayName $DisplayName
    $SPObjectId = $templateInstance.servicePrincipal.objectId
    $AppObjectId = $templateInstance.application.objectId

    #STEP 2: Create Claims Mapping Policy
    Write-Progress -Activity "Exporting AD FS RP $DisplayName to Azure AD" -Status "Create Claims Mapping Policy"
    $ClaimsMP =  Get-AzureADClaimsMappingFromADFSRPTrust -ADFSRelyingPartyTrust $ADFSRelyingPartyTrust
    $ClaimsMPJSON = $ClaimsMP | ConvertTo-Json -Depth 99
    $ClaimsMPJSONArray = @($ClaimsMPJSON)
    $ClaimsMPRequestBody = New-Object PSObject -Property @{
        definition=$ClaimsMPJSONArray;
        displayName = "Autogenerated - Claims Policy - $DisplayName";
        isOrganizationDefault = "false"
    } | ConvertTo-Json -Depth 99
    $ClaimsMPObject = Invoke-MSGraphQuery -endpoint "policies/claimsMappingPolicies" -Body $ClaimsMPRequestBody -Method "POST"
    $ClaimsMPObjectId = $ClaimsMPObject.id

    #Step 3: Create Self-Signed Certificate
    Write-Progress -Activity "Exporting AD FS RP $DisplayName to Azure AD" -Status "Create Self-Signed Token Signing Certificate"
    $tokenSigningCert = New-TempSelfSignedCertificate -CertificateSubject "CN=Autogenerated token signing cert for - $DisplayName"
    $customKeys = New-AzureADCustomSigningKeyFromPfx -CertificateInfo $tokenSigningCert
    Remove-TempSelfSignedCertificate -CertificateInfo $tokenSigningCert
    
    #Step 4: Adding keys, set SSO mode and endpoints to service principal
    #We have to wrap the PATCH operation in a retry loop because it might have
    #Read after write inconsistencies
    Write-Progress -Activity "Exporting AD FS RP $DisplayName to Azure AD" -Status "Updating Service Principal"

    #Create the body of the patch request for service principal
    #Custom keys
    $servicePrincipalPatchRequest =  $customKeys 

    #Preferred SSO mode
    $servicePrincipalPatchRequest | Add-Member -NotePropertyName  "preferredSingleSignOnMode" -NotePropertyValue "saml"


    #Login URL and reply URLs
    $SamlACSEndpoints =$ADFSRelyingPartyTrust.SamlEndpoints | where {$_.Protocol -eq "SAMLAssertionConsumer"}
    $firstSamlACSEndpoint = $SamlACSEndpoints | Sort-Object -Property Index | Select-Object -First 1 -ExpandProperty Location
    if ($firstSamlACSEndpoint)
    {
        $servicePrincipalPatchRequest | Add-Member -NotePropertyName  "loginUrl" -NotePropertyValue $firstSamlACSEndpoint.AbsoluteUri
    }
    else 
    {
        $WSFedEndpoint = $ADFSRelyingPartyTrust.WSFedEndpoint
        if ($WSFedEndpoint)
        {
            $servicePrincipalPatchRequest | Add-Member -NotePropertyName  "loginUrl" -NotePropertyValue $WSFedEndpoint.AbsoluteUri
        }
        else {
            #This should note happen if the script validates first 
            throw "Could not find compatible login URL"
        }
    }

    #Wrap ADFS property in an array, in case there is only one value, PSH does not set the note property as a single value
    $SAMLACSEndpointArray = @($SamlACSEndpoints.Location.AbsoluteUri)
    $servicePrincipalPatchRequest | Add-Member -NotePropertyName  "replyUrls" -NotePropertyValue $SAMLACSEndpointArray

    #Active SSO Cert
    $servicePrincipalPatchRequest | Add-Member -NotePropertyName  "preferredTokenSigningKeyThumbprint" -NotePropertyValue $tokenSigningCert.Thumbprint

   
    #Serialize and send to MS Graph
    $servicePrincipalPatchBody = $servicePrincipalPatchRequest| ConvertTo-Json -Depth 99


    $millisecondsWait = 500
    $patchSuceeded = $false

    do 
    {
        try 
        {
            Write-Debug "Attempting to update service principal properties."
            Invoke-MSGraphQuery -endpoint "servicePrincipals/$SPObjectId" -Method "PATCH"  -Body $servicePrincipalPatchBody | Out-Null
            Write-Debug "Service Principal updated successfully"
            $patchSuceeded = $true 
        }
        catch 
        {
            Write-Debug "Update to Service Principal failed ... sleeping $millisecondsWait milliseconds"
            Start-Sleep -Milliseconds $millisecondsWait
            $millisecondsWait *= 2
        }
    }
    while (-not $patchSuceeded)

    #Step 5: Patch the Application object with the Entity ID
    #Wrap ADFS property in an array, in case there is only one value, PSH does not set the note property as a single value
    $RPIdentifierArray = @($ADFSRelyingPartyTrust.identifier) 
    $applicationPatchRequest = new-Object PSObject -Property @{
        identifierUris = $RPIdentifierArray
    }

    #Serialize and send to MS Graph
    $applicationPatchBody = $applicationPatchRequest| ConvertTo-Json -Depth 99

    $millisecondsWait = 500
    $patchSuceeded = $false

    do 
    {
        try 
        {
            Write-Debug "Attempting to update application properties."
            Invoke-MSGraphQuery -endpoint "applications/$AppObjectId" -Method "PATCH"  -Body $applicationPatchBody | Out-Null
            Write-Debug "Application updated successfully"
            $patchSuceeded = $true 
        }
        catch 
        {
            Write-Debug "Update to Application failed ... sleeping $millisecondsWait milliseconds"
            Start-Sleep -Milliseconds $millisecondsWait
            $millisecondsWait *= 2
        }
    }
    while (-not $patchSuceeded)
   
    #Step 6: Associating Claims Mapping Policy to serviceprincipals
    Write-Progress -Activity "Exporting AD FS RP $DisplayName to Azure AD" -Status "Assign Claims Mapping Policy to Service Principal"
    #HACK: wrap the Claims Mapping Policy association to service principal in a try loop
    #Read after write inconsistencies
    $millisecondsWait = 500
    $AssociationSucceed = $false
    do 
    {
        try {
            Write-Debug "Trying to associate claims mapping policy to service principal"
            $AssignClaimsMPRequestBody = New-Object PSObject -Property @{
                "@odata.id"="https://graph.microsoft.com/v1.0/policies/claimsMappingPolicies/$ClaimsMPObjectId"
            } | ConvertTo-Json -Depth 99
        
            Invoke-MSGraphQuery -endpoint "servicePrincipals/$SPObjectId/claimsMappingPolicies/`$ref" -Method "POST" -Body $AssignClaimsMPRequestBody
            Write-Debug "Claims mapping policy read succesfully"
            $AssociationSucceed = $true
        }
        catch 
        {
            Write-Debug "Did not read back claims mapping policy ... sleeping $millisecondsWait milliseconds"
            Start-Sleep -Milliseconds $millisecondsWait
            $millisecondsWait *= 2
        }
    }
    while (-not $AssociationSucceed)

    #Step 7: Associate the group to the app
    #first, we have to get the appRoles from the application object
    Write-Progress -Activity "Exporting AD FS RP $DisplayName to Azure AD" -Status "Creating test group assignment"

    $appObject = Invoke-MSGraphQuery -endpoint "/applications/$AppObjectId" -method GET
    $appRoleIdToAssign = $appObject.AppRoles | where {$_.displayName -eq $TestGroupAssignmentRoleName} | Select-Object -ExpandProperty Id

    $appAssignmentRequestBody = new-Object PSObject -Property @{
        principalId = $TestGroupAssignmentObjectId;
        principalType = "Group";
        appRoleId = $appRoleIdToAssign;
        resourceId = $SPObjectId
    } | ConvertTo-JSON -Depth 99
    Invoke-MSGraphQuery -endpoint "servicePrincipals/$SPObjectId/appRoleAssignments" -Method "POST" -Body $appAssignmentRequestBody | Out-Null
    Write-Debug "Test group assignment completed successfully"

}

Export-ModuleMember -Function Connect-MSGraphAPI
Export-ModuleMember -Function Start-ADFS2AADSession	
Export-ModuleMember -Function Get-AzureADApplicationTemplate
Export-ModuleMember -Function New-AzureADAppFromADFSRPTrust