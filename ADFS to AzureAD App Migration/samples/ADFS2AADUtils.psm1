#Requires -Version 4
#Requires -Module @{ ModuleName = 'MSAL.PS'; ModuleVersion = '4.7.1.2'  }

<# 
 
.SYNOPSIS
	ADFS2AADUtils.psm1 is a Windows PowerShell module to help migrating AD FS configuration to Azure AD

.DESCRIPTION

	Version: 1.0.0

	ADFS2AADUtils.psm1 is a Windows PowerShell module to help migrating AD FS configuration to Azure AD


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

<# 
 .Synopsis
  Starts the sessions to AzureAD and MSOnline Powershell Modules

 .Description
  This function prompts for authentication against azure AD 

#>
function Start-MSCloudIdSession		
{
    Connect-MSGraphAPI
    $msGraphToken = $global:msgraphToken

    $aadTokenPsh = Get-MSCloudIdAccessToken -ClientID 1b730954-1685-4b74-9bfd-dac224a7b894 -Scopes "https://graph.windows.net/.default"  -RedirectUri "urn:ietf:wg:oauth:2.0:oob" 
    #$aadTokenPsh

    Connect-AzureAD -AadAccessToken $aadTokenPsh.AccessToken  -MsAccessToken $msGraphToken.AccessToken -AccountId $msGraphToken.Account.UserName -TenantId $msGraphToken.TenantID  | Out-Null
    Connect-MsolService -AdGraphAccesstoken $aadTokenPsh.AccessToken -MsGraphAccessToken $msGraphToken.AccessToken | Out-Null

    $global:tokenRequestedTime = [DateTime](Get-Date)

    Write-Output "Session Started!"
}



function New-MSGraphQueryToBatch
{
    [CmdletBinding()]
    param (
        # endpoint
        [string]
        $endpoint,
        [string]
        $QueryParameters,
        # HTTP Method
        [Parameter(Mandatory = $true)]
        [ValidateSet("GET", "POST", "PUT", "DELETE")]
        [string]
        $Method,
        [string]
        $Body
    )

    if ($null -notlike $QueryParameters) {
        $URI = ("/{0}?{1}" -f $endpoint, $QueryParameters)
        
    }
    else {
        $URI = ("/{0}" -f $endpoint)
    }

    $result = New-Object PSObject -Property @{
        id = [Guid]::NewGuid()
        method=$Method
        url=$URI
        body=$Body
    }

    Write-Output $result
}

function Invoke-MSGraphBatch
{
    param (
        # Base URI
        [string]
        $BaseURI = "https://graph.microsoft.com/",
        # endpoint
        [ValidateSet("v1.0", "beta")]
        [string]
        $APIVersion = "v1.0",
        [object[]]
        $requests
    )

    #MS Graph limit
    $maxBatchSize = 20
    $batchCount = 0
    $currentBatch=@()
    $totalResults=@()

    foreach($request in $requests)
    {
        $batchCount++
        $currentBatch += $request
        
        if ($batchCount -ge $maxBatchSize)
        {
            $requestsJson = New-Object psobject -Property @{requests=$currentBatch} | ConvertTo-Json -Depth 100
            $batchResults = Invoke-MSGraphQuery -BaseURI $BaseURI -endpoint "`$batch" -Method "POST" -Body $requestsJson
            $totalResults += $batchResults
            
            $batchCount = 0
            $currentBatch = @()
        }
    }

    if ($batchCount -gt 0)
    {
        $requestsJson = New-Object psobject -Property @{requests=$currentBatch} | ConvertTo-Json -Depth 100
        $batchResults = Invoke-MSGraphQuery -BaseURI $BaseURI -endpoint "`$batch" -Method "POST" -Body $requestsJson
        $totalResults += $batchResults
        
        $batchCount = 0
        $currentBatch = @()
    }

    Write-Output $totalResults
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

function Add-MSGraphObjectIdCondition
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $InitialFilter,
        [Parameter()]
        [string]
        $PropertyName,
        [string]
        $ObjectId,
        [Parameter()]
        $Operator = "or"
    )

    $oid = [Guid]::NewGuid()

    if ([String]::IsNullOrWhiteSpace($oid) -or -not [Guid]::TryParse($ObjectId, [ref]$oid))
    {
        Write-Output $InitialFilter
        return
    }

    $Condition = "$PropertyName+eq+'$ObjectId'"

    if ([string]::IsNullOrWhiteSpace($InitialFilter))
    {
        Write-Output $Condition
    }
    else {
        Write-Output "$InitialFilter+$Operator+$Condition"
    }
}

###########################################
# Wrappers for app management  as documented in https://aka.ms/aadgallery-sso-api 
###########################################

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

$MFAMigratableRules =
@{
"MFA for a User" = 
@"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid", Value == "__ANYVALUE__"]
 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", Value = "http://schemas.microsoft.com/claims/multipleauthn");
"@;
"MFA for a Group" = 
@"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "__ANYVALUE__"]
 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", Value = "http://schemas.microsoft.com/claims/multipleauthn");
"@;
"MFA for unregistered devices" = 
@"
c:[Type == "http://schemas.microsoft.com/2012/01/devicecontext/claims/isregistereduser", Value == "false"]
 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", Value = "http://schemas.microsoft.com/claims/multipleauthn");
"@
"MFA for extranet" = 
@"
c:[Type == "http://schemas.microsoft.com/ws/2012/01/insidecorporatenetwork", Value == "false"]
 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", Value = "http://schemas.microsoft.com/claims/multipleauthn");
"@
}

$DelegationMigratableRules =
@{
}

$ImpersonationMigratableRules =
@{
"ADFS V2 - ProxySid by user" = 
@"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid", Issuer =~ "^(AD AUTHORITY|SELF AUTHORITY|LOCAL AUTHORITY)$"]
 => issue(store = "_ProxyCredentialStore", types = ("http://schemas.microsoft.com/authorization/claims/permit"), query = "isProxySid({0})", param = c.Value);
"@
"ADFS V2 - ProxySid by group" =
@"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Issuer =~ "^(AD AUTHORITY|SELF AUTHORITY|LOCAL AUTHORITY)$"]
 => issue(store = "_ProxyCredentialStore", types = ("http://schemas.microsoft.com/authorization/claims/permit"), query = "isProxySid({0})", param = c.Value);
"@
"ADFS V2 - Proxy Trust check" =
@"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/proxytrustid", Issuer =~ "^SELF AUTHORITY$"]
 => issue(store = "_ProxyCredentialStore", types = ("http://schemas.microsoft.com/authorization/claims/permit"), query = "isProxyTrustProvisioned({0})", param = c.Value);
"@
}

$IssuanceAuthorizationMigratableRules =
@{
"Permit All" = 
@"
@RuleTemplate = "AllowAllAuthzRule"
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");
"@
"Permit a group" =
@"
Assign to groups
@RuleTemplate = "Authorization"
@RuleName = "__ANYVALUE__"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value =~ "__ANYVALUE__"]
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "PermitUsersWithClaim");
"@
}

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

Function Test-ADFSRPAdditionalAuthenticationRules
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    Test-ADFSRPRuleset `
        -RulesetName "AdditionalAuthentication" `
        -ADFSRuleSet $ADFSRelyingPartyTrust.AdditionalAuthenticationRules `
        -KnownRules $MFAMigratableRules `
        -ResultTypeIfUnknownPattern Fail

}

Function Test-ADFSRPDelegationAuthorizationRules
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    Test-ADFSRPRuleset `
        -RulesetName "DelegationAuthorization" `
        -ADFSRuleSet $ADFSRelyingPartyTrust.DelegationAuthorizationRules `
        -KnownRules $DelegationMigratableRules `
        -ResultTypeIfUnknownPattern Warning

}

Function Test-ADFSRPImpersonationAuthorizationRules
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    Test-ADFSRPRuleset `
        -RulesetName "ImpersonationAuthorization" `
        -ADFSRuleSet $ADFSRelyingPartyTrust.ImpersonationAuthorizationRules `
        -KnownRules $ImpersonationMigratableRules `
        -ResultTypeIfUnknownPattern Warning

}

Function Test-ADFSRPIssuanceAuthorizationRules
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    Test-ADFSRPRuleset `
        -RulesetName "IssuanceAuthorization" `
        -ADFSRuleSet $ADFSRelyingPartyTrust.IssuanceAuthorizationRules `
        -KnownRules $IssuanceAuthorizationMigratableRules `
        -ResultTypeIfUnknownPattern Warning
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
# RP Trust properties migration checks
###########################################

Function Test-ADFSRPAdditionalWSFedEndpoint
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    $TestResult = New-Object MigrationTestResult

    if ($ADFSRelyingPartyTrust.AdditionalWSFedEndpoint.Count -gt 0)  
    {
        $TestResult.Result = [ResultType]::Fail
        $TestResult.Message = "Relying Party has additional WS-Federation Endpoints."
        
    }
    else
    {
        $TestResult.Message = "No additional WS-Federation endpoints were found"
    }

    $TestResult.Details.Add("AdditionalWSFedEndpoint.Count", $ADFSRelyingPartyTrust.AdditionalWSFedEndpoint.Count)

    Return $TestResult
}

Function Test-ADFSRPAllowedAuthenticationClassReferences
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    $TestResult = New-Object MigrationTestResult

    if ($ADFSRelyingPartyTrust.AllowedAuthenticationClassReferences.Count -gt 0)  
    {
        $TestResult.Result = [ResultType]::Fail
        $TestResult.Message = "Relying Party has set AllowedAuthenticationClassReferences."
        
    }
    else
    {
        $TestResult.Message = "AllowedAuthenticationClassReferences is not set up."
    }

    $TestResult.Details.Add("AllowedAuthenticationClassReferences.Count", $ADFSRelyingPartyTrust.AllowedAuthenticationClassReferences.Count)

    Return $TestResult
}

Function Test-ADFSRPAlwaysRequireAuthentication
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    $TestResult = New-Object MigrationTestResult

    if ($ADFSRelyingPartyTrust.AlwaysRequireAuthentication)  
    {
        $TestResult.Result = [ResultType]::Fail
        $TestResult.Message = "Relying Party has AlwaysRequireAuthentication enabled"        
    }
    else
    {
        $TestResult.Message = "AlwaysRequireAuthentication is not set up."
    }

    $TestResult.Details.Add("AlwaysRequireAuthentication", $ADFSRelyingPartyTrust.AlwaysRequireAuthentication)

    Return $TestResult
}

Function Test-ADFSRPAutoUpdateEnabled
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    $TestResult = New-Object MigrationTestResult

    if ($ADFSRelyingPartyTrust.AutoUpdateEnabled) #CSV: False is string "0"
    {
        $TestResult.Result = [ResultType]::Warning
        $TestResult.Message = "Relying Party has AutoUpdateEnabled set to true"
        
    }
    else
    {
        $TestResult.Message = "AutoUpdateEnabled is not set up."
    }

    $TestResult.Details.Add("AutoUpdateEnabled", $ADFSRelyingPartyTrust.AutoUpdateEnabled)

    Return $TestResult
}

Function Test-ADFSRPClaimsProviderName
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )


    $TestResult = New-Object MigrationTestResult
    $TestResult.Details.Add("ClaimsProviderName.Count", $ADFSRelyingPartyTrust.ClaimsProviderName.Count)
     
    if ($ADFSRelyingPartyTrust.ClaimsProviderName.Count -gt 1) 
    {
        $TestResult.Result = [ResultType]::Fail
        $TestResult.Message = "Relying Party has multiple ClaimsProviders enabled"        
    }
    elseif ($ADFSRelyingPartyTrust.ClaimsProviderName.Count -eq 1 -and $ADFSRelyingPartyTrust.ClaimsProviderName[0] -ne 'Active Directory')
    {
        $TestResult.Result = [ResultType]::Fail
        $TestResult.Message = "Relying Party has a non-Active Directory store: $($ADFSRelyingPartyTrust.ClaimsProviderName[0])"        
    }
    else
    {
        $TestResult.Message = "No Additional Claim Providers were configured."
    }

    

    Return $TestResult
}

Function Test-ADFSRPEncryptClaims
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    $TestResult = New-Object MigrationTestResult

    #CSV: "0" string is false

    if ($ADFSRelyingPartyTrust.EncryptClaims -and $ADFSRelyingPartyTrust.EncryptionCertificate -ne $null)
    {
        $TestResult.Result = [ResultType]::Pass
        $TestResult.Message = "Relying Party is set to encrypt claims. This is supported by Azure AD"
        
    }
    else
    {
        $TestResult.Message = "Relying Party is not set to encrypt claims."
    }

    $TestResult.Details.Add("EncryptClaims", $ADFSRelyingPartyTrust.EncryptClaims)

    Return $TestResult
}

Function Test-ADFSRPEncryptedNameIdRequired
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    $TestResult = New-Object MigrationTestResult

    #CSV: "0" string is false

    if ($ADFSRelyingPartyTrust.EncryptedNameIdRequired -and $ADFSRelyingPartyTrust.EncryptionCertificate -ne $null)
    {
        $TestResult.Result = [ResultType]::Fail
        $TestResult.Message = "Relying Party is set to encrypt Name ID."
        
    }
    else
    {
        $TestResult.Message = "Relying Party is not set to encrypt name ID."
    }

    $TestResult.Details.Add("EncryptedNameIdRequired", $ADFSRelyingPartyTrust.EncryptedNameIdRequired)

    Return $TestResult
}

Function Test-ADFSRPMonitoringEnabled
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    $TestResult = New-Object MigrationTestResult

    if ($ADFSRelyingPartyTrust.MonitoringEnabled) #CSV: boolean syntax
    {
        $TestResult.Result = [ResultType]::Warning
        $TestResult.Message = "Relying Party has MonitoringEnabled set to true"
        
    }
    else
    {
        $TestResult.Message = "MonitoringEnabled is not set up."
    }

    $TestResult.Details.Add("MonitoringEnabled", $ADFSRelyingPartyTrust.MonitoringEnabled)

    Return $TestResult
}

Function Test-ADFSRPNotBeforeSkew
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    $TestResult = New-Object MigrationTestResult

    if ($ADFSRelyingPartyTrust.NotBeforeSkew -gt 0) #CSV: Int Syntax
    {
        $TestResult.Result = [ResultType]::Warning
        $TestResult.Message = "Relying Party has NotBeforeSkew configured"
        
    }
    else
    {
        $TestResult.Message = "NotBeforeSkew is not set up."
    }

    $TestResult.Details.Add("NotBeforeSkew", $ADFSRelyingPartyTrust.NotBeforeSkew)

    Return $TestResult
}

Function Test-ADFSRPRequestMFAFromClaimsProviders 
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    $TestResult = New-Object MigrationTestResult

    if ($ADFSRelyingPartyTrust.RequestMFAFromClaimsProviders) #CSV: Boolean syntax
    {
        $TestResult.Result = [ResultType]::Warning
        $TestResult.Message = "Relying Party has RequestMFAFromClaimsProviders set to true"
        
    }
    else
    {
        $TestResult.Message = "RequestMFAFromClaimsProviders is not set up."
    }

    $TestResult.Details.Add("RequestMFAFromClaimsProviders", $ADFSRelyingPartyTrust.RequestMFAFromClaimsProviders)

    Return $TestResult
}

Function Test-ADFSRPSignedSamlRequestsRequired 
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    $TestResult = New-Object MigrationTestResult

    if ($ADFSRelyingPartyTrust.SignedSamlRequestsRequired) #CSV: Boolean syntax
    {
        $TestResult.Result = [ResultType]::Warning
        $TestResult.Message = "Relying Party has SignedSamlRequestsRequired set to true"
        
    }
    else
    {
        $TestResult.Message = "SignedSamlRequestsRequired is not set up."
    }

    $TestResult.Details.Add("SignedSamlRequestsRequired", $ADFSRelyingPartyTrust.SignedSamlRequestsRequired)

    Return $TestResult
}

Function Test-ADFSRPTokenLifetime
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true)]
        $ADFSRelyingPartyTrust
    )

    $TestResult = New-Object MigrationTestResult

    if ($ADFSRelyingPartyTrust.TokenLifetime -gt 0 -and $ADFSRelyingPartyTrust.TokenLifetime -lt 10) #CSV: Int Syntax
    {
        $TestResult.Result = [ResultType]::Fail
        $TestResult.Message = "TokenLifetime is set to less than 10 minutes"
        
    }
    else
    {
        $TestResult.Message = "TokenLifetime is set to a supported value."
    }

    $TestResult.Details.Add("TokenLifetime", $ADFSRelyingPartyTrust.TokenLifetime)

    Return $TestResult
}

###########################################
# Orchestrating functions
###########################################

Function Invoke-TestFunctions([array]$functionsToRun, $ADFSRelyingPartyTrust)
{
    $RPStopWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $results = @()
    $totalFunctions = $functionsToRun.Count
    $functionCount = 0
    foreach($function in $functionsToRun)
    {
        $FunctionStopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        $StartTime = (Get-Date).Millisecond
        $functionCount++
        $percent = 100 * $functionCount / $totalFunctions
        #Write-Progress -Activity "Executing Tests" -Status $function -PercentComplete $percent -Id 10 -ParentId 1
        $ScriptString = "param(`$ADFSRP) $function -ADFSRelyingPartyTrust `$ADFSRP"
        $functionScriptBlock = [ScriptBlock]::Create($ScriptString)        
        $result = Invoke-Command -NoNewScope -ScriptBlock $functionScriptBlock  -ArgumentList ($ADFSRelyingPartyTrust)
        $result.TestName = $function
        $result.ADFSObjectType = "Relying Party"
        $result.ADFSObjectIdentifier = $ADFSRelyingPartyTrust.Name
        $results = $results + $result
        $FunctionStopWatch.Stop()
        #Write-Debug "$function`: $($FunctionStopWatch.Elapsed.TotalMilliseconds) milliseconds to run"
    }
    $RPStopWatch.Stop()
    Write-Debug "-------------$($ADFSRelyingPartyTrust.Name)`: $($RPStopWatch.Elapsed.TotalMilliseconds) milliseconds to run"

    return $results
}


<# 
 .Synopsis
  Analyzes an individual Relying Party trust object  

 .Description
  The cmdlet expects an RP Trust object and returns an object with four complex properties: 
  * AggregateReportRow: Object with  individual properties per each compatibility test performed
  (e.g. Test-ADFSRPAdditionalWSFedEndpoint)
  * AttributeReportRows: List of Active Directory Attributes found in the RP Trust rule sets. 
  There is one element in the list for every attribute found
  * AttributeStoreReportRows: List of Attribute Stores found in the RP Trust rule sets. There is one 
  element for every RP Trust and Attribute store found
  * ClaimTypeReportRows: List of Claim Types found in the RP Trust rule sets. There is one row for every 
  RP Trust and Claim Type found

 .Parameter ADFSRPTrust
  AD FS Relying party trust Object (either deserialized from a file or straight from AD FS Powershell) 
 
 .Example 
  Run the test from the ADFS Federation Server:
  Get-AdfsRelyingPartyTrust -Identifier urn:myCRMApp | Test-ADFS2AADOnPremRPTrust 
#> 


Function Test-ADFS2AADOnPremRPTrust
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $ADFSRPTrust
    )

     $functionsToRun =  @( `
	    "Test-ADFSRPAdditionalAuthenticationRules",
        "Test-ADFSRPAdditionalWSFedEndpoint",
        "Test-ADFSRPAllowedAuthenticationClassReferences",
        "Test-ADFSRPAlwaysRequireAuthentication",
        "Test-ADFSRPAutoUpdateEnabled",
        "Test-ADFSRPClaimsProviderName",
        "Test-ADFSRPDelegationAuthorizationRules", #out
        "Test-ADFSRPEncryptClaims",
        "Test-ADFSRPImpersonationAuthorizationRules", #out
        "Test-ADFSRPIssuanceAuthorizationRules", #out
        "Test-ADFSRPIssuanceTransformRules",
        "Test-ADFSRPMonitoringEnabled",
        "Test-ADFSRPNotBeforeSkew",
        "Test-ADFSRPRequestMFAFromClaimsProviders",
        "Test-ADFSRPSignedSamlRequestsRequired",
        "Test-ADFSRPTokenLifetime",
        "Test-ADFSRPEncryptedNameIdRequired"
    );

    $rpTestResults  =  Invoke-TestFunctions -FunctionsToRun $functionsToRun -ADFSRelyingPartyTrust $ADFSRPTrust

    $attributeReportRows = @()
    $attributeStoreReportRows = @()
    $claimTypesReportRows = @()
    $RuleDetailReportRows = @()

    #now, assemble the result object
    $aggregateReportRow= New-Object -TypeName PSObject
    $aggregateReportRow| Add-Member -MemberType NoteProperty -Name "RP Name" -Value $ADFSRPTrust.Name
    $aggregateReportRow| Add-Member -MemberType NoteProperty -Name "Result" -Value Pass

    $aggregateMessage = ""
    $aggregateDetail = ""
    $aggregateNotPassTests = ""     


    foreach($rpTestResult in $rpTestResults)
    {

        $aggregateReportRow | Add-Member -MemberType NoteProperty -Name $rpTestResult.TestName -Value $rpTestResult.Result

        if ($rpTestResult.Result -eq [ResultType]::Fail)
        {
            $aggregateReportRow.Result = [ResultType]::Fail
            $aggregateNotPassTests += $rpTestResult.TestName + "(Fail);" 
        }

        if ($rpTestResult.Result -eq [ResultType]::Warning -and $aggregateReportRow.Result -ne [ResultType]::Fail)
        {
            $aggregateReportRow.Result = [ResultType]::Warning
            $aggregateNotPassTests += $rpTestResult.TestName + "(Warning);"
        }

        if (-Not [String]::IsNullOrWhiteSpace( $rpTestResult.Message))
        {
            $aggregateMessage += $rpTestResult.TestName + "::" + $rpTestResult.Message.replace("`r``n",",") + "||"              
        }
            
        foreach($detailKey in $rpTestResult.Details.Keys)
        {
            if (-Not [String]::IsNullOrWhiteSpace($rpTestResult.Details[$detailKey]))
            {
                $aggregateDetail += $rpTestResult.TestName + "::" + $detailKey + "->" +  $rpTestResult.Details[ $detailKey].ToString().replace("`r`n",",") + "||"
            }

            #additional parsing for claim rule checks
            if ($detailKey -eq "ClaimRuleProperties")
            {
                $ClaimRuleProperties = $rpTestResult.Details[$detailKey]

                foreach($claimRuleProperty in $ClaimRuleProperties)
                {
                    $RuleDetailReportRow =  New-Object -TypeName PSObject -Property @{
                            "RP Name" = $ADFSRPTrust.Name
                            "Rule" = $claimRuleProperty.Rule
                            RuleSet = $claimRuleProperty.RuleSet
                            IsKnownRuleMigratablePattern = $claimRuleProperty.IsKnownRuleMigratablePattern
                            KnownRulePatternName = $claimRuleProperty.KnownRulePatternName
                    }

                    $RuleDetailReportRows += $RuleDetailReportRow
                    
                
                    #ImportFromCsv Application.ActiveWorkbook.Path & "\Attributes.csv", "AD Attributes", 1, 1
                    #RP Name, RuleSet, ADAttribute
                    foreach ($ADAttribute in $claimRuleProperty.ADAttributes)
                    {
                        $AttributeReportRow =  New-Object -TypeName PSObject -Property @{
                            "RP Name" = $ADFSRPTrust.Name
                            "Rule" = $claimRuleProperty.Rule
                            RuleSet = $claimRuleProperty.RuleSet
                            ADAttribute = $ADAttribute
                        }
                        $attributeReportRows += $AttributeReportRow
                    }

                    if ($claimRuleProperty.AttributeStoreName -ne "N/A")
                    {
                        $AttributeStoreReportRow =  New-Object -TypeName PSObject -Property @{
                            "RP Name" = $ADFSRPTrust.Name
                            "Rule" = $claimRuleProperty.Rule
                            AttributeStoreName = $claimRuleProperty.AttributeStoreName
                        }
                        $attributeStoreReportRows += $AttributeStoreReportRow
                    }

                    if ($claimRuleProperty.RuleSet -eq "IssuanceTransform")
                    {
                        foreach ($ClaimType in $claimRuleProperty.IssuanceClaimTypes)
                        {
                            $claimTypesReportRow =  New-Object -TypeName PSObject -Property @{
                                "RP Name" = $ADFSRPTrust.Name
                                "Rule" = $claimRuleProperty.Rule
                                "Claim Type" = $ClaimType
                            }
                            $claimTypesReportRows += $claimTypesReportRow
                        }
                    }
                }
            }
        }
    }

    $aggregateReportRow | Add-Member -MemberType NoteProperty -Name "Message" -Value $aggregateMessage
    $aggregateReportRow | Add-Member -MemberType NoteProperty -Name "Details" -Value $aggregateDetail
    $aggregateReportRow | Add-Member -MemberType NoteProperty -Name "NotPassedTests" -Value $aggregateNotPassTests


    New-Object -TypeName PSObject -Property @{
        AggregateReportRow = $aggregateReportRow
        AttributeReportRows = $attributeReportRows
        AttributeStoreReportRows = $attributeStoreReportRows
        ClaimTypeReportRows = $claimTypesReportRows
        RuleDetailReportRows = $RuleDetailReportRows
    }
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
            Write-Debug "Did not read backclaims mapping policy ... sleeping $millisecondsWait milliseconds"
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





