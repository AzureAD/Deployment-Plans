<# 
 
.SYNOPSIS
	ADFSAADMigrationUtils.psm1 is a Windows PowerShell module that contains functions to analyze ADFS configuration and tests for compatibility to Migrate to Azure Active Directory

.DESCRIPTION

	Version: 1.0.0

	ADFSAADMigrationUtils.psm1 is a Windows PowerShell module that contains functions to analyze ADFS configuration and tests for compatibility to Migrate to Azure Active Directory


.DISCLAIMER
	THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
	ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
	THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
	PARTICULAR PURPOSE.

	Copyright (c) Microsoft Corporation. All rights reserved.
#>

Function Remove-InvalidFileNameChars 
{
  param(
    [Parameter(Mandatory=$true,
      Position=0,
      ValueFromPipeline=$true,
      ValueFromPipelineByPropertyName=$true)]
    [String]$Name
  )

  $invalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $re = "[{0}]" -f [RegEx]::Escape($invalidChars)
  return ($Name -replace $re)
}


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

    if ($ADFSRelyingPartyTrust.AdditionalWSFedEndpoint.Count -gt 0) #TODO: CSV key to be empty would be "[]"
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

    if ($ADFSRelyingPartyTrust.AllowedAuthenticationClassReferences.Count -gt 0) #For csv, the value from kusto is "[]"
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

    if ($ADFSRelyingPartyTrust.AlwaysRequireAuthentication) #CSV: false comes as string "0"
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
     
    if ($ADFSRelyingPartyTrust.ClaimsProviderName.Count -gt 1) #CSV: Kusto comes with a array syntax
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

    if (($ADFSRelyingPartyTrust.EncryptClaims -or $ADFSRelyingPartyTrust.EncryptedNameIdRequired) -and $ADFSRelyingPartyTrust.EncryptionCertificate -ne $null)
    {
        $TestResult.Result = [ResultType]::Fail
        $TestResult.Message = "Relying Party is set to encrypt claims and/or nameid."
        
    }
    else
    {
        $TestResult.Message = "Relying Party is set to encrypt claims and/or nameid."
    }

    $TestResult.Details.Add("EncryptClaims", $ADFSRelyingPartyTrust.EncryptClaims)
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
        $TestResult.Result = [ResultType]::Fail
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
        "Test-ADFSRPTokenLifetime"
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

<# 
 .Synopsis
  Analyzes a set of Relying Party trusts and produces CSV files with the results

 .Description
  The cmdlet expects either a root folder where the RP Trusts are serialized in XML format,
  or a CSV file that has all the RP Trust information. After executing, the following files 
  are created in the directory from which the cmdlet ran:
  
  1. ADFSRPConfiguration.csv: This file has one row per RP Trust. There are individual columns
  per each compatibility test (e.g. Test-ADFSRPAdditionalWSFedEndpoint)
  2. Attributes.csv: This file contains the list of Active Directory Attributes found in the RP 
  Trust rule sets. There is one row for each RP Trust/attribute found.
  3. AttributeStores.csv: This file contains the list of Attribute Stores found in the RP Trust
  rule sets. There is one row for each RP Trust and Attribute store found
  4. ClaimTypes.csv: This file contains the list of Claim Types found in the RP Trust rule sets.
  There is one row for each RP Trust and Claim Type found


 .Parameter RPXMLFileDirectory
  Path to a directory that contains XML files with RP Trust information. 
  To export the CSVFiles in XML format, run the cmdlet Export-ADFS2AADOnPremConfiguration in the ADFS
  server; then, unzip the generated ZIP file and provide "apps" subfolder to the Test-ADFS2AADOnPremRPTrustSet
  cmdlet.

 .Parameter RPCSVFilePath
  
 .Example 
  Run from a root folder that has XML serialized files
  Test-ADFS2AADOnPremRPTrustSet -RPXMLFileDirectory "C:\ADFSConfig\Apps"

 .Example 
  Run from a CSV file from the ADFS Server
  Get-ADFSRelyingPartyTrust | ConvertTo-Csv -NoTypeInformation | Out-File "C:\ADFSConfig\OnPremRPs.csv"
  Test-ADFS2AADOnPremRPTrustSet -RPCSVFilePath "C:\ADFSConfig\OnPremRPs.csv" 
#>

Function Test-ADFS2AADOnPremRPTrustSet
{
    [CmdletBinding()]
    param
    (    
        [Parameter(Mandatory=$true, ParameterSetName="RPXMLFileDirectory")]
        [String]
        $RPXMLFileDirectory,

        [Parameter(Mandatory=$true, ParameterSetName="RPCSVFilePath")]
        [String]
        $RPCSVFilePath
    )

    $trustSetTestOutput = @()

    if ( $PSCmdlet.ParameterSetName -eq "RPXMLFileDirectory" )
    {
        $fileEntries = [IO.Directory]::GetFiles($RPXMLFileDirectory);
        $totalRPs = $fileEntries.Count
        $rpCount = 0
    
    
        foreach($fileName in $fileEntries) 
        {
            $rpCount++
            $percent = 100 * $rpCount / $totalRPs
            
            
            $ADFSRPTrust = Import-clixml $fileName
            $RPTrustName = $ADFSRPTrust.Name 
            
            Write-Progress -Activity "Analyzing Relying Parties" -Status "Processing $RPTrustName" -PercentComplete $percent -Id 1
            $rpTestResults  = Test-ADFS2AADOnPremRPTrust -ADFSRPTrust $ADFSRPTrust

            $trustSetTestOutput += $rpTestResults
        }
    } elseif ( $PSCmdlet.ParameterSetName -eq "RPCSVFilePath" ) 
    {
        $RPTrusts = Get-Content -Path $RPCSVFilePath -Raw | ConvertFrom-Csv

        $totalRPs = $RPTrusts.Count
        $rpCount = 0
    
    
        foreach($ADFSRPTrust in $RPTrusts) 
        {
            $rpCount++
            $percent = 100 * $rpCount / $totalRPs

            $RPTrustName = $ADFSRPTrust.Name
            Write-Progress -Activity "Analyzing Relying Parties" -Status "Processing app $RPTrustName" -PercentComplete $percent -Id 1
            $rpTestResults  = Test-ADFS2AADOnPremRPTrust -ADFSRPTrust $ADFSRPTrust 
            $trustSetTestOutput +=  $rpTestResults
        }
    }
    else
    {
        throw "Invalid input"
    }

    #Serialize the reports in different files
    #TODO: Dedup??
    $trustSetTestOutput | Select-Object -ExpandProperty "AggregateReportRow" | ConvertTo-Csv -NoTypeInformation | Out-File ".\ADFSRPConfiguration.csv"
    $trustSetTestOutput | Select-Object -ExpandProperty "AttributeReportRows" | Select-Object -Property "RP Name","RuleSet","Rule", "ADAttribute" -Unique | ConvertTo-Csv -NoTypeInformation | Out-File ".\Attributes.csv"
    $trustSetTestOutput | Select-Object -ExpandProperty "AttributeStoreReportRows" | Select-Object -Property "RP Name","Rule", "AttributeStoreName" -Unique    | ConvertTo-Csv -NoTypeInformation | Out-File ".\AttributeStores.csv"
    $trustSetTestOutput | Select-Object -ExpandProperty "ClaimTypeReportRows" | Select-Object -Property "RP Name","Rule", "Claim Type" -Unique | ConvertTo-Csv -NoTypeInformation | Out-File ".\ClaimTypes.csv"
    $trustSetTestOutput | Select-Object -ExpandProperty "RuleDetailReportRows" | Select-Object -Property "RP Name","RuleSet","Rule", "IsKnownRuleMigratablePattern", "KnownRulePatternName" -Unique | ConvertTo-Csv -NoTypeInformation | Out-File ".\RuleDetails.csv"
    
}

<# 
 .Synopsis
  Exports the configuration of Relying Party Trusts and Claims Provider Trusts

 .Description
  Creates and zips a set of files that hold the configuration of AD FS claim providers and relying parties.
  The output files are created under a directory called "ADFS" in the system drive.
 

 .Example
  Export-ADFS2AADOnPremConfiguration
#>
Function Export-ADFS2AADOnPremConfiguration
{
    $filePathBase = "$env:systemdrive\ADFS\apps\"
    $zipfileBase = "$env:systemdrive\ADFS\zip\"
    $zipfileName = $zipfileBase + "ADFSApps.zip"
    mkdir $filePathBase -ErrorAction SilentlyContinue
    mkdir $zipfileBase -ErrorAction SilentlyContinue

    $AdfsRelyingPartyTrusts = Get-AdfsRelyingPartyTrust
    foreach ($AdfsRelyingPartyTrust in $AdfsRelyingPartyTrusts)
    {
        $RPfileName = $AdfsRelyingPartyTrust.Name.ToString()
        $CleanedRPFileName = Remove-InvalidFileNameChars -Name $RPfileName
        $RPName = "RPT - " + $CleanedRPFileName
        $filePath = $filePathBase + $RPName + '.xml'
        $AdfsRelyingPartyTrust | Export-Clixml $filePath -ErrorAction SilentlyContinue
    }

    $AdfsClaimsProviderTrusts = Get-AdfsClaimsProviderTrust
    foreach ($AdfsClaimsProviderTrust in $AdfsClaimsProviderTrusts)
    {
 
        $CPfileName = $AdfsClaimsProviderTrust.Name.ToString()
        $CleanedCPFileName = Remove-InvalidFileNameChars -Name $CPfileName
        $CPTName = "CPT - " + $CleanedCPFileName
        $filePath = $filePathBase + $CPTName + '.xml'
        $AdfsClaimsProviderTrust | Export-Clixml $filePath -ErrorAction SilentlyContinue
 
    } 

    If (Test-Path $zipfileName)
    {
        Remove-Item $zipfileName
    }

    Add-Type -assembly "system.io.compression.filesystem"
    [io.compression.zipfile]::CreateFromDirectory($filePathBase, $zipfileName)
    
    invoke-item $zipfileBase
}

Export-ModuleMember Export-ADFS2AADOnPremConfiguration
Export-ModuleMember Test-ADFS2AADOnPremRPTrust
Export-ModuleMember Test-ADFS2AADOnPremRPTrustSet
