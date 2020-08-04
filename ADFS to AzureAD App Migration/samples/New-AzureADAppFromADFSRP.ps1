Import-Module AzureAD
Import-Module .\ADFS2AADUtils.psm1

#Connect to both Azure AD Powershell and MS Graph API Client library
Connect-MSGraphAPI | Out-Null
Connect-AzureAD | Out-Null

##Replace this values
$targetGalleryApp = "GalleryAppName"
$targetGroup = Get-AzureADGroup -SearchString "TestGroupName"
$targetAzureADRole = "TestRoleName"
$targetADFSRPId = "ADFSRPIdentifier"

#Run the code below if you need to cleanup
#$RP=Get-AdfsRelyingPartyTrust -Identifier $targetADFSRPId
#Get-AzureADServicePrincipal -SearchString $RP.Name | Remove-AzureADServicePrincipal; 
#Get-AzureADApplication -SearchString $RP.Name | Remove-AzureADApplication


#Query the app gallery
$galleryApp = Get-AzureADApplicationTemplate -DisplayNameFilter $targetGalleryApp

#Get the RP from ADFS
$RP=Get-AdfsRelyingPartyTrust -Identifier $targetADFSRPId

#Migrate!
New-AzureADAppFromADFSRPTrust `
    -AzureADAppTemplateId $galleryApp.id `
    -ADFSRelyingPartyTrust $RP `
    -TestGroupAssignmentObjectId $targetGroup.ObjectId `
    -TestGroupAssignmentRoleName $targetAzureADRole