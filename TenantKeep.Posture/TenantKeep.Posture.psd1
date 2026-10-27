# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
@{
    RootModule        = 'TenantKeep.Posture.psm1'
    ModuleVersion     = '0.3.0'
    GUID              = '3f1c2a7e-9b64-4e0d-a5c1-7d2e8f6b0c41'
    Author            = 'Connor Johnson'
    CompanyName       = 'Kainor LLC'
    Copyright         = '(c) 2026 Kainor LLC. PolyForm Shield 1.0.0, see LICENSE.md.'
    Description       = 'Read-only Microsoft 365 security posture report with Conditional Access documentation and diff.'
    PowerShellVersion = '7.4'
    CompatiblePSEditions = @('Core')

    RequiredModules   = @(
        @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0' }
    )

    # Maintained by build.ps1 from the Public/ folder. Keep in sync by hand for Import-Module from src/.
    FunctionsToExport = @(
        'Compare-PostureCaSnapshot',
        'Connect-PostureSession',
        'Disconnect-PostureSession',
        'Export-PostureCaSnapshot',
        'Export-PostureFindings',
        'Get-PostureLicense',
        'Get-PostureCheckCatalog',
        'Get-PostureRequirement',
        'Initialize-PostureClient',
        'Invoke-PostureChecks',
        'Invoke-PostureCollection',
        'New-PostureCaDocument',
        'New-PostureProfile',
        'New-PostureReport',
        'Start-PostureRun'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('Microsoft365', 'EntraID', 'ConditionalAccess', 'Security', 'Posture', 'Audit', 'PSEdition_Core', 'MacOS', 'Linux', 'Windows')
            LicenseUri   = 'https://github.com/Kainor-LLC/TenantKeep-Posture/blob/main/LICENSE.md'
            ProjectUri   = 'https://github.com/Kainor-LLC/TenantKeep-Posture'
            ReleaseNotes = 'Pre-release, Authenticode-signed by Kainor LLC. A free 30-day trial of every domain: Start-PostureRun prints the link when the tenant has no Full licence, and the report names a trial licence and its end date. CP-009 no longer fails a tenant that never set Restricted SharePoint Search. See CHANGELOG.md.'
            Prerelease   = 'alpha'
        }
    }
}
