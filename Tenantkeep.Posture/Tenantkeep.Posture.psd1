# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
@{
    RootModule        = 'Tenantkeep.Posture.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '3f1c2a7e-9b64-4e0d-a5c1-7d2e8f6b0c41'
    Author            = 'Connor Johnson'
    CompanyName       = 'Kainor LLC'
    Copyright         = '(c) 2026 Kainor LLC. All rights reserved. Source-available, see LICENSE.md.'
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
            LicenseUri   = 'https://github.com/Kainor-LLC/tenantkeep-posture/blob/main/LICENSE.md'
            ProjectUri   = 'https://github.com/Kainor-LLC/tenantkeep-posture'
            ReleaseNotes = 'Pre-release. One sign-in, every collector, thirteen check domains, the interactive report. See CHANGELOG.md.'
            Prerelease   = 'alpha'
        }
    }
}
