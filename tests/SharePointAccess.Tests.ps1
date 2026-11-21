# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-spo-$([guid]::NewGuid().ToString('n'))"
    $script:Write = { param([string] $Dir, [string] $Name, $Data) New-Item -ItemType Directory -Path $Dir -Force | Out-Null; ConvertTo-Json -InputObject $Data -Depth 10 | Set-Content -LiteralPath (Join-Path $Dir "$Name.json") }
    $script:Checks = {
        param([string] $Dir, [string[]] $Domain)
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache }
        $r = Invoke-PostureChecks -Evidence $Dir -Domain $Domain -PassThru; $by = @{}; foreach ($x in $r.results) { $by[$x.id] = $x }; $by
    }
    # Graph's admin/sharepoint/settings as it answers, trimmed to what the checks read.
    $script:Graph = { param([string] $Capability) [ordered]@{ sharingCapability = $Capability; sharingDomainRestrictionMode = 'allowList'; sharingAllowedDomainList = @('partner.example'); sharingBlockedDomainList = @(); isLegacyAuthProtocolsEnabled = $false; isResharingByExternalUsersEnabled = $false; isRequireAcceptingUserToMatchInvitedUserEnabled = $true } }
}

AfterAll { if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force } }

Describe 'SharePoint settings without the SharePoint admin read' {
    It 'judges what Graph returns and says exactly what needs the admin read' {
        $d = Join-Path $script:Root 'graph-guests'
        & $script:Write $d 'spo-tenant-settings-graph' (& $script:Graph 'externalUserSharingOnly')
        $by = & $script:Checks $d 'collaboration', 'copilot'
        $by['CL-001'].status | Should -Be 'pass'
        $by['CL-004'].status | Should -Be 'pass' -Because 'the allow list comes from Graph'
        $by['CL-016'].status | Should -Be 'pass' -Because 'OneDrive cannot be more open than a tenant without Anyone links'
        $by['CL-002'].status | Should -Be 'pass'
        $by['CP-005'].status | Should -Be 'pass'
        foreach ($id in 'CL-003', 'CL-005', 'CL-006', 'CL-008', 'CP-004', 'CP-009') {
            $by[$id].status | Should -Be 'notEvaluated'
            $by[$id].reason | Should -Match 'Grant-PostureSharePointAccess\.ps1' -Because "$id names both ways to get the admin read"
            $by[$id].reason | Should -Match 'Get-SpoBaseline\.ps1'
        }
    }

    It 'leaves Anyone link expiry and OneDrive to the admin read when the tenant allows Anyone links' {
        $d = Join-Path $script:Root 'graph-anyone'
        & $script:Write $d 'spo-tenant-settings-graph' (& $script:Graph 'externalUserAndGuestSharing')
        $by = & $script:Checks $d 'collaboration', 'copilot'
        $by['CL-001'].status | Should -Be 'fail'
        foreach ($id in 'CL-002', 'CL-016', 'CP-005') { $by[$id].status | Should -Be 'notEvaluated' }
        $by['CL-016'].reason | Should -Match 'OneDrive sharing level'
    }

    It 'prefers the admin read when both files are in the folder' {
        $d = Join-Path $script:Root 'both'
        & $script:Write $d 'spo-tenant-settings-graph' (& $script:Graph 'externalUserSharingOnly')
        & $script:Write $d 'spo-tenant-settings' @{ SharingCapability = 'ExternalUserSharingOnly'; DefaultSharingLinkType = 'Direct'; DefaultLinkPermission = 'View'; OneDriveSharingCapability = 'ExternalUserSharingOnly'; SharingDomainRestrictionMode = 'None'; ExternalUserExpirationRequired = $true; ExternalUserExpireInDays = 30; ShowEveryoneClaim = $false; ShowEveryoneExceptExternalUsersClaim = $false; ShowAllUsersClaim = $false; EnableRestrictedAccessControl = $true }
        $by = & $script:Checks $d 'collaboration'
        $by['CL-003'].status | Should -Be 'pass'
        $by['CL-004'].status | Should -Be 'fail' -Because 'the admin read says no domain restriction, and it wins'
    }
}
