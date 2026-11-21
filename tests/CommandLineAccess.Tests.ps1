# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Write = { param([string] $Dir, [string] $Name, $Data) New-Item -ItemType Directory -Path $Dir -Force | Out-Null; ConvertTo-Json -InputObject $Data -Depth 12 | Set-Content -LiteralPath (Join-Path $Dir "$Name.json") }
    $script:Checks = {
        param([string] $Dir, [string[]] $Domain)
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache }
        $r = Invoke-PostureChecks -Evidence $Dir -Domain $Domain -PassThru; $by = @{}; foreach ($x in $r.results) { $by[$x.id] = $x }; $by
    }
    $script:Sp = { param([string] $AppId, $Required) @{ AppId = $AppId; DisplayName = $AppId; AccountEnabled = $true; AppRoleAssignmentRequired = $Required } }
}

Describe 'Admin command-line tools' {
    It 'counts a tool closed by assignment, by Conditional Access, or through the Azure API, and names the ones left open' {
        $d = Join-Path $TestDrive 'tools'
        & $script:Write $d '10-service-principals' @(
            (& $script:Sp '14d82eec-204b-4c2f-b7e8-296a70dab67e' $true)
            (& $script:Sp 'de8bc8b5-d9f9-48b1-a8ad-b748da725064' $false)
            (& $script:Sp 'fb78d390-0c51-40cd-8e17-fdbfab77341b' $false)
        )
        $policies = @(
            @{ displayName = 'Block Azure management'; state = 'enabled'; grantControls = @{ builtInControls = @('block') }; conditions = @{ users = @{ includeUsers = @('All'); excludeGroups = @('admins') }; applications = @{ includeApplications = @('797f4846-ba00-4fd7-ba43-dac1f8f63013') } } }
            @{ displayName = 'Block Teams PowerShell'; state = 'enabled'; grantControls = @{ builtInControls = @('block') }; conditions = @{ users = @{ includeUsers = @('All') }; applications = @{ includeApplications = @('12128f48-ec9e-42f0-b203-ea49fb6af367') } } }
        )
        & $script:Write $d 'policies' @{ value = $policies }
        InModuleScope TenantKeep.Posture -Parameters @{ D = $d } {
            $t = @(Get-PostureAdminToolRestriction -Evidence $D)
            $t.Count | Should -Be 7
            ($t | Where-Object appId -eq '14d82eec-204b-4c2f-b7e8-296a70dab67e').how | Should -Be 'assignment required'
            ($t | Where-Object appId -eq '04b07795-8ddb-461a-bbee-02f9e1bf7b46').how | Should -Match 'Azure management blocked'
            ($t | Where-Object appId -eq '12128f48-ec9e-42f0-b203-ea49fb6af367').restricted | Should -BeTrue
            ($t | Where-Object appId -eq 'de8bc8b5-d9f9-48b1-a8ad-b748da725064').detail | Should -Be 'anyone can sign in: assignment not required'
            ($t | Where-Object appId -eq '9bc3ab49-b65d-410a-85ad-de819febfddc').detail | Should -Match 'no enterprise app in the tenant yet'
        }
        $by = & $script:Checks $d 'identity'
        $by['ID-023'].status | Should -Be 'fail'
        @($by['ID-023'].affected.name | Sort-Object) | Should -Be @('Exchange Online PowerShell', 'Graph Explorer', 'SharePoint Online Management Shell')
    }
}

Describe 'Device code sign-in' {
    BeforeAll {
        $script:Ca = {
            param([string] $Dir, $Policies)
            New-Item -ItemType Directory -Path $Dir -Force | Out-Null
            Copy-Item -Path (Join-Path $PSScriptRoot '..' 'samples' 'ca-snapshot' '*.json') -Destination $Dir
            if ($null -ne $Policies) { & $script:Write $Dir 'policies' @{ value = $Policies } }
        }
    }

    It 'passes with a policy that blocks device code flow for everyone, fails without one, and says when the snapshot cannot tell' {
        $block = @{ id = 'p1'; displayName = 'Block device code'; state = 'enabled'; grantControls = @{ builtInControls = @('block'); operator = 'OR' }; conditions = @{ users = @{ includeUsers = @('All') }; applications = @{ includeApplications = @('All') }; authenticationFlows = @{ transferMethods = 'deviceCodeFlow,authenticationTransfer' } } }
        $other = @{ id = 'p2'; displayName = 'MFA'; state = 'enabled'; grantControls = @{ builtInControls = @('mfa'); operator = 'OR' }; conditions = @{ users = @{ includeUsers = @('All') }; applications = @{ includeApplications = @('All') }; authenticationFlows = $null } }
        $yes = Join-Path $TestDrive 'dc-yes'; & $script:Ca $yes @($block, $other)
        (& $script:Checks $yes 'ca')['CA-016'].status | Should -Be 'pass'
        $no = Join-Path $TestDrive 'dc-no'; & $script:Ca $no @($other)
        (& $script:Checks $no 'ca')['CA-016'].status | Should -Be 'fail' -Because 'the snapshot carries the property, and no policy blocks device code'
        $noFlows = @{ id = 'p3'; displayName = 'MFA'; state = 'enabled'; grantControls = @{ builtInControls = @('mfa'); operator = 'OR' }; conditions = @{ users = @{ includeUsers = @('All') }; applications = @{ includeApplications = @('All') } } }
        $old = Join-Path $TestDrive 'dc-old'; & $script:Ca $old @($noFlows)
        $r = (& $script:Checks $old 'ca')['CA-016']
        $r.status | Should -Be 'notEvaluated'
        $r.reason | Should -Match 'carries no authentication flows'
    }
}

Describe 'Exchange Online PowerShell for administrators only' {
    It 'counts people who are not administrators, leaving out shared mailboxes, and passes when the app is closed' {
        $d = Join-Path $TestDrive 'exo'
        & $script:Write $d 'exo-12-remote-powershell-users' @(
            @{ UserPrincipalName = 'admin1@contoso.example'; RecipientTypeDetails = 'UserMailbox' }
            @{ UserPrincipalName = 'user1@contoso.example'; RecipientTypeDetails = 'UserMailbox' }
            @{ UserPrincipalName = 'user2@contoso.example'; RecipientTypeDetails = 'UserMailbox' }
            @{ UserPrincipalName = 'billing@contoso.example'; RecipientTypeDetails = 'SharedMailbox' }
        )
        & $script:Write $d '04-role-assignments-active' @(@{ RoleName = 'Exchange Administrator'; PrincipalUpn = 'admin1@contoso.example' })
        & $script:Write $d 'exo-01-orgconfig' @{ Name = 'contoso' }
        & $script:Write $d '10-service-principals' @((& $script:Sp 'fb78d390-0c51-40cd-8e17-fdbfab77341b' $false))
        # Open on the app itself: without the Conditional Access snapshot a blocking policy cannot be ruled out.
        $unknown = (& $script:Checks $d 'email')['EM-025']
        $unknown.status | Should -Be 'notEvaluated'
        $unknown.reason | Should -Match 'facts\.exoPowerShellAppRestricted has no value.*Not collected: policies\.json'
        & $script:Write $d 'policies' @()
        $by = & $script:Checks $d 'email'
        $by['EM-025'].status | Should -Be 'fail'
        @($by['EM-025'].affected.name) | Should -Be @('user1@contoso.example', 'user2@contoso.example')
        & $script:Write $d '10-service-principals' @((& $script:Sp 'fb78d390-0c51-40cd-8e17-fdbfab77341b' $true))
        (& $script:Checks $d 'email')['EM-025'].status | Should -Be 'pass' -Because 'the app is closed to everyone but an assigned group'
    }

    It 'takes the collector''s count when the list holds the first 500, and says what it cannot know' {
        $d = Join-Path $TestDrive 'exo-counted'
        $list = @(1..500 | ForEach-Object { @{ UserPrincipalName = "user$_@contoso.example"; RecipientTypeDetails = 'UserMailbox' } })
        & $script:Write $d 'exo-12-remote-powershell-users' $list
        & $script:Write $d 'exo-01-orgconfig' @{ Name = 'contoso' }
        & $script:Write $d '10-service-principals' @((& $script:Sp 'fb78d390-0c51-40cd-8e17-fdbfab77341b' $false))
        & $script:Write $d 'policies' @()
        & $script:Write $d '04-role-assignments-active' @(@{ Role = 'Exchange Administrator'; PrincipalType = 'user'; PrincipalUpn = 'user7@contoso.example' })
        # Counted with the administrators already left out: the number is the collector's, the list its first 500.
        & $script:Write $d 'exo-12-remote-powershell-summary' @{ RemotePowerShellEnabled = 41000; NonAdmin = 40000; Listed = 500; AdminsExcluded = $true }
        $r = (& $script:Checks $d 'email')['EM-025']
        $r.status | Should -Be 'fail'
        $r.affectedCount | Should -Be 40000
        $r.affectedListed | Should -Be 500
        $r.reason | Should -BeNullOrEmpty
        # Counted without knowing the administrators: the 500 listed are sorted out here, and the count is a floor.
        & $script:Write $d 'exo-12-remote-powershell-summary' @{ RemotePowerShellEnabled = 41000; NonAdmin = 40000; Listed = 500; AdminsExcluded = $false }
        $r = (& $script:Checks $d 'email')['EM-025']
        $r.status | Should -Be 'fail'
        $r.affectedCount | Should -Be 499 -Because 'user7 is an administrator'
        $r.reason | Should -Match '^At least 499: the list holds the first 500 of 40000 accounts and the administrators were not known when Exchange was collected'
    }
}
