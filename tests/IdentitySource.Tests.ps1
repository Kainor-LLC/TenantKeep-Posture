# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Write = { param([string] $Dir, [string] $Name, $Data) New-Item -ItemType Directory -Path $Dir -Force | Out-Null; ConvertTo-Json -InputObject $Data -Depth 10 | Set-Content -LiteralPath (Join-Path $Dir "$Name.json") }
    $script:Checks = {
        param([string] $Dir, [string] $Model = 'hybrid-connect')
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache }
        $pf = Join-Path $Dir 'profile.json'
        @{ version = 1; identityModel = $Model } | ConvertTo-Json | Set-Content $pf
        $r = Invoke-PostureChecks -Evidence $Dir -Domain hybrid -ProfilePath $pf -PassThru; $by = @{}; foreach ($x in $r.results) { $by[$x.id] = $x }; @{ by = $by; run = $r }
    }
    $script:Fixture = {
        param([string] $Dir, [switch] $NoSource)
        & $script:Write $Dir '01-onprem-sync-features' @(@{ id = 't'; features = @{ passwordSyncEnabled = $true } })
        $groups = @(
            @{ Id = 'g-ca'; DisplayName = 'CA Exclusions'; OnPremisesSyncEnabled = $true; Source = 'ActiveDirectory'; Licensed = $false }
            @{ Id = 'g-lic'; DisplayName = 'E5 Users'; OnPremisesSyncEnabled = $true; Source = 'ActiveDirectory'; Licensed = $true }
            @{ Id = 'g-plain'; DisplayName = 'File Share'; OnPremisesSyncEnabled = $true; Source = 'ActiveDirectory'; Licensed = $false }
            @{ Id = 'g-moved'; DisplayName = 'Sales'; OnPremisesSyncEnabled = $false; Source = 'EntraFromAD'; Licensed = $false }
            @{ Id = 'g-cloud'; DisplayName = 'Project X'; OnPremisesSyncEnabled = $false; Source = 'Cloud'; Licensed = $false }
        )
        if ($NoSource) { foreach ($g in $groups) { $g.Remove('Source'); $g.Remove('Licensed') } }
        & $script:Write $Dir '07-groups' $groups
        $policies = @(
            @{ displayName = 'Require MFA'; state = 'enabled'; conditions = @{ users = @{ includeUsers = @('All'); excludeGroups = @('g-ca') } } }
            @{ displayName = 'Old draft'; state = 'disabled'; conditions = @{ users = @{ excludeGroups = @('g-plain') } } }
        )
        & $script:Write $Dir 'policies' @{ value = $policies }
        & $script:Write $Dir '06-users-summary' @{ Synced = 80; EntraManagedFromAd = 5; CloudOnlyMembers = 25 }
    }
}

Describe 'Users and groups managed in AD or in Entra' {
    It 'tells AD, switched-to-Entra and cloud objects apart from read-only properties' {
        InModuleScope TenantKeep.Posture {
            Get-PostureObjectSource -Object @{ onPremisesSyncEnabled = $true; onPremisesSecurityIdentifier = 'S-1-5-21-1' } | Should -Be 'ActiveDirectory'
            Get-PostureObjectSource -Object @{ onPremisesSyncEnabled = $null; onPremisesSecurityIdentifier = 'S-1-5-21-1' } | Should -Be 'EntraFromAD'
            Get-PostureObjectSource -Object @{ onPremisesSyncEnabled = $null } | Should -Be 'Cloud'
        }
    }

    It 'flags synced groups a live Conditional Access policy or a licence depends on, and measures how many moved' {
        $d = Join-Path $TestDrive 'mixed'
        & $script:Fixture $d
        $r = & $script:Checks $d
        $r.by['HY-032'].status | Should -Be 'fail'
        @($r.by['HY-032'].affected.name | Sort-Object) | Should -Be @('CA Exclusions', 'E5 Users') -Because 'a disabled policy grants nothing, and a group used nowhere is HY-033''s business'
        (@($r.by['HY-032'].affected) | Where-Object name -eq 'CA Exclusions').detail | Should -Be "synced from AD, left out of Conditional Access policy 'Require MFA'"
        $r.by['HY-033'].status | Should -Be 'fail'
        $r.by['HY-033'].observed['cloudManagedGroupPct'] | Should -Be 25 -Because 'one of four groups that came from AD is managed in Entra'
        $r.run.domains['hybrid'].facts['usersManagedInEntraFromAd'] | Should -Be 5
        InModuleScope TenantKeep.Posture -Parameters @{ D = $d; F = $r.run.domains['hybrid'].facts } {
            $c = Get-PostureChartData -Evidence $D -DomainFacts @{ hybrid = $F }
            @($c.identitySource.rows.label) | Should -Be @('Users', 'Groups that came from AD')
            @($c.identitySource.rows[0].segment | ForEach-Object { $_.value }) | Should -Be @(80, 5, 20)
            $c.identitySource.takeaway | Should -Be '2 group(s) still managed in AD decide cloud access.'
        }
    }

    It 'counts every synced group that access depends on when there are more than the 500 it lists' {
        $d = Join-Path $TestDrive 'many-groups'
        & $script:Fixture $d
        & $script:Write $d '07-groups' @(1..620 | ForEach-Object { @{ Id = "g$_"; DisplayName = "Licence group $_"; OnPremisesSyncEnabled = $true; Source = 'ActiveDirectory'; Licensed = $true } })
        $r = (& $script:Checks $d).by['HY-032']
        $r.status | Should -Be 'fail'
        $r.observed['syncedAccessGroups'] | Should -Be 620 -Because 'the number found is of the tenant, not of the rows kept for the report'
        $r.affectedCount | Should -Be 620
        $r.affectedListed | Should -Be 500
    }

    It 'reads older evidence for HY-032 and asks for a new collection for HY-033' {
        $d = Join-Path $TestDrive 'old'
        & $script:Fixture $d -NoSource
        $r = & $script:Checks $d
        $r.by['HY-032'].status | Should -Be 'fail'
        $r.by['HY-033'].status | Should -Be 'notEvaluated'
        $r.by['HY-033'].reason | Should -Match 'Resume-PostureRun -Collector Entra'
    }

    It 'is not applicable to a cloud-only tenant' {
        $d = Join-Path $TestDrive 'cloud'
        & $script:Fixture $d
        $r = & $script:Checks $d 'cloud-only'
        $r.by['HY-032'].status | Should -Be 'notApplicable'
        $r.by['HY-033'].status | Should -Be 'notApplicable'
    }
}
