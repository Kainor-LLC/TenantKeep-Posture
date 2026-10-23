# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'Tenantkeep.Posture.psd1') -Force
}

AfterAll { Remove-Module Tenantkeep.Posture -Force -ErrorAction SilentlyContinue }

Describe 'The module requirement table' {
    It 'names every service module the collectors use, with a parseable tested version and known collectors' {
        InModuleScope Tenantkeep.Posture {
            $rows = @(Get-PostureModuleRequirement)
            @($rows | ForEach-Object name) | Should -Be @('Microsoft.Graph.Authentication', 'ExchangeOnlineManagement', 'PnP.PowerShell', 'MicrosoftTeams', 'Az.Accounts', 'Az.ResourceGraph')
            $known = @('ConditionalAccess', 'Entra', 'Intune', 'Defender', 'Exchange', 'Purview', 'SharePoint', 'Teams', 'Azure')
            foreach ($r in $rows) {
                { [version]$r.tested } | Should -Not -Throw
                @($r.collectors).Count | Should -BeGreaterThan 0
                foreach ($c in $r.collectors) { $c | Should -BeIn $known }
                $r.note | Should -Not -BeNullOrEmpty
            }
        }
    }

    It 'keeps the Graph floor at or above what the manifest requires' {
        InModuleScope Tenantkeep.Posture {
            $manifest = Import-PowerShellDataFile -Path (Join-Path $script:ModuleRoot 'Tenantkeep.Posture.psd1')
            $required = [version]($manifest.RequiredModules | Where-Object { $_.ModuleName -eq 'Microsoft.Graph.Authentication' }).ModuleVersion
            [version](Get-PostureModuleRequirement -Name Microsoft.Graph.Authentication).tested | Should -BeGreaterOrEqual $required
        }
    }

    It 'refuses a module that is not in the table' {
        InModuleScope Tenantkeep.Posture { { Test-PostureModuleRequirement -Name 'Not.A.Module' } | Should -Throw '*not a module the collectors use*' }
    }
}

Describe 'Test-PostureModuleRequirement' {
    It 'reports missing with the install line' {
        InModuleScope Tenantkeep.Posture {
            Mock Get-Module { @() } -ParameterFilter { $ListAvailable }
            $r = Test-PostureModuleRequirement -Name PnP.PowerShell
            $r.status | Should -Be 'missing'
            $r.installed | Should -BeNullOrEmpty
            $r.message | Should -Be 'PnP.PowerShell is not installed: Install-Module PnP.PowerShell -Scope CurrentUser'
        }
    }

    It 'reports older with the update line, naming the collectors that use it' {
        InModuleScope Tenantkeep.Posture {
            Mock Get-Module { [pscustomobject]@{ Name = $Name; Version = [version]'2.12.0' }, [pscustomobject]@{ Name = $Name; Version = [version]'1.0.0' } } -ParameterFilter { $ListAvailable }
            $r = Test-PostureModuleRequirement -Name ExchangeOnlineManagement
            $r.status | Should -Be 'older'
            $r.installed | Should -Be ([version]'2.12.0') -Because 'the newest installed version is the one that loads'
            $r.message | Should -Match '^ExchangeOnlineManagement 2\.12\.0 is older than the version the collectors were tested with \(3\.10\.1\)\. If Exchange or Purview fails, update it: Update-Module ExchangeOnlineManagement$'
        }
    }

    It 'reports ok at or above the tested version, and present when the mock gives no version' {
        InModuleScope Tenantkeep.Posture {
            Mock Get-Module { [pscustomobject]@{ Name = $Name; Version = [version]'9.0.0' } } -ParameterFilter { $ListAvailable }
            (Test-PostureModuleRequirement -Name MicrosoftTeams).status | Should -Be 'ok'
            Mock Get-Module { $true } -ParameterFilter { $ListAvailable }
            $r = Test-PostureModuleRequirement -Name MicrosoftTeams
            $r.status | Should -Be 'present'
            $r.message | Should -Be ''
        }
    }
}

Describe 'Get-PostureModuleVersionUsed' {
    It 'prefers the loaded version, falls back to the newest installed, and records null for a missing module' {
        InModuleScope Tenantkeep.Posture {
            Mock Get-Module { if ($Name -eq 'Az.Accounts') { [pscustomobject]@{ Name = $Name; Version = [version]'5.5.3' } } } -ParameterFilter { -not $ListAvailable }
            Mock Get-Module {
                switch ($Name) {
                    'Az.Accounts' { [pscustomobject]@{ Name = $Name; Version = [version]'5.9.0' } }
                    'PnP.PowerShell' { [pscustomobject]@{ Name = $Name; Version = [version]'3.2.0' } }
                    default { @() }
                }
            } -ParameterFilter { $ListAvailable }
            $used = Get-PostureModuleVersionUsed
            $used['Az.Accounts'] | Should -Be '5.5.3' -Because 'the loaded version is the one the run used'
            $used['PnP.PowerShell'] | Should -Be '3.2.0'
            $used.Contains('ExchangeOnlineManagement') | Should -BeTrue
            $used['ExchangeOnlineManagement'] | Should -BeNullOrEmpty
        }
    }
}

Describe 'Get-PostureRequirement' {
    It 'returns one row per module with the installed and tested versions as text' {
        InModuleScope Tenantkeep.Posture {
            Mock Get-Module { if ($Name -eq 'MicrosoftTeams') { @() } else { [pscustomobject]@{ Name = $Name; Version = [version]'99.0.0' } } } -ParameterFilter { $ListAvailable }
            $rows = @(Get-PostureRequirement)
            $rows.Count | Should -Be 6
            ($rows | Where-Object Name -eq 'MicrosoftTeams').Status | Should -Be 'missing'
            ($rows | Where-Object Name -eq 'MicrosoftTeams').Installed | Should -Be ''
            ($rows | Where-Object Name -eq 'Az.Accounts').Status | Should -Be 'ok'
            ($rows | Where-Object Name -eq 'Az.Accounts').Installed | Should -Be '99.0.0'
            ($rows | Where-Object Name -eq 'Az.Accounts').Tested | Should -Be '5.5.3'
            @(Get-PostureRequirement -Name PnP.PowerShell).Count | Should -Be 1
        }
    }
}
