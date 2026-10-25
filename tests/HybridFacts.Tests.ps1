# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-hybrid-$([guid]::NewGuid().ToString('n'))"
    $script:Ev = Join-Path $script:Root 'evidence'
    New-Item -ItemType Directory -Path $script:Ev -Force | Out-Null
    $w = { param([string] $Name, $Data) ConvertTo-Json -InputObject $Data -Depth 10 | Set-Content -LiteralPath (Join-Path $script:Ev "$Name.json") }
    # Entra side
    & $w '01-onprem-sync-features' @(@{ id = 't'; features = @{ passwordSyncEnabled = $true; blockSoftMatchEnabled = $false; blockCloudObjectTakeoverThroughHardMatchEnabled = $true; passwordWritebackEnabled = $false } })
    & $w '01-domains' @(@{ Id = 'contoso.example'; AuthenticationType = 'Managed' })
    & $w 'az-08-entra-connect-health' @(@{ Name = 'AadSyncService-contoso'; Type = 'AadSyncService'; Health = 'Healthy'; ActiveAlerts = 2 })
    # AD side, as the Windows collector writes it. Every value is made up.
    & $w 'ad-01-forest-domain' @{ ForestFunctionalLevel = 'Windows2016Forest'; DomainFunctionalLevel = 'Windows2012R2Domain'; RecycleBinEnabled = $true; MachineAccountQuota = 10; PasswordPolicy = @{ MinPasswordLength = 8; LockoutThreshold = 10; ReversibleEncryptionEnabled = $false } }
    & $w 'ad-01-trusts' @(@{ Name = 'partner.example'; Direction = 'Outbound'; TrustType = 'Uplevel'; SidFilteringQuarantined = $false; SidFilteringForestAware = $false; IntraForest = $false }, @{ Name = 'child.contoso.example'; Direction = 'BiDirectional'; TrustType = 'Uplevel'; SidFilteringQuarantined = $false; SidFilteringForestAware = $false; IntraForest = $true })
    & $w 'ad-02-domain-controllers' @(@{ Name = 'DC01'; OperatingSystem = 'Windows Server 2022 Standard'; Supported = $true }, @{ Name = 'DC02'; OperatingSystem = 'Windows Server 2012 R2 Standard'; Supported = $false })
    & $w 'ad-03-privileged-groups' @(
        @{ Group = 'Domain Admins'; SamAccountName = 'adm-alice'; ObjectClass = 'user' }, @{ Group = 'Domain Admins'; SamAccountName = 'adm-bob'; ObjectClass = 'user' }, @{ Group = 'Domain Admins'; SamAccountName = 'svc-backup'; ObjectClass = 'user' }, @{ Group = 'Domain Admins'; SamAccountName = 'adm-carol'; ObjectClass = 'user' }, @{ Group = 'Domain Admins'; SamAccountName = 'adm-dave'; ObjectClass = 'user' }, @{ Group = 'Domain Admins'; SamAccountName = 'adm-erin'; ObjectClass = 'user' }
        @{ Group = 'Schema Admins'; SamAccountName = 'adm-alice'; ObjectClass = 'user' }, @{ Group = 'DnsAdmins'; SamAccountName = 'svc-dns'; ObjectClass = 'user' }
    )
    & $w 'ad-03-admin-accounts' @(@{ SamAccountName = 'adm-alice'; Enabled = $true; PasswordAgeDays = 900; HasSpn = $false; AccountNotDelegated = $true; InProtectedUsers = $true; HasMailbox = $false }, @{ SamAccountName = 'adm-bob'; Enabled = $true; PasswordAgeDays = 30; HasSpn = $false; AccountNotDelegated = $false; InProtectedUsers = $false; HasMailbox = $true }, @{ SamAccountName = 'krbtgt'; Enabled = $false; PasswordAgeDays = 400; HasSpn = $true; AccountNotDelegated = $false; InProtectedUsers = $false; HasMailbox = $false })
    & $w 'ad-04-builtin-accounts' @{ KrbtgtPasswordAgeDays = 400; BuiltinAdministratorEnabled = $true; GuestEnabled = $false }
    & $w 'ad-05-delegation' @(@{ Name = 'DC01'; ObjectClass = 'computer'; IsDomainController = $true; Unconstrained = $true }, @{ Name = 'APP01'; ObjectClass = 'computer'; IsDomainController = $false; Unconstrained = $true })
    & $w 'ad-05-kerberoastable' @(@{ SamAccountName = 'svc-sql'; Enabled = $true; Spns = 2; PasswordAgeDays = 1200; AesOnly = $false; Privileged = $false })
    & $w 'ad-05-asrep-roastable' @()
    & $w 'ad-06-computers-summary' @{ EnabledComputers = 120; ActiveWindowsNonDc = 100; WindowsLaps = 80; LegacyLaps = 10 }
    & $w 'ad-07-users-summary' @{ Users = 700; Enabled = 600; StaleEnabled = 40; PasswordNeverExpiresEnabledHumans = 3 }
    & $w 'ad-08-gpos' @(@{ Name = 'Default Domain Policy'; Links = 1; HasCpassword = $false }, @{ Name = 'Old drive maps'; Links = 0; HasCpassword = $true })
    & $w 'ad-09-adcs' @{ Present = $true; EnrollmentServices = @(@{ Name = 'contoso-CA' }) }
    & $w 'ad-09-adcs-templates' @(@{ Name = 'User'; Published = $true; Esc1Candidate = $false }, @{ Name = 'VPN-Legacy'; Published = $true; Esc1Candidate = $true })
    & $w 'ad-10-entra-accounts' @{ SeamlessSsoPresent = $true; SeamlessSsoKeyAgeDays = 400; CloudKerberosTrustPresent = $false }
    $script:ProfilePath = Join-Path $script:Root 'profile.json'
    '{ "version": 1, "identityModel": "hybrid-connect", "licenses": ["E5", "P1", "P2"] }' | Set-Content -LiteralPath $script:ProfilePath
}

AfterAll { if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force } }

Describe 'Hybrid checks from the Windows collector files' {
    BeforeAll {
        $script:Run = Invoke-PostureChecks -Evidence $script:Ev -ProfilePath $script:ProfilePath -Domain hybrid -PassThru
        $script:By = @{}; foreach ($r in $script:Run.results) { $script:By[$r.id] = $r }
    }

    It 'evaluates 25 checks' { $script:Run.results.Count | Should -Be 25 }

    It 'gives <Id> status <Status>' -ForEach @(
        @{ Id = 'HY-001'; Status = 'pass' }
        @{ Id = 'HY-002'; Status = 'fail' }
        @{ Id = 'HY-003'; Status = 'pass' }
        @{ Id = 'HY-004'; Status = 'fail' }
        @{ Id = 'HY-010'; Status = 'fail' }
        @{ Id = 'HY-011'; Status = 'fail' }
        @{ Id = 'HY-012'; Status = 'fail' }
        @{ Id = 'HY-013'; Status = 'fail' }
        @{ Id = 'HY-014'; Status = 'fail' }
        @{ Id = 'HY-015'; Status = 'fail' }
        @{ Id = 'HY-016'; Status = 'fail' }
        @{ Id = 'HY-017'; Status = 'fail' }
        @{ Id = 'HY-018'; Status = 'fail' }
        @{ Id = 'HY-019'; Status = 'pass' }
        @{ Id = 'HY-020'; Status = 'fail' }
        @{ Id = 'HY-021'; Status = 'fail' }
        @{ Id = 'HY-022'; Status = 'fail' }
        @{ Id = 'HY-023'; Status = 'pass' }
        @{ Id = 'HY-024'; Status = 'fail' }
        @{ Id = 'HY-025'; Status = 'fail' }
        @{ Id = 'HY-026'; Status = 'fail' }
        @{ Id = 'HY-027'; Status = 'fail' }
        @{ Id = 'HY-028'; Status = 'fail' }
        @{ Id = 'HY-029'; Status = 'fail' }
        @{ Id = 'HY-030'; Status = 'fail' }
    ) { $script:By[$Id].status | Should -Be $Status -Because ($script:By[$Id].reason) }

    It 'names the affected objects' {
        $script:By['HY-010'].affectedCount | Should -Be 6
        $script:By['HY-013'].affectedCount | Should -Be 2 -Because 'alice has an old password, bob lacks protection; krbtgt is left out'
        $script:By['HY-017'].affected[0].name | Should -Be 'APP01'
        $script:By['HY-027'].affected[0].name | Should -Be 'partner.example' -Because 'the intra-forest trust is not counted'
        $script:By['HY-029'].affected[0].name | Should -Be 'VPN-Legacy'
    }

    It 'is not applicable on a cloud-only profile and not evaluated without the AD files' {
        $cloud = Join-Path $script:Root 'cloud.json'
        '{ "version": 1, "identityModel": "cloud-only" }' | Set-Content -LiteralPath $cloud
        $r = Invoke-PostureChecks -Evidence $script:Ev -ProfilePath $cloud -Domain hybrid -PassThru
        @($r.results | Where-Object { $_.status -ne 'notApplicable' }).Count | Should -Be 0
        $entraOnly = Join-Path $script:Root 'entra-only'
        New-Item -ItemType Directory -Path $entraOnly | Out-Null
        Copy-Item (Join-Path $script:Ev '01-onprem-sync-features.json') $entraOnly
        $r2 = Invoke-PostureChecks -Evidence $entraOnly -ProfilePath $script:ProfilePath -Domain hybrid -PassThru
        $by2 = @{}; foreach ($x in $r2.results) { $by2[$x.id] = $x }
        $by2['HY-001'].status | Should -Be 'pass'
        $by2['HY-014'].status | Should -Be 'notEvaluated'
        $by2['HY-014'].reason | Should -Match 'Get-ADBaseline.ps1'
    }
}

Describe 'The Windows collector script' {
    It 'parses, is Windows-only by location, reads only, and writes the ad-* files the facts expect' {
        $path = Join-Path $PSScriptRoot '..' 'collectors' 'windows' 'Get-ADBaseline.ps1'
        $tokens = $null; $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors) | Out-Null
        @($errors).Count | Should -Be 0
        $src = Get-Content -Raw $path
        $src | Should -Not -Match '(^|[;{|(&])\s*(Set|New|Remove|Add|Move|Rename|Enable|Disable|Reset|Unlock|Grant|Revoke)-AD' -Because 'the collector reads only'
        $src | Should -Not -Match 'Set-GPO|Set-GPRegistryValue|New-GPO|Remove-GPO'
        foreach ($n in 'ad-01-forest-domain', 'ad-01-trusts', 'ad-02-domain-controllers', 'ad-03-privileged-groups', 'ad-03-admin-accounts', 'ad-04-builtin-accounts', 'ad-05-delegation', 'ad-05-kerberoastable', 'ad-05-asrep-roastable', 'ad-06-computers-summary', 'ad-07-users-summary', 'ad-08-gpos', 'ad-09-adcs', 'ad-09-adcs-templates', 'ad-10-entra-accounts') { $src | Should -Match ([regex]::Escape("'$n'")) }
    }
}
