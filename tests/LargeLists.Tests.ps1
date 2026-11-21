# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# The lists with a row per user, device, group, mailbox or site are read a row at a time (Read-PostureEvidenceRow,
# Find-PostureEvidenceRow) by everything that runs after collection: the fact providers, the report model, the
# charts, the inventory, the profile discovery. Loaded whole, one of them was most of the report's memory on a
# large tenant (10 GB at 300,000 users). This test reads the source: a whole-file read of one of these names in
# that code fails the build. Scale.Tests.ps1 measures the result; this says where a regression is.
BeforeDiscovery {
    $private = Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'Private'
    $script:AfterCollection = @(Get-ChildItem -LiteralPath $private -Filter '*.ps1' | Where-Object { $_.Name -match '^(Get-Posture.+Fact|ConvertTo-PostureReport.*|Get-PostureChartData|Get-PostureInventory|Get-PostureProfileDiscovery|Get-PostureRoleHolder|Get-PostureAdminRow|Get-PostureRegistrationTally|Get-PostureAdminToolRestriction)\.ps1$' } | ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } })
}

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    $script:LargeLists = @(
        '05-auth-registration', '05-per-user-mfa', '06-users', '06-users-guests', '07-groups', '08-entra-devices', '08-bitlocker-keys-by-device',
        '09-intune-managed-devices', '09-autopilot-devices', '11-risky-users', 'def-01-devices', 'def-02-av-state',
        'exo-09-mailboxes', 'exo-10-cas-mailboxes', 'exo-12-remote-powershell-users', 'spo-sites'
    )
    # "& $load 'name'" and "Read-PostureEvidenceFile ... -Name 'name'" parse the whole JSON file.
    $names = ($script:LargeLists | ForEach-Object { [regex]::Escape($_) }) -join '|'
    $script:WholeRead = [regex]::new("(?m)(&\s*\`$load\s+|Read-PostureEvidenceFile\b[^\r\n|;]*-Name\s+)'($names)'")
}

Describe 'Large lists are never loaded whole after collection' {
    It 'covers the fact providers and the report (<Count> files)' -ForEach @(@{ Count = $script:AfterCollection.Count }) {
        $Count | Should -BeGreaterThan 20
    }

    It 'knows a whole-file read when it sees one' {
        $script:WholeRead.IsMatch('    $users = & $load ''06-users''') | Should -BeTrue
        $script:WholeRead.IsMatch('$r = Read-PostureEvidenceFile -Folder $ev -Name ''05-auth-registration''') | Should -BeTrue
        $script:WholeRead.IsMatch('$s = & $load ''06-users-summary''') | Should -BeFalse -Because 'a summary is one small object'
        $script:WholeRead.IsMatch('Read-PostureEvidenceRow -Folder $Evidence -Name ''06-users'' -OnRow { }') | Should -BeFalse
    }

    It '<Name> reads no large list whole' -ForEach $script:AfterCollection {
        $found = @($script:WholeRead.Matches((Get-Content -Raw -LiteralPath $Path)) | ForEach-Object { $_.Groups[2].Value } | Sort-Object -Unique)
        $found | Should -BeNullOrEmpty -Because 'these lists have a row per user, device or site: read them with Read-PostureEvidenceRow, or have the collector write a summary'
    }
}

Describe 'The evidence cache' {
    It 'keeps a small file and parses a large one again each time, so a large list never stays in memory' {
        InModuleScope TenantKeep.Posture {
            $dir = Join-Path $TestDrive 'cache'; New-Item -ItemType Directory -Path $dir | Out-Null
            Set-Content -LiteralPath (Join-Path $dir 'small.json') -Value '[{"Id":1}]'
            Set-Content -LiteralPath (Join-Path $dir 'large.json') -Value ('[' + ((1..5 | ForEach-Object { '{"Id":' + $_ + ',"Pad":"' + ('x' * 40) + '"}' }) -join ',') + ']')
            Clear-PostureEvidenceCache -Confirm:$false
            $limit = $script:PostureEvidenceCacheLimit
            try {
                $script:PostureEvidenceCacheLimit = 100
                $null = Read-PostureEvidenceFile -Folder $dir -Name 'small'
                $large = Read-PostureEvidenceFile -Folder $dir -Name 'large'
                @($large).Count | Should -Be 5 -Because 'a large file is still read'
                @($script:PostureEvidenceCache.get_Keys() | Where-Object { $_ -like '*small.json*' }).Count | Should -Be 1
                @($script:PostureEvidenceCache.get_Keys() | Where-Object { $_ -like '*large.json*' }).Count | Should -Be 0
            }
            finally { $script:PostureEvidenceCacheLimit = $limit; Clear-PostureEvidenceCache -Confirm:$false }
            $script:PostureEvidenceCacheLimit | Should -Be 8MB
        }
    }
}
