# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# A run can be killed at any moment: the laptop sleeps, the process runs out of memory, an Automation job is stopped
# at its time limit. Whatever was being written then must never be read as evidence. These tests stop the writers
# where a kill would and ask every reader, and then the checks, what they see.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Folder = Join-Path $TestDrive 'stream'
    New-Item -ItemType Directory -Path $script:Folder | Out-Null
}

AfterAll { InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = $null } }

Describe 'Evidence stream' {
    It 'keeps a list under .part until it is closed, and no reader opens a .part' {
        InModuleScope TenantKeep.Posture -Parameters @{ Folder = $script:Folder } {
            $s = Open-PostureEvidenceStream -Folder $Folder -Name 'x-list' -Csv -Confirm:$false
            # A column named Keys, as 08-bitlocker-keys-by-device has: the row's key list must still be its keys.
            foreach ($i in 1..50) { Add-PostureEvidenceRow -Stream $s -Row ([ordered]@{ Id = "d$i"; Keys = $i }) }
            $s.json.Flush(); $s.csv.Flush()

            Test-Path -LiteralPath (Join-Path $Folder 'x-list.json') | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $Folder 'x-list.csv') | Should -BeFalse
            (Get-Item -LiteralPath (Join-Path $Folder 'x-list.json.part')).Length | Should -BeGreaterThan 0
            (Get-Item -LiteralPath (Join-Path $Folder 'x-list.csv.part')).Length | Should -BeGreaterThan 0
            Read-PostureEvidenceFile -Folder $Folder -Name 'x-list' | Should -BeNullOrEmpty
            Read-PostureEvidenceRow -Folder $Folder -Name 'x-list' -OnRow { throw 'a reader opened an unfinished list' } | Should -BeFalse
            Find-PostureEvidenceRow -Folder $Folder -Name 'x-list' -Key 'Id' -Value 'd1' | Should -BeNullOrEmpty
            Get-PostureUnfinishedEvidence -Folder $Folder | Should -Be @('x-list')

            Close-PostureEvidenceStream -Stream $s -Quiet | Should -Be (Join-Path $Folder 'x-list.json')
            @(Get-ChildItem -LiteralPath $Folder -Filter '*.part').Count | Should -Be 0
            Get-PostureUnfinishedEvidence -Folder $Folder | Should -BeNullOrEmpty
            @(Get-Content -Raw -LiteralPath (Join-Path $Folder 'x-list.json') | ConvertFrom-Json).Count | Should -Be 50
            $rows = @(Import-Csv -LiteralPath (Join-Path $Folder 'x-list.csv'))
            $rows.Count | Should -Be 50
            @($rows[0].PSObject.Properties.Name) | Should -Be @('Id', 'Keys')
            $rows[49].Keys | Should -Be '50'
        }
    }

    It 'removes an abandoned list and leaves nothing behind' {
        InModuleScope TenantKeep.Posture -Parameters @{ Folder = $script:Folder } {
            $s = Open-PostureEvidenceStream -Folder $Folder -Name 'y-list' -Csv -Confirm:$false
            Add-PostureEvidenceRow -Stream $s -Row ([ordered]@{ Id = 'a' })
            Stop-PostureEvidenceStream -Stream $s -Confirm:$false
            @(Get-ChildItem -LiteralPath $Folder -Filter 'y-list*').Count | Should -Be 0
        }
    }

    It 'does not leave an earlier attempt''s list to be read as this one''s when the second attempt fails' {
        InModuleScope TenantKeep.Posture -Parameters @{ Folder = $script:Folder } {
            $first = Open-PostureEvidenceStream -Folder $Folder -Name 'z-list' -Csv -Confirm:$false
            Add-PostureEvidenceRow -Stream $first -Row ([ordered]@{ Id = 'from the first attempt' })
            $null = Close-PostureEvidenceStream -Stream $first -Quiet
            $second = Open-PostureEvidenceStream -Folder $Folder -Name 'z-list' -Csv -Confirm:$false
            Stop-PostureEvidenceStream -Stream $second -Confirm:$false
            Read-PostureEvidenceRow -Folder $Folder -Name 'z-list' -OnRow { } | Should -BeFalse
        }
    }
}

Describe 'Write-PostureEvidence' {
    It 'writes the file under its name with no .part left' {
        InModuleScope TenantKeep.Posture -Parameters @{ Folder = $script:Folder } {
            $null = Write-PostureEvidence -Folder $Folder -Name 'w-list' -InputObject @([ordered]@{ Id = 1 }, [ordered]@{ Id = 2 }) -AsArray -Csv -Quiet
            @(Get-Content -Raw -LiteralPath (Join-Path $Folder 'w-list.json') | ConvertFrom-Json).Count | Should -Be 2
            @(Import-Csv -LiteralPath (Join-Path $Folder 'w-list.csv')).Count | Should -Be 2
            @(Get-ChildItem -LiteralPath $Folder -Filter 'w-list*.part').Count | Should -Be 0
        }
    }

    It 'leaves neither file nor .part when the write fails part-way' {
        InModuleScope TenantKeep.Posture -Parameters @{ Folder = $script:Folder } {
            Mock Export-Csv { throw 'no space left on device' }
            { Write-PostureEvidence -Folder $Folder -Name 'v-list' -InputObject @([ordered]@{ Id = 1 }) -AsArray -Csv -Quiet } | Should -Throw '*no space left*'
            @(Get-ChildItem -LiteralPath $Folder -Filter 'v-list*').Count | Should -Be 0
        }
    }
}

Describe 'A run killed while the device lists were being written' {
    BeforeAll {
        $script:Made = & (Join-Path $PSScriptRoot '..' 'samples' 'demo' 'New-PostureDemoRun.ps1') -Path (Join-Path $TestDrive 'fernquill')
        $ev = $script:Made.Evidence
        # The two device lists as a killed process leaves them: written through the real stream writer, about 40
        # percent of the rows, the writers never closed.
        InModuleScope TenantKeep.Posture -Parameters @{ Ev = $ev } {
            foreach ($name in '08-entra-devices', '09-intune-managed-devices') {
                $file = Join-Path $Ev "$name.json"
                $rows = @(Get-Content -Raw -LiteralPath $file | ConvertFrom-Json -AsHashtable -Depth 10)
                $s = Open-PostureEvidenceStream -Folder $Ev -Name $name -Csv -Confirm:$false
                foreach ($row in @($rows | Select-Object -First ([int]($rows.Count * 0.4)))) { Add-PostureEvidenceRow -Stream $s -Row $row }
                $s.json.Dispose(); $s.csv.Dispose()
            }
        }
        $script:Run = Invoke-PostureChecks -Evidence $ev -ProfilePath (Join-Path $script:Made.Client 'profile.json') -Domain devices -OutputPath (Join-Path $TestDrive 'killed-out') -PassThru
        $script:ById = @{}; foreach ($r in $script:Run.results) { $script:ById[[string]$r['id']] = $r }
    }

    It 'computes no device counts from the part that was written' {
        $facts = $script:Run.domains['devices'].facts
        foreach ($fact in 'entraDevices', 'staleEntraDevices', 'managedDevices', 'intuneCompliancePct', 'windowsManagedDevices') { $facts.Contains($fact) | Should -BeFalse -Because "$fact would be a count over 40 percent of the list" }
    }

    It 'reads <Id> as not evaluated and names <File>' -ForEach @(
        @{ Id = 'DEV-001'; File = '09-intune-managed-devices' }
        @{ Id = 'DEV-004'; File = '09-intune-managed-devices' }
        @{ Id = 'DEV-006'; File = '09-intune-managed-devices' }
        @{ Id = 'DEV-007'; File = '09-intune-managed-devices' }
        @{ Id = 'DEV-014'; File = '09-intune-managed-devices' }
        @{ Id = 'DEV-002'; File = '08-entra-devices' }
        @{ Id = 'DEV-003'; File = '08-entra-devices' }
        @{ Id = 'DEV-005'; File = '08-entra-devices' }
    ) {
        $r = $script:ById[$Id]
        $r | Should -Not -BeNullOrEmpty
        $r['status'] | Should -BeIn @('notEvaluated', 'notApplicable')
        if ($r['status'] -eq 'notEvaluated') { $r['reason'] | Should -Match ([regex]::Escape($File)) }
    }

    It 'says which lists were unfinished' {
        InModuleScope TenantKeep.Posture -Parameters @{ Ev = $script:Made.Evidence } { Get-PostureUnfinishedEvidence -Folder $Ev | Should -Be @('08-entra-devices', '09-intune-managed-devices') }
    }
}

Describe 'profile.json and checks.json' {
    It 'are written through a temporary file that is gone afterwards' {
        $dir = Join-Path $TestDrive 'atomic'
        $profilePath = Join-Path $dir 'profile.json'
        $null = New-PostureProfile -Path $profilePath -NonInteractive -ClientName 'Contoso' -TenantId '11111111-2222-3333-4444-555555555555'
        (Get-Content -Raw -LiteralPath $profilePath | ConvertFrom-Json).tenantId | Should -Be '11111111-2222-3333-4444-555555555555'
        @(Get-ChildItem -LiteralPath $dir -File | Where-Object { $_.Name -ne 'profile.json' }).Count | Should -Be 0
        $ev = Join-Path $dir 'evidence'; $out = Join-Path $dir 'out'
        New-Item -ItemType Directory -Path $ev | Out-Null
        Set-Content -LiteralPath (Join-Path $ev 'collection.json') -Value '{ "tenantId": "11111111-2222-3333-4444-555555555555" }'
        $null = Invoke-PostureChecks -Evidence $ev -OutputPath $out
        (Get-Content -Raw -LiteralPath (Join-Path $out 'checks.json') | ConvertFrom-Json).results.Count | Should -BeGreaterThan 10
        @(Get-ChildItem -LiteralPath $out | Where-Object { $_.Name -ne 'checks.json' }).Count | Should -Be 0
    }
}
