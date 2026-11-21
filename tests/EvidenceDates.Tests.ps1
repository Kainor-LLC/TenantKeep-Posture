# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# A date in CSV evidence says which zone it is in. Written as plain text it had none ("11/15/2026 02:03:22"), and
# the reader took it for the machine's own: the same folder read six hours off in Chicago and eleven in Sydney.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-dates-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
}

AfterAll { Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue }

Describe 'Dates in CSV evidence' {
    It 'writes a date as ISO 8601 in UTC, whatever kind of date it was given' {
        InModuleScope TenantKeep.Posture -Parameters @{ Folder = $script:Root } {
            $utc = [datetime]::new(2026, 11, 15, 2, 3, 22, [System.DateTimeKind]::Utc)
            $s = Open-PostureEvidenceStream -Folder $Folder -Name 'd-stream' -Csv -Confirm:$false
            Add-PostureEvidenceRow -Stream $s -Row ([ordered]@{ Id = 'utc'; When = $utc })
            Add-PostureEvidenceRow -Stream $s -Row ([ordered]@{ Id = 'local'; When = $utc.ToLocalTime() })
            Add-PostureEvidenceRow -Stream $s -Row ([ordered]@{ Id = 'unspecified'; When = [datetime]::SpecifyKind($utc, [System.DateTimeKind]::Unspecified) })
            Add-PostureEvidenceRow -Stream $s -Row ([ordered]@{ Id = 'offset'; When = [System.DateTimeOffset]::new(2026, 11, 14, 21, 3, 22, [timespan]::FromHours(-5)) })
            Add-PostureEvidenceRow -Stream $s -Row ([ordered]@{ Id = 'fraction'; When = $utc.AddMilliseconds(250) })
            Add-PostureEvidenceRow -Stream $s -Row ([ordered]@{ Id = 'text'; When = '2026-11-15T02:03:22Z' })
            Add-PostureEvidenceRow -Stream $s -Row ([ordered]@{ Id = 'none'; When = $null })
            $null = Close-PostureEvidenceStream -Stream $s -Quiet
            $rows = @(Import-Csv -LiteralPath (Join-Path $Folder 'd-stream.csv'))
            foreach ($id in 'utc', 'local', 'unspecified', 'offset', 'text') { @($rows | Where-Object Id -eq $id)[0].When | Should -Be '2026-11-15T02:03:22Z' -Because "the $id date is the same instant" }
            @($rows | Where-Object Id -eq 'fraction')[0].When | Should -Be '2026-11-15T02:03:22.25Z'
            @($rows | Where-Object Id -eq 'none')[0].When | Should -Be ''
        }
    }

    It 'does the same for a list written in one piece' {
        InModuleScope TenantKeep.Posture -Parameters @{ Folder = $script:Root } {
            $utc = [datetime]::new(2026, 11, 15, 2, 3, 22, [System.DateTimeKind]::Utc)
            $null = Write-PostureEvidence -Folder $Folder -Name 'd-whole' -InputObject @([ordered]@{ Id = 'a'; Keys = 3; When = $utc }, [ordered]@{ Id = 'b'; Keys = 0; When = $utc.ToLocalTime() }) -AsArray -Csv -Quiet
            $rows = @(Import-Csv -LiteralPath (Join-Path $Folder 'd-whole.csv'))
            @($rows[0].PSObject.Properties.Name) | Should -Be @('Id', 'Keys', 'When') -Because 'the columns keep their order and their names'
            $rows.When | Should -Be @('2026-11-15T02:03:22Z', '2026-11-15T02:03:22Z')
            $rows[0].Keys | Should -Be '3'
        }
    }

    It 'reads text with no zone as UTC, so the CSV files already on disk read right' {
        InModuleScope TenantKeep.Posture {
            (ConvertTo-PostureUtcDateTime '11/15/2026 02:03:22').ToString('o') | Should -Be '2026-11-15T02:03:22.0000000Z'
            (ConvertTo-PostureUtcDateTime '2026-11-15 02:03:22').Kind | Should -Be 'Utc'
            (ConvertTo-PostureUtcDateTime '2026-11-15T02:03:22').ToString('HH:mm') | Should -Be '02:03'
            (ConvertTo-PostureUtcDateTime '2026-11-15T02:03:22+02:00').ToString('HH:mm') | Should -Be '00:03' -Because 'a zone that is there is honoured'
            (ConvertTo-PostureUtcDateTime '2026-11-15T02:03:22Z').ToString('HH:mm') | Should -Be '02:03'
        }
    }

    It 'reads back the instant it wrote under <_>' -Skip:$IsWindows -ForEach @('America/Chicago', 'Australia/Sydney', 'UTC') {
        # The time zone is the process's, so a fresh PowerShell with TZ set writes a row, reads it back through the
        # row reader and says what it got. (Windows takes its zone from the system, not from TZ.)
        $folder = Join-Path $script:Root ("tz-" + ($_ -replace '/', '-'))
        New-Item -ItemType Directory -Path $folder | Out-Null
        $script = @'
param([string] $Module, [string] $Folder)
Import-Module $Module -Force
& (Get-Module TenantKeep.Posture) {
    param($Folder)
    $s = Open-PostureEvidenceStream -Folder $Folder -Name 'tz' -Csv -Confirm:$false
    Add-PostureEvidenceRow -Stream $s -Row ([ordered]@{ Id = 'x'; When = [datetime]::new(2026, 11, 15, 2, 3, 22, [System.DateTimeKind]::Utc); Old = '11/15/2026 02:03:22' })
    $null = Close-PostureEvidenceStream -Stream $s -Quiet
    $said = [System.Collections.Generic.List[string]]::new()
    $null = Read-PostureEvidenceRow -Folder $Folder -Name 'tz' -OnRow { param($row) $said.Add("$([System.TimeZoneInfo]::Local.Id)|$((ConvertTo-PostureUtcDateTime $row.When).ToString('o'))|$((ConvertTo-PostureUtcDateTime $row.Old).ToString('o'))") }
    $said
} $Folder
'@
        $file = Join-Path $folder 'roundtrip.ps1'
        Set-Content -LiteralPath $file -Value $script
        $before = $env:TZ
        try { $env:TZ = $_; $said = @(& ([Environment]::ProcessPath) -NoProfile -File $file -Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Folder $folder) }
        finally { $env:TZ = $before }
        $line = @($said | Where-Object { $_ -match '\|' })[-1]
        $line | Should -Be "$_|2026-11-15T02:03:22.0000000Z|2026-11-15T02:03:22.0000000Z" -Because 'the child ran in that zone and read both the new text and the old as the instant written'
    }
}
