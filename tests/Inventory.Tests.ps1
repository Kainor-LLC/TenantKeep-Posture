# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    $script:Ev = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-inventory-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Ev | Out-Null
    $put = { param([string] $Name, [string] $Json) Set-Content -LiteralPath (Join-Path $script:Ev "$Name.json") -Value $Json }
    & $put 'exo-02-accepted-domains' '[ { "DomainName": "contoso.example", "DomainType": "Authoritative", "Default": true }, { "DomainName": "contoso.onmicrosoft.com", "DomainType": "Authoritative", "Default": false }, { "DomainName": "old.example", "DomainType": "InternalRelay", "Default": false } ]'
    & $put 'exo-02-dkim' '[ { "Domain": "contoso.example", "Enabled": true, "Status": "Valid" }, { "Domain": "old.example", "Enabled": false, "Status": "CnameMissing" } ]'
    & $put 'dns-01-mail-records' '[ { "Domain": "contoso.example", "MX": "0 contoso-example.mail.protection.outlook.com", "SPF": "v=spf1 include:spf.protection.outlook.com -all", "DMARC": "v=DMARC1; p=quarantine; rua=mailto:d@contoso.example" }, { "Domain": "old.example", "MX": "10 mx.old.example", "SPF": "", "DMARC": "" } ]'
    & $put 'exo-03-transport-rules' ''
    & $put '09-intune-summary-compliance' '[ { "Name": "Windows, compliant", "Count": 7 }, { "Name": "Windows, noncompliant", "Count": 2 }, { "Name": "Windows, inGracePeriod", "Count": 1 }, { "Name": "iOS, compliant", "Count": 3 } ]'
    & $put '04-role-assignments-active' '[ { "Role": "Global Administrator", "AssignmentType": "Assigned" }, { "Role": "Global Administrator", "AssignmentType": "Activated" }, { "Role": "Security Reader", "AssignmentType": "Assigned" } ]'
    & $put '04-role-assignments-pim-eligible' '[ { "Role": "Global Administrator" }, { "Role": "Exchange Administrator" } ]'
    & $put 'policies' '[ { "displayName": "B off", "state": "disabled", "modifiedDateTime": "2026-10-01T08:00:00Z" }, { "displayName": "A on", "state": "enabled" }, { "displayName": "C report", "state": "enabledForReportingButNotEnforced" } ]'
}

AfterAll { if (Test-Path $script:Ev) { Remove-Item -LiteralPath $script:Ev -Recurse -Force } }

Describe 'Get-PostureInventory' {
    BeforeAll {
        $script:Inv = InModuleScope TenantKeep.Posture -Parameters @{ Ev = $script:Ev } { param($Ev) Clear-PostureEvidenceCache; , @(Get-PostureInventory -Evidence $Ev) }
        $script:By = @{}; foreach ($s in $script:Inv) { $script:By[$s.key] = $s }
    }

    It 'joins accepted domains to DKIM and DNS, in words' {
        $m = @($script:By['mail-domains'].rows)
        $c = $m | Where-Object Domain -eq 'contoso.example'
        $c.Type | Should -Be 'Authoritative, default'
        $c.DKIM | Should -Be 'on'
        $c.SPF | Should -Be 'hard fail (-all)'
        $c.DMARC | Should -Be 'quarantine'
        $c.MX | Should -Be 'Exchange Online Protection'
        $o = $m | Where-Object Domain -eq 'old.example'
        $o.DKIM | Should -Be 'off (CnameMissing)'
        $o.SPF | Should -Be 'missing'
        $o.DMARC | Should -Be 'missing'
        ($m | Where-Object Domain -eq 'contoso.onmicrosoft.com').DKIM | Should -Be 'Microsoft signs'
        ($m | Where-Object Domain -eq 'contoso.onmicrosoft.com').SPF | Should -Be 'Microsoft managed'
    }

    It 'pivots devices by platform and counts roles by how they are held' {
        $w = @($script:By['device-compliance'].rows) | Where-Object Platform -eq 'Windows'
        $w.Compliant | Should -Be '7'; $w.Noncompliant | Should -Be '2'; $w.'Unknown or grace' | Should -Be '1'; $w.Total | Should -Be '10'
        $ga = @($script:By['roles'].rows)[0]
        $ga.Role | Should -Be 'Global Administrator' -Because 'the most held role comes first'
        $ga.Permanent | Should -Be '1'; $ga.'Activated now' | Should -Be '1'; $ga.Eligible | Should -Be '1'
        @($script:By['roles'].rows).Role | Should -Contain 'Exchange Administrator' -Because 'an eligible-only role is still a privileged role'
    }

    It 'lists CA policies on, report-only, then off, with the date' {
        $p = @($script:By['ca-policies'].rows)
        $p.Name | Should -Be @('A on', 'C report', 'B off')
        $p[2].Modified | Should -Be '2026-10-01'
        $script:By['ca-policies'].note | Should -Be '3 policies: 1 on, 1 report-only, 1 off.'
    }

    It 'says when a file was collected empty and when it was not collected at all' {
        $script:By['transport-rules'].total | Should -Be 0
        $script:By['transport-rules'].note | Should -Be 'No transport rules.'
        $script:By['compliance-policies'].note | Should -Match '^Not collected: 09-intune-compliance-policies\.json comes from the Intune collector'
        $script:By['endpoint-security'].rows | Should -BeNullOrEmpty
    }
}
