# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    $script:Script = Join-Path $PSScriptRoot '..' 'deploy' 'verify' 'Test-PostureReadOnly.ps1'
    $script:Tid = '33333333-3333-3333-3333-333333333333'
    # Stubs for the two sessions the script reads through. Shapes mirror what the cmdlets return.
    function global:Get-MgContext { [pscustomobject]@{ TenantId = '33333333-3333-3333-3333-333333333333' } }
    function global:Get-ConnectionInformation { [pscustomobject]@{ State = 'Connected'; TenantID = '33333333-3333-3333-3333-333333333333' } }
    function global:Search-UnifiedAuditLog { param($StartDate, $EndDate, $UserIds, $SessionId, $SessionCommand, $ResultSize) @($env:TKP_RO_AUDIT | ConvertFrom-Json) }
    function global:Invoke-MgGraphRequest {
        param([string] $Method, [string] $Uri, [string] $OutputType)
        if ($Method -ne 'GET') { throw "The check sent $Method" }
        if ($Uri -match 'directoryAudits') { return @{ value = @($env:TKP_RO_DIRECTORY | ConvertFrom-Json -AsHashtable | Where-Object { $_ }) } }
        return @{ value = @(@{ appDisplayName = 'TenantKeep Posture'; appId = 'e5b148e7-9689-40b2-9b09-9d0bef133049'; createdDateTime = '2026-11-20T14:05:00Z' }) }
    }
}

AfterAll {
    Remove-Item Function:\global:Get-MgContext, Function:\global:Get-ConnectionInformation, Function:\global:Search-UnifiedAuditLog, Function:\global:Invoke-MgGraphRequest -ErrorAction SilentlyContinue
    Remove-Item Env:TKP_RO_AUDIT, Env:TKP_RO_DIRECTORY -ErrorAction SilentlyContinue
}

Describe 'Test-PostureReadOnly.ps1' {
    BeforeAll {
        $script:Run = Join-Path $TestDrive 'run'
        foreach ($p in 'evidence', 'errors', 'logs') { New-Item -ItemType Directory -Path (Join-Path $script:Run $p) -Force | Out-Null }
        @{ tenantId = $script:Tid; startedUtc = '2026-11-20T14:00:00Z'; runAs = @{ account = 'posture-run@contoso.example' } } | ConvertTo-Json | Set-Content (Join-Path $script:Run 'logs' 'run.json')
    }

    It 'reads only, and does not load the module it is checking' {
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Script, [ref]$tokens, [ref]$errors)
        @($errors).Count | Should -Be 0
        $src = Get-Content -Raw $script:Script
        $src | Should -Not -Match 'Import-Module\s+.*TenantKeep'
        $src | Should -Not -Match "-Method\s+['`"]?(POST|PATCH|PUT|DELETE)"
        $commands = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ -match '-' } | Sort-Object -Unique)
        foreach ($c in $commands) { $c | Should -Match '^(Get-|Search-UnifiedAuditLog$|Invoke-MgGraphRequest$|Write-|Select-|Sort-|Group-|Where-|ForEach-|Export-Csv$|ConvertTo-Json$|ConvertFrom-Json$|Join-Path$|Split-Path$|Resolve-Path$|New-Item$|Set-StrictMode$|Out-Null$)' -Because "$c must not change anything" }
    }

    It 'finds no changes when the account only read, and names the apps it signed in to' {
        $env:TKP_RO_AUDIT = ConvertTo-Json -InputObject @(@{ RecordType = 'SharePointFileOperation'; Operations = 'FileAccessed'; CreationDate = '2026-11-20T14:10:00Z'; UserIds = 'posture-run@contoso.example'; AuditData = '{}' }) -Compress
        $env:TKP_RO_DIRECTORY = '[]'
        $r = & $script:Script -TenantId $script:Tid -RunFolder $script:Run -OutputPath (Join-Path $TestDrive 'out1') 6>$null 3>$null
        $r.verdict | Should -Be 'no changes'
        $r.account | Should -Be 'posture-run@contoso.example' -Because 'the account comes from the run folder'
        $r.unifiedAuditRecords | Should -Be 1
        @($r.signInsByApp)[0].app | Should -Be 'TenantKeep Posture'
        Join-Path $TestDrive 'out1' 'summary.json' | Should -Exist
    }

    It 'reports an Exchange admin operation, a SharePoint sharing change and a directory change' {
        $env:TKP_RO_AUDIT = ConvertTo-Json -Compress -InputObject @(
            @{ RecordType = 'ExchangeAdmin'; Operations = 'Set-Mailbox'; CreationDate = '2026-11-20T14:10:00Z'; UserIds = 'posture-run@contoso.example'; AuditData = '{}' }
            @{ RecordType = 'SharePointSharingOperation'; Operations = 'SharingSet'; CreationDate = '2026-11-20T14:11:00Z'; UserIds = 'posture-run@contoso.example'; AuditData = '{}' }
            @{ RecordType = 'SharePoint'; Operations = 'PageViewed'; CreationDate = '2026-11-20T14:12:00Z'; UserIds = 'posture-run@contoso.example'; AuditData = '{}' }
        )
        $env:TKP_RO_DIRECTORY = ConvertTo-Json -Compress -InputObject @(@{ activityDateTime = '2026-11-20T14:13:00Z'; activityDisplayName = 'Update user'; category = 'UserManagement'; result = 'success' })
        $r = & $script:Script -TenantId $script:Tid -RunFolder $script:Run -OutputPath (Join-Path $TestDrive 'out2') 6>$null 3>$null
        $r.verdict | Should -Be 'changes found'
        $r.unifiedAuditChanges | Should -Be 2
        $r.entraDirectoryChanges | Should -Be 1
        @(Import-Csv (Join-Path $TestDrive 'out2' 'unified-audit-changes.csv')).Operations | Should -Be @('Set-Mailbox', 'SharingSet')
    }

    It 'refuses a run folder from another tenant' {
        { & $script:Script -TenantId '44444444-4444-4444-4444-444444444444' -RunFolder $script:Run -OutputPath (Join-Path $TestDrive 'out3') 6>$null 3>$null } | Should -Throw '*is tenant 3333*'
    }
}
