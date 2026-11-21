# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-collector-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $script:Tid = '33333333-3333-3333-3333-333333333333'
    # A run in the folders layout, with the two files the command is filled in from.
    $script:Run = Join-Path $script:Root "it's a run"
    foreach ($d in 'evidence', 'errors', 'logs') { New-Item -ItemType Directory -Path (Join-Path $script:Run $d) -Force | Out-Null }
    @{ tenantId = $script:Tid; client = $script:Root; planned = @('Entra') } | ConvertTo-Json | Set-Content (Join-Path $script:Run 'logs' 'run.json')
    ConvertTo-Json -InputObject @(@{ id = $script:Tid; displayName = 'Contoso'; verifiedDomains = @(@{ name = 'contoso.example'; isInitial = $false }, @{ name = 'contoso.onmicrosoft.com'; isInitial = $true }) }) -Depth 5 | Set-Content (Join-Path $script:Run 'evidence' '01-organization.json')
    $script:Repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}

AfterAll { Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue }

Describe 'Export-PostureCollector' {
    It 'writes the Active Directory collector into the run, unchanged, with the command and the way back' {
        $r = Export-PostureCollector -Kind ActiveDirectory -Run $script:Run -PassThru
        $r.Folder | Should -Be (Join-Path $script:Run 'collectors' 'active-directory')
        (Get-FileHash $r.Script).Hash | Should -Be (Get-FileHash (Join-Path $script:Repo 'collectors' 'windows' 'Get-ADBaseline.ps1')).Hash -Because 'the script is the one the repository tests'
        $text = Get-Content -Raw $r.Instructions
        $text | Should -Match '\.\\Get-ADBaseline\.ps1'
        $text | Should -Match ([regex]::Escape("Import-PostureEvidence -Path <the folder the script wrote, or a zip of it> -Run 'it''s a run'".Replace("'it''s a run'", "'" + $script:Run.Replace("'", "''") + "'")))
        $text | Should -Match 'It only reads'
        $text | Should -Match "`r`n" -Because 'the file is opened on Windows'
        $text | Should -Not -Match ([string][char]0x2014) -Because 'plain English, no em dashes'
        $text | Should -Not -Match 'ExecutionPolicy Bypass' -Because 'the instructions never tell anyone to switch a protection off'
    }

    It 'fills the SharePoint command in with the run''s tenant name and id' {
        $r = Export-PostureCollector -Kind SharePoint -Run $script:Run -PassThru
        $r.Folder | Should -Be (Join-Path $script:Run 'collectors' 'sharepoint')
        $r.Command | Should -Be ".\Get-SpoBaseline.ps1 -Tenant contoso -TenantId $($script:Tid)"
        Get-Content -Raw $r.Instructions | Should -Match ([regex]::Escape($r.Command))
        (Get-FileHash $r.Script).Hash | Should -Be (Get-FileHash (Join-Path $script:Repo 'collectors' 'windows' 'Get-SpoBaseline.ps1')).Hash
        # The command is one the script accepts.
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($r.Script, [ref]$null, [ref]$null)
        $names = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
        foreach ($p in 'Tenant', 'TenantId') { $names | Should -Contain $p }
    }

    It 'writes where it is told, and says what is not known when there is no run' {
        $out = Join-Path $script:Root 'usb' 'spo'
        $folder = Export-PostureCollector -Kind SharePoint -OutputPath $out
        $folder | Should -Be $out
        $text = Get-Content -Raw (Join-Path $out 'RUN-ME.txt')
        $text | Should -Match '-Tenant <tenant name, the part before \.onmicrosoft\.com> -TenantId <tenant id>'
        $text | Should -Match '-Run <the run folder>'
        Join-Path $out 'Get-SpoBaseline.ps1' | Should -Exist
    }

    It 'leaves a placeholder for a tenant name the run does not record, and takes the id from the manifest' {
        $bare = Join-Path $script:Root 'bare'
        foreach ($d in 'evidence', 'errors', 'logs') { New-Item -ItemType Directory -Path (Join-Path $bare $d) -Force | Out-Null }
        @{ tenantId = $script:Tid; collectors = @() } | ConvertTo-Json | Set-Content (Join-Path $bare 'evidence' 'collection.json')
        (Export-PostureCollector -Kind SharePoint -Run $bare -PassThru).Command | Should -Be ".\Get-SpoBaseline.ps1 -Tenant <tenant name, the part before .onmicrosoft.com> -TenantId $($script:Tid)"
    }

    It 'refuses without a run or a place to write, and for a run that is not there' {
        { Export-PostureCollector -Kind ActiveDirectory } | Should -Throw '*-Run*-OutputPath*'
        { Export-PostureCollector -Kind ActiveDirectory -Run (Join-Path $script:Root 'no-such-run') } | Should -Throw '*Run folder not found*'
    }

    It 'writes nothing under -WhatIf' {
        $out = Join-Path $script:Root 'whatif'
        $null = Export-PostureCollector -Kind ActiveDirectory -OutputPath $out -WhatIf
        $out | Should -Not -Exist
    }

    It 'is packaged with the module: the build stages the Windows collectors' {
        $build = Get-Content -Raw (Join-Path $script:Repo 'build.ps1')
        $build | Should -Match "Join-Path \`$stage 'collectors' 'windows'"
        InModuleScope TenantKeep.Posture { Join-Path (Get-PostureDataFolder -Name collectors) 'windows' 'Get-ADBaseline.ps1' | Should -Exist }
    }
}
