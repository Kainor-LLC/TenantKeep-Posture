# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    $script:Root = Join-Path $PSScriptRoot '..'
    $script:Workflow = Get-Content -Raw (Join-Path $script:Root '.github' 'workflows' 'sign-release.yml')
    $script:Setup = Get-Content -Raw (Join-Path $script:Root 'deploy' 'release' 'New-PostureSigningIdentity.ps1')
    $script:Build = Get-Content -Raw (Join-Path $script:Root 'build.ps1')
}

Describe 'The sign-release workflow' {
    It 'signs on a Windows runner through Azure Artifact Signing, gated by the release environment, with OIDC and no secret credential' {
        $script:Workflow | Should -Match 'runs-on: windows-latest'
        $script:Workflow | Should -Match 'environment: release'
        $script:Workflow | Should -Match 'id-token: write'
        $script:Workflow | Should -Match 'uses: azure/artifact-signing-action@v2'
        $script:Workflow | Should -Match 'exclude-azure-cli-credential: false'
        $script:Workflow | Should -Not -Match 'client-secret|AZURE_CLIENT_SECRET|password|pfx'
    }

    It 'signs every staged script, module and manifest with a timestamp, then verifies before it packages' {
        $script:Workflow | Should -Match 'files-folder-filter: ps1,psm1,psd1'
        $script:Workflow | Should -Match 'files-folder-recurse: true'
        $script:Workflow | Should -Match 'timestamp-rfc3161: http://timestamp\.acs\.microsoft\.com'
        $script:Workflow | Should -Match '-Task Verify, Integrity, Package'
    }

    It 'reads exactly the variables and secrets the setup script writes' {
        $used = @([regex]::Matches($script:Workflow, '\$\{\{\s*(vars|secrets)\.([A-Z_]+)\s*\}\}') | ForEach-Object { "$($_.Groups[1].Value).$($_.Groups[2].Value)" } | Sort-Object -Unique)
        $written = @([regex]::Matches($script:Setup, "gh (variable|secret) set (\\$)?(?:name|pair\[0\])?([A-Z_]*)") | ForEach-Object { $_ })
        $variables = @([regex]::Matches($script:Setup, '\b(AZURE_CLIENT_ID|AZURE_TENANT_ID|AZURE_SUBSCRIPTION_ID|SIGNING_ENDPOINT|SIGNING_ACCOUNT|SIGNING_PROFILE)\b') | ForEach-Object { "vars.$($_.Groups[1].Value)" } | Sort-Object -Unique)
        $secrets = @([regex]::Matches($script:Setup, '\b(LICENCE_VAULT|LICENCE_KEY)\b') | ForEach-Object { "secrets.$($_.Groups[1].Value)" } | Sort-Object -Unique)
        $used | Should -Be @($variables + $secrets | Sort-Object -Unique)
        $written.Count | Should -BeGreaterThan 0
    }
}

Describe 'New-PostureSigningIdentity.ps1' {
    It 'parses, supports -WhatIf and creates nothing that is a credential' {
        $tokens = $null; $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseInput($script:Setup, [ref]$tokens, [ref]$errors)
        @($errors).Count | Should -Be 0
        $script:Setup | Should -Match 'SupportsShouldProcess'
        $script:Setup | Should -Match 'federated-credential'
        $script:Setup | Should -Not -Match "ad app credential reset|ad sp credential|--password|client-secret"
    }

    It 'assigns the two least-privilege roles and nothing broader' {
        $roles = @([regex]::Matches($script:Setup, '@\(''([^'']+)'', \$(signingId|keyScope)\)') | ForEach-Object { $_.Groups[1].Value })
        $roles | Should -Be @('Artifact Signing Certificate Profile Signer', 'Key Vault Crypto User')
        $script:Setup | Should -Not -Match "'Owner'|'Contributor'|Key Vault Administrator|Crypto Officer"
    }
}

Describe 'build.ps1 Verify and Package' {
    It 'offers Verify, makes Package accept Verify in place of Sign, and keeps the certificate gate otherwise' {
        $script:Build | Should -Match "ValidateSet\('Analyze', 'Test', 'Build', 'Sign', 'Verify', 'Integrity', 'Package', 'Clean', 'Catalog', 'Publish'\)"
        $script:Build | Should -Match '-notcontains ''Sign'' -and \$tasks -notcontains ''Verify''\) \{ \$tasks\.Add\(''Sign''\) \}'
        $script:Build | Should -Match "Package needs Sign \(local certificate\) or Verify"
    }

    It 'refuses Verify off Windows with a plain message' -Skip:$IsWindows {
        $out = & pwsh -NoProfile -Command "try { & '$(Join-Path $script:Root 'build.ps1')' -Task Build, Verify -SkipInstall 2>&1 | Out-Null } catch { `$_.Exception.Message }" 2>&1
        ($out -join "`n") | Should -Match 'Windows-only'
    }
}
