# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    $script:Root = Join-Path $PSScriptRoot '..'
    $script:Workflow = Get-Content -Raw (Join-Path $script:Root '.github' 'workflows' 'release.yml')
    $script:Setup = Get-Content -Raw (Join-Path $script:Root 'deploy' 'release' 'New-PostureSigningIdentity.ps1')
    $script:Build = Get-Content -Raw (Join-Path $script:Root 'build.ps1')
}

Describe 'The release workflow' {
    It 'packages after a maintainer approves the release environment, signs on Windows only when RELEASE_SIGNING is on, with OIDC and no secret credential' {
        $script:Workflow | Should -Match 'environment: release'
        $script:Workflow | Should -Match 'id-token: write'
        $script:Workflow | Should -Match "runs-on: \$\{\{ vars\.RELEASE_SIGNING == 'on' && 'windows-latest' \|\| 'ubuntu-latest' \}\}"
        $script:Workflow | Should -Match "if: vars\.RELEASE_SIGNING == 'on'\s+uses: azure/artifact-signing-action@v2"
        $script:Workflow | Should -Match 'exclude-azure-cli-credential: false'
        $script:Workflow | Should -Not -Match 'client-secret|AZURE_CLIENT_SECRET|password|pfx'
    }

    It 'signs every staged script, module and manifest with a timestamp, verifies before it packages, and packages unsigned explicitly otherwise' {
        $script:Workflow | Should -Match 'files-folder-filter: ps1,psm1,psd1'
        $script:Workflow | Should -Match 'files-folder-recurse: true'
        $script:Workflow | Should -Match 'timestamp-rfc3161: http://timestamp\.acs\.microsoft\.com'
        $script:Workflow | Should -Match '-Task Verify, Integrity, Package'
        $script:Workflow | Should -Match '-Task Integrity, Package -Unsigned'
        $script:Workflow | Should -Match '-Task Publish -Unsigned'
        $script:Workflow | Should -Match 'Copy-Item -LiteralPath \./tooling/build\.ps1' -Because 'a tag cut before a build.ps1 change is built with the current tooling (2026-10-26)'
    }

    It 'reads exactly the variables and secrets the setup script writes' {
        $used = @([regex]::Matches($script:Workflow, '(vars|secrets)\.([A-Z_]+)') | ForEach-Object { "$($_.Groups[1].Value).$($_.Groups[2].Value)" } | Sort-Object -Unique)
        $variables = @([regex]::Matches($script:Setup, '\b(AZURE_CLIENT_ID|AZURE_TENANT_ID|AZURE_SUBSCRIPTION_ID|RELEASE_SIGNING|GALLERY_PUBLISH|SIGNING_ENDPOINT|SIGNING_ACCOUNT|SIGNING_PROFILE)\b') | ForEach-Object { "vars.$($_.Groups[1].Value)" } | Sort-Object -Unique)
        $secrets = @([regex]::Matches($script:Setup, '\b(LICENCE_VAULT|LICENCE_KEY|GALLERY_API_KEY)\b') | ForEach-Object { "secrets.$($_.Groups[1].Value)" } | Sort-Object -Unique)
        $used | Should -Be @($variables + $secrets | Sort-Object -Unique)
    }
}

Describe 'New-PostureSigningIdentity.ps1' {
    It 'parses, supports -WhatIf and creates nothing that is a credential' {
        $tokens = $null; $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseInput($script:Setup, [ref]$tokens, [ref]$errors)
        @($errors).Count | Should -Be 0
        $script:Setup | Should -Match 'SupportsShouldProcess'
        $script:Setup | Should -Match 'federated-credential'
        $script:Setup | Should -Match 'certificateProfiles\?api-version' -Because 'a missing profile is a bare 403 at signing time (2026-10-26)'
        $script:Setup | Should -Match 'actions/oidc/customization/sub' -Because 'the subject prefix comes from GitHub, immutable owner@id/repo@id or the name form (2026-10-26)'
        $script:Setup | Should -Not -Match "ad app credential reset|ad sp credential|--password|client-secret"
        $script:Setup | Should -Not -Match '@\(, @\([^)]*\), @\(' -Because 'a leading comma before several pairs nests the first one a level too deep (2026-10-26)'
    }

    It 'assigns the two least-privilege roles and nothing broader, the signing one only once the account exists' {
        $roles = @([regex]::Matches($script:Setup, '@\(''([^'']+)'', \$(signingId|keyScope)\)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object)
        $roles | Should -Be @('Artifact Signing Certificate Profile Signer', 'Key Vault Crypto User')
        $script:Setup | Should -Match 'if \(\$signing\) \{ \$roles \+= '
        $script:Setup | Should -Not -Match "'Owner'|'Contributor'|Key Vault Administrator|Crypto Officer"
    }
}

Describe 'build.ps1 Verify and Package' {
    It 'offers Verify, makes Package accept Verify in place of Sign, and keeps the certificate gate otherwise' {
        $script:Build | Should -Match "ValidateSet\('Analyze', 'Test', 'Build', 'Sign', 'Verify', 'Integrity', 'Package', 'Clean', 'Catalog', 'Publish'\)"
        $script:Build | Should -Match '-notcontains ''Sign'' -and \$tasks -notcontains ''Verify'' -and -not \$Unsigned\) \{ \$tasks\.Add\(''Sign''\) \}'
        $script:Build | Should -Match "Package needs Sign \(local certificate\) or Verify"
    }

    It 'refuses Verify off Windows with a plain message' -Skip:$IsWindows {
        $out = & pwsh -NoProfile -Command "try { & '$(Join-Path $script:Root 'build.ps1')' -Task Build, Verify -SkipInstall 2>&1 | Out-Null } catch { `$_.Exception.Message }" 2>&1
        ($out -join "`n") | Should -Match 'Windows-only'
    }
}
