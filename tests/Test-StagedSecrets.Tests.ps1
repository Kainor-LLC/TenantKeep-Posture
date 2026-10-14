# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    . (Join-Path $PSScriptRoot '..' '.githooks' 'Test-StagedSecrets.ps1')
}

Describe 'Pre-commit secret scanner' {
    Context 'blocked file names' {
        It 'blocks <Path>' -ForEach @(
            @{ Path = 'signing.pfx' }
            @{ Path = 'certs/kainor.pem' }
            @{ Path = 'CLAUDE.local.md' }
            @{ Path = 'evidence/20261013-0900/01-organization.json' }
            @{ Path = 'samples/20261013-0900-ca/policies.json' }
            @{ Path = '.env' }
        ) {
            @(Test-PostureStagedContent -Path $Path -Content 'nothing').Count | Should -BeGreaterOrEqual 1
        }
    }

    Context 'content patterns' {
        # Every value below is a synthetic fixture built to the shape of the real thing. posture:allow-secret
        It 'flags <Rule>' -ForEach @(
            @{ Rule = 'Entra client secret'; Text = ('secret = "' + 'Abc8Q~' + ('x' * 34) + '"') }                     # posture:allow-secret
            @{ Rule = 'JWT / bearer token'; Text = ('Authorization: Bearer ' + 'eyJ' + ('a' * 20) + '.eyJ' + ('b' * 20) + '.' + ('c' * 20)) }   # posture:allow-secret
            @{ Rule = 'private key block'; Text = ('-----BEGIN ' + 'RSA PRIVATE KEY-----') }                           # posture:allow-secret
            @{ Rule = 'Azure storage account key'; Text = ('AccountKey=' + ('A' * 86) + '==') }                                # posture:allow-secret
            @{ Rule = 'connection string password'; Text = 'Server=db;User Id=sa;Password=Hunter2Hunter2;' }                    # posture:allow-secret
            @{ Rule = 'GitHub token'; Text = ('ghp_' + ('Z' * 36)) }                                              # posture:allow-secret
            @{ Rule = 'Teams or Slack webhook'; Text = 'https://contoso.webhook.office.com/webhookb2/abc' }                 # posture:allow-secret
            @{ Rule = 'generic secret assignment'; Text = ('ClientSecret: "' + ('q' * 24) + '"') }                             # posture:allow-secret
        ) {
            $hits = @(Test-PostureStagedContent -Path 'src/thing.ps1' -Content $Text)
            $hits.Rule | Should -Contain $Rule
        }

        It 'passes ordinary module code' {
            $clean = @'
function Export-PostureCaSnapshot {
    [CmdletBinding()]
    param([string] $OutRoot = "$HOME/audit/evidence")
    $policies = Invoke-PostureGraphRequest -Uri 'identity/conditionalAccess/policies' -ApiVersion 'v1.0'
    $password = Read-Host -AsSecureString
}
'@
            @(Test-PostureStagedContent -Path 'Tenantkeep.Posture/Public/Export-PostureCaSnapshot.ps1' -Content $clean) | Should -BeNullOrEmpty
        }

        It 'skips a line carrying the allow marker' {
            $text = ('token = "' + 'ghp_' + ('Z' * 36) + '"  # posture:allow-secret')
            @(Test-PostureStagedContent -Path 'tests/fixture.ps1' -Content $text) | Should -BeNullOrEmpty
        }

        It 'reports the line number' {
            $text = "line one`nline two`nAccountKey=$('B' * 86)=="   # posture:allow-secret
            (Test-PostureStagedContent -Path 'x.txt' -Content $text).Line | Should -Be 3
        }

        It 'applies only path rules to binary content' {
            $binary = "PK`0`0" + ('ghp_' + ('Z' * 36))   # posture:allow-secret
            @(Test-PostureStagedContent -Path 'a.zip' -Content $binary) | Should -BeNullOrEmpty
        }
    }
}
