# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    . (Join-Path $PSScriptRoot '..' '.githooks' 'Test-StagedSecrets.ps1')
    # The tests never read this machine's notes or client folders: no deny list unless a test builds one.
    $script:PostureDenyRegex = $null
    $script:PostureDenyLoaded = $true
}

Describe 'Pre-commit secret scanner' {
    Context 'blocked file names' {
        It 'blocks <Path>' -ForEach @(
            @{ Path = 'signing.pfx' }
            @{ Path = 'certs/kainor.pem' }
            @{ Path = 'CLAUDE.local.md' }
            @{ Path = '.githooks/denylist.local.txt' }
            @{ Path = 'evidence/20261013-0900/01-organization.json' }
            @{ Path = 'samples/20261013-0900-ca/policies.json' }
            @{ Path = '.env' }
            @{ Path = 'clients/contoso/tenantkeep.lic' }
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
    param([string] $OutRoot = "$HOME/tenantkeep/evidence")
    $policies = Invoke-PostureGraphRequest -Uri 'identity/conditionalAccess/policies' -ApiVersion 'v1.0'
    $password = Read-Host -AsSecureString
}
'@
            @(Test-PostureStagedContent -Path 'TenantKeep.Posture/Public/Export-PostureCaSnapshot.ps1' -Content $clean) | Should -BeNullOrEmpty
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

Describe 'Company information: reserved names only' {
    # The made-up organisation below stands for a real customer. Its lines carry the marker so this file can be committed.
    It 'passes <Text>' -ForEach @(
        @{ Text = 'UserPrincipalName = "megan@contoso.example"' }
        @{ Text = 'contact: security@kainor.com, admin@contoso.com, a@b.example' }
        @{ Text = 'Co-Authored-By: Someone <noreply@anthropic.com>' }
        @{ Text = 'uses: actions/checkout@v4.1.0' }
        @{ Text = 'Organization contoso.onmicrosoft.com, site https://contoso-admin.sharepoint.com and https://fernquilldemo-my.sharepoint.com' }
        @{ Text = '$metadata = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$Tenant.onmicrosoft.com/v2.0/.well-known/openid-configuration"' }
        @{ Text = 'Connect-PnPOnline -Url https://$short-admin.sharepoint.com and "https://$($session[''tenantName''])-admin.sharepoint.com"' }
        @{ Text = 'audience https://{tenant}-admin.sharepoint.com, or https://<tenant>-admin.sharepoint.com' }
    ) {
        @(Test-PostureStagedContent -Path 'tests/Thing.Tests.ps1' -Content $Text) | Should -BeNullOrEmpty
    }

    It 'refuses a mail domain that is not reserved' {
        $hits = @(Test-PostureStagedContent -Path 'samples/users.json' -Content ('"mail": "dana@woodgrove' + '-bank.com"'))   # posture:allow-secret
        $hits.Rule | Should -Be 'mail domain not on the allow list'
        $hits.Text | Should -Be ('woodgrove' + '-bank.com')
    }

    It 'refuses a tenant name that is not reserved, on <Text>' -ForEach @(
        @{ Text = ('woodgrove' + 'bank.onmicrosoft.com') }   # posture:allow-secret
        @{ Text = ('https://woodgrove' + 'bank-admin.sharepoint.com/sites/x') }   # posture:allow-secret
        @{ Text = ('https://woodgrove' + 'bank-my.sharepoint.com/personal/dana') }   # posture:allow-secret
        @{ Text = ('woodgrove' + 'bank.mail.onmicrosoft.com') }   # posture:allow-secret
    ) {
        (Test-PostureStagedContent -Path 'docs/guide.md' -Content $Text).Rule | Should -Be 'tenant name not on the allow list'
    }

    It 'lets a marked fixture line through the allow list' {
        @(Test-PostureStagedContent -Path 'tests/x.ps1' -Content ('dana@woodgrove' + '-bank.com  # posture:allow-secret')) | Should -BeNullOrEmpty
    }
}

Describe 'Company information: the local deny list' {
    BeforeAll {
        # Local notes and a clients folder as they look on a developer's machine, with made-up names throughout.
        $script:Root = Join-Path $TestDrive 'deny'
        $clients = Join-Path $script:Root 'clients'
        New-Item -ItemType Directory -Path (Join-Path $clients 'kainor'), (Join-Path $clients 'northwind-traders') -Force | Out-Null
        $script:Tenant = 'aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb'
        $notes = @(
            '# Local settings'
            ('- Publisher: tenant cccccccc-1111-4222-8333-dddddddddddd, kainor.onmicrosoft.com, sign in as owner' + '@kainor.com.')
            ("- First customer: tenant $script:Tenant, woodgrove" + 'bank1.onmicrosoft.com, sign in as dana@woodgrove' + '-bank.com.')   # posture:allow-secret
            '- Signing key in Key Vault kv-made-up-0001, key name kainor-2026-10.'
        ) -join "`n"
        Set-Content -LiteralPath (Join-Path $script:Root 'CLAUDE.local.md') -Value $notes
        Set-Content -LiteralPath (Join-Path $clients 'kainor' 'profile.json') -Value '{ "tenantId": "cccccccc-1111-4222-8333-dddddddddddd", "clientName": "Kainor LLC" }'
        Set-Content -LiteralPath (Join-Path $clients 'northwind-traders' 'profile.json') -Value ('{ "tenantId": "eeeeeeee-1111-4222-8333-ffffffffffff", "clientName": "Northwind Traders Ltd", "breakGlass": ["bg1@northwind' + '-traders.com"] }')   # posture:allow-secret
        Set-Content -LiteralPath (Join-Path $script:Root 'denylist.local.txt') -Value @('# extra', 'Project Bluebird', 're:tailspin\s*toys')
        $script:Deny = Get-PostureDenyRegex -NotesPath (Join-Path $script:Root 'CLAUDE.local.md') -ClientsRoot $clients -ExtraPath (Join-Path $script:Root 'denylist.local.txt')
    }

    It 'is empty when the machine has no notes, clients or extra file' {
        Get-PostureDenyRegex -NotesPath (Join-Path $TestDrive 'none.md') -ClientsRoot (Join-Path $TestDrive 'none') -ExtraPath (Join-Path $TestDrive 'none.txt') | Should -BeNullOrEmpty
    }

    It 'denies <Why>' -ForEach @(
        @{ Why = 'a tenant id from the notes'; Text = 'TenantId = "AAAAAAAA-1111-4222-8333-BBBBBBBBBBBB"' }
        @{ Why = 'the publisher tenant id, which is local too'; Text = 'cccccccc-1111-4222-8333-dddddddddddd' }
        @{ Why = 'a customer tenant name'; Text = ('woodgrove' + 'bank1.onmicrosoft.com') }   # posture:allow-secret
        @{ Why = 'a customer mail domain'; Text = ('see woodgrove' + '-bank.com for the address') }
        @{ Why = 'the customer name, spaced'; Text = 'Seen live on Woodgrove Bank, 2026-11-01' }
        @{ Why = 'the customer name, joined'; Text = 'WoodgroveBank-Prod' }
        @{ Why = 'the name read from the tenant name'; Text = 'woodgrovebank evidence' }
        @{ Why = 'an account at the publisher'; Text = ('sign in as owner' + '@kainor.com') }
        @{ Why = 'a Key Vault name'; Text = '-VaultName kv-made-up-0001' }
        @{ Why = 'a tenant id from a client profile'; Text = 'eeeeeeee-1111-4222-8333-ffffffffffff' }
        @{ Why = 'a client folder name'; Text = 'clients/northwind_traders/profile.json' }
        @{ Why = 'a client name from its profile'; Text = 'Prepared for Northwind  Traders Ltd' }
        @{ Why = 'a break-glass account from a profile'; Text = ('bg1@northwind' + '-traders.com') }
        @{ Why = 'a line of the extra file'; Text = 'project bluebird kickoff' }
        @{ Why = 'a regex of the extra file'; Text = 'Tailspin Toys' }
    ) {
        $script:Deny.IsMatch($Text) | Should -BeTrue
    }

    It 'leaves public names alone: <Text>' -ForEach @(
        @{ Text = '# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.' }
        @{ Text = 'security@kainor.com, kainor.onmicrosoft.com, https://kainor.com, TenantKeep, clients/kainor/profile.json' }
        @{ Text = 'megan@contoso.example in contoso.onmicrosoft.com, key kainor-2026-10' }
        @{ Text = '11111111-2222-3333-4444-555555555555' }
    ) {
        $script:Deny.IsMatch($Text) | Should -BeFalse
    }

    It 'reports a hit by file and line and never prints the text' {
        $hits = @(Test-PostureStagedContent -Path 'docs/collection.md' -Content "first line`nSeen live on Woodgrove Bank" -Deny $script:Deny)
        $hits.Count | Should -Be 1
        $hits[0].Rule | Should -Be 'company information (local deny list)'
        $hits[0].Line | Should -Be 2
        ($hits | Out-String) | Should -Not -Match '(?i)woodgrove'
    }

    It 'has no marker that lets a deny list hit through' {
        @(Test-PostureStagedContent -Path 'tests/x.ps1' -Content 'Woodgrove Bank  # posture:allow-secret' -Deny $script:Deny).Count | Should -Be 1
    }

    It 'refuses a file named after a customer without printing the name' {
        $hits = @(Test-PostureStagedContent -Path 'samples/woodgrove-bank/policies.json' -Content '{}' -Deny $script:Deny)
        $hits.Count | Should -Be 1
        ($hits | Out-String) | Should -Not -Match '(?i)woodgrove'
    }

    It 'scans a commit message and leaves out the comment lines' {
        @(Test-PostureCommitMessage -Message "Fix the sample`n`nSeen live on Woodgrove Bank." -Deny $script:Deny).Count | Should -Be 1
        @(Test-PostureCommitMessage -Message "Fix the sample`n# Woodgrove Bank is only in git's comment`n" -Deny $script:Deny) | Should -BeNullOrEmpty
        @(Test-PostureCommitMessage -Message "Fix the sample`n`nCo-Authored-By: Someone <noreply@anthropic.com>" -Deny $script:Deny) | Should -BeNullOrEmpty
    }
}

Describe 'Outgoing commits (pre-push)' {
    BeforeAll {
        # A throwaway repository: one clean commit, one that names a customer in a file and removes it again in the
        # next, and one that names it in the message. All three would be published by a push.
        $script:Repo = Join-Path $TestDrive 'repo'
        New-Item -ItemType Directory -Path $script:Repo | Out-Null
        $git = { param([string[]] $GitArgs) & git -C $script:Repo -c user.name=test -c user.email=test@contoso.example -c core.hooksPath=/dev/null -c commit.gpgsign=false @GitArgs 2>&1 | Out-Null; if ($LASTEXITCODE -ne 0) { throw "git $($GitArgs -join ' ') failed" } }
        & $git @('init', '--quiet')
        Set-Content -LiteralPath (Join-Path $script:Repo 'a.txt') -Value 'clean'
        & $git @('add', '.'); & $git @('commit', '--quiet', '-m', 'First')
        $script:Base = (& git -C $script:Repo rev-parse HEAD).Trim()
        Set-Content -LiteralPath (Join-Path $script:Repo 'a.txt') -Value "clean`nSeen live on Woodgrove Bank"
        & $git @('add', '.'); & $git @('commit', '--quiet', '-m', 'Second')
        Set-Content -LiteralPath (Join-Path $script:Repo 'a.txt') -Value 'clean again'
        & $git @('add', '.'); & $git @('commit', '--quiet', '-m', 'Third: take it out')
        Set-Content -LiteralPath (Join-Path $script:Repo 'b.txt') -Value 'more'
        & $git @('add', '.'); & $git @('commit', '--quiet', '-m', 'Fourth, for Woodgrove Bank')
        $script:Deny = [regex]::new('woodgrove[\s._-]*bank', 'IgnoreCase')
    }

    It 'finds the text in a commit even though a later commit removed it, and in a message' {
        Push-Location $script:Repo
        try { $hits = @(Test-PostureOutgoingCommit -Range "$script:Base..HEAD" -Deny $script:Deny) } finally { Pop-Location }
        $hits.Count | Should -Be 2
        @($hits | Where-Object { $_.Path -like '* a.txt' }).Count | Should -Be 1
        @($hits | Where-Object { $_.Path -like '* message' }).Count | Should -Be 1
        ($hits | Out-String) | Should -Not -Match '(?i)woodgrove'
    }

    It 'is clean for a range without it, and applies the file name rules' {
        Push-Location $script:Repo
        try {
            @(Test-PostureOutgoingCommit -Range "$script:Base..HEAD" -Deny $null) | Should -BeNullOrEmpty
            Set-Content -LiteralPath (Join-Path $script:Repo 'tenantkeep.lic') -Value 'x'
            & $git @('add', '.'); & $git @('commit', '--quiet', '-m', 'Fifth')
            $hits = @(Test-PostureOutgoingCommit -Range 'HEAD~1..HEAD' -Deny $null)
        }
        finally { Pop-Location }
        $hits.Rule | Should -Contain 'licence file'
    }
}
