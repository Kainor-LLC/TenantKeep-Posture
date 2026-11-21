#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    Commit guards. Refuses a commit, a commit message or a push whose content looks like a credential, a key,
    tenant evidence, or company information.
.DESCRIPTION
    Pure PowerShell, no external dependency. Three ways in, one rule set:
      pre-commit   no arguments: the staged version of every added, copied or modified file
      commit-msg   -MessageFile <file>: the message being committed
      pre-push     -Outgoing <range>: the message and the added lines of every commit about to leave, so a commit
                   made with --no-verify is caught before it is public

    Blocks: Entra client secrets, bearer tokens, private key blocks, Azure storage keys and SAS tokens, connection
    string passwords, cloud provider tokens, generic "secret = '...'" assignments, Teams and Slack webhooks, and
    files that should never be committed (.pfx, .pem, .lic, CLAUDE.local.md, anything under evidence/).

    Company information, two rules:
      1. A local deny list, built when the hook runs and never stored: every id, address, tenant name and Key Vault
         name in CLAUDE.local.md, the tenant ids, names and addresses in ~/tenantkeep/clients/*/profile.json, the
         client folder names there, and the lines of .githooks/denylist.local.txt when that file exists (one text
         per line, or re:<regex>; gitignored). A hit is reported by file and line; the text is never printed.
         There is no marker that lets a deny list hit through.
      2. An allow list for mail domains and Microsoft tenant names in tracked text. Fixtures use reserved names
         (anything.example, contoso, fabrikam, the Fernquill demo tenant); any other mail domain or
         <name>.onmicrosoft.com or <name>.sharepoint.com is refused.

    A line containing the marker  posture:allow-secret  skips the credential rules and the allow list, for
    documented test fixtures only. Dot-source this file to get the functions for unit tests and CI.
#>
[CmdletBinding()]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Hook output is for the console.')]
param(
    [string] $MessageFile,
    [string] $Outgoing
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:AllowMarker = 'posture:allow-secret'
$script:DenyRule = 'company information (local deny list)'

$script:BlockedPathPatterns = @(
    @{ Name = 'certificate or key file'; Pattern = '\.(pfx|p12|pem|key|cer|crt|jks|keystore)$' }
    @{ Name = 'local notes file'; Pattern = '(^|/)CLAUDE\.local\.md$' }
    @{ Name = 'local deny list'; Pattern = '(^|/)denylist\.local\.txt$' }
    @{ Name = 'dotenv file'; Pattern = '(^|/)\.env(\..+)?$' }
    @{ Name = 'tenant evidence folder'; Pattern = '(^|/)evidence/' }
    @{ Name = 'CA snapshot folder'; Pattern = '(^|/)\d{8}-\d{4}-ca/' }
    @{ Name = 'transcript or error log'; Pattern = '(^|/)(transcript|errors)\.txt$' }
    @{ Name = 'ssh private key'; Pattern = '(^|/)id_(rsa|dsa|ecdsa|ed25519)$' }
    @{ Name = 'licence file'; Pattern = '\.lic$' }
)

$script:ContentPatterns = @(
    @{ Name = 'Entra client secret'; Pattern = '\b[A-Za-z0-9~._-]{3}8Q~[A-Za-z0-9~._-]{30,}\b' }
    @{ Name = 'JWT / bearer token'; Pattern = '\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' }
    @{ Name = 'private key block'; Pattern = '-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY( BLOCK)?-----' }
    @{ Name = 'Azure storage account key'; Pattern = 'AccountKey=[A-Za-z0-9+/]{86}==' }
    @{ Name = 'Azure SAS token'; Pattern = '[?&]sig=[A-Za-z0-9%+/]{40,}={0,2}' }
    @{ Name = 'connection string password'; Pattern = '(?i)(^|;)\s*(password|pwd)\s*=\s*[^;''"\s$]{8,}(;|$)' }
    @{ Name = 'GitHub token'; Pattern = '\bgh[pousr]_[A-Za-z0-9]{36,}\b' }
    @{ Name = 'AWS access key id'; Pattern = '\bAKIA[0-9A-Z]{16}\b' }
    @{ Name = 'Teams or Slack webhook'; Pattern = 'https://(hooks\.slack\.com/services/|[a-z0-9-]+\.webhook\.office\.com/webhookb2/)' }
    @{ Name = 'generic secret assignment'; Pattern = '(?i)\b(client[_-]?secret|api[_-]?key|access[_-]?token|secret|password)\b\s*[:=]\s*[''"][A-Za-z0-9+/=_~.-]{16,}[''"]' }
)

# Names that are public by design: the publisher, the product, Microsoft's fictitious companies, the demo tenant.
# Mail domains may also be anything under the reserved .example top-level domain.
$script:AllowedMailDomains = @('example.com', 'example.org', 'example.net', 'contoso.com', 'fabrikam.com', 'kainor.com', 'tenantkeep.com', 'tenantkeep.app', 'github.com', 'users.noreply.github.com', 'anthropic.com')
$script:AllowedTenantLabels = @('contoso', 'fabrikam', 'tenant', 'fernquilldemo', 'kainor')
$script:PublicNames = @('kainor', 'tenantkeep', 'lapslock', 'contoso', 'fabrikam', 'fernquill', 'fernquilldemo', 'example', 'tenant', 'client', 'clients', 'test', 'demo', 'sample')
# Words that say nothing about whose name it is: "Kainor LLC" is still only the publisher.
$script:GenericNameWords = @('llc', 'inc', 'ltd', 'limited', 'corp', 'corporation', 'co', 'company', 'gmbh', 'plc', 'the')

$script:GuidPattern = '[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}'
$script:MailPattern = '(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)'
# A tenant name at the start of a label: not inside a longer name, not after $ ) } > (string interpolation and
# placeholders such as "$Tenant.onmicrosoft.com" or "<tenant>-admin.sharepoint.com").
$script:TenantHostPattern = '(?<![\w$)}>.-])([A-Za-z0-9][A-Za-z0-9-]*)\.(?:(?:mail\.)?onmicrosoft\.com|sharepoint\.com)'

function Test-PostureAllowedMailDomain {
    <#
    .SYNOPSIS
        True for a mail domain fixtures and docs may use: a reserved example name, the publisher's, or an allowed tenant.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Domain)

    $d = $Domain.ToLowerInvariant().TrimEnd('.')
    if ($d -eq 'example' -or $d.EndsWith('.example')) { return $true }
    if ($d -in $script:AllowedMailDomains) { return $true }
    if ($d -match '^([a-z0-9-]+)\.(?:mail\.)?onmicrosoft\.com$') { return ($Matches[1] -in $script:AllowedTenantLabels) }
    return $false
}

function Get-PostureDenyRegex {
    <#
    .SYNOPSIS
        The local deny list as one case-insensitive regex, or $null when this machine has nothing to deny (CI, a fresh
        clone). Built from the local notes and the client folders each time the hook runs; nothing is written.
    .PARAMETER NotesPath
        CLAUDE.local.md. Every id, mail address, tenant name and Key Vault name in it is denied, and the organisation
        names read from its domains, in any spacing ("woodgrove-bank.test" also denies "Woodgrove Bank").
    .PARAMETER ClientsRoot
        ~/tenantkeep/clients. The same reading of each profile.json, plus the client folder names.
    .PARAMETER ExtraPath
        Optional lines to deny: plain text, or re:<regex>. Lines starting with # are comments.
    #>
    [CmdletBinding()]
    [OutputType([regex])]
    param(
        [string] $NotesPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'CLAUDE.local.md'),
        [string] $ClientsRoot = (Join-Path $HOME 'tenantkeep' 'clients'),
        [string] $ExtraPath = (Join-Path $PSScriptRoot 'denylist.local.txt')
    )

    $ErrorActionPreference = 'Stop'
    $literals = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $patterns = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    # An organisation's name from a domain label or a folder name: "woodgrove-bank1" denies woodgrove bank in any spacing.
    $addName = {
        param([string] $Label)
        $words = @(($Label.ToLowerInvariant() -replace '\d+$', '') -split '[^a-z0-9]+' | Where-Object { $_ })
        if ($words.Count -eq 0 -or @($words | Where-Object { $_ -notin $script:PublicNames -and $_ -notin $script:GenericNameWords }).Count -eq 0) { return }
        if ((-join $words).Length -lt 5) { return }
        $null = $patterns.Add((@($words | ForEach-Object { [regex]::Escape($_) }) -join '[\s._-]*'))
    }
    $addText = {
        param([string] $Text)
        foreach ($m in [regex]::Matches($Text, $script:GuidPattern)) { $null = $literals.Add($m.Value) }
        foreach ($m in [regex]::Matches($Text, $script:MailPattern)) {
            $null = $literals.Add($m.Value)
            $domain = $m.Groups[1].Value
            if ($domain -notmatch '\.[A-Za-z]{2,}$' -or (Test-PostureAllowedMailDomain -Domain $domain)) { continue }
            $null = $literals.Add($domain)
            & $addName ($domain -split '\.')[0]
        }
        foreach ($m in [regex]::Matches($Text, $script:TenantHostPattern)) {
            $label = ($m.Groups[1].Value -replace '-(admin|my)$', '')
            if ($label.ToLowerInvariant() -in $script:AllowedTenantLabels) { continue }
            $null = $literals.Add($m.Value)
            & $addName $label
        }
        # Key Vault names in the usual prefix form: a vault name is a public DNS name, so it stays out of tracked text.
        foreach ($m in [regex]::Matches($Text, '(?<![A-Za-z0-9-])kv-[a-z0-9]+(?:-[a-z0-9]+)+(?![A-Za-z0-9-])')) { $null = $literals.Add($m.Value) }
    }

    if ($NotesPath -and (Test-Path -LiteralPath $NotesPath -PathType Leaf)) { & $addText (Get-Content -Raw -LiteralPath $NotesPath) }
    if ($ClientsRoot -and (Test-Path -LiteralPath $ClientsRoot -PathType Container)) {
        foreach ($dir in Get-ChildItem -LiteralPath $ClientsRoot -Directory) {
            & $addName $dir.Name
            $profilePath = Join-Path $dir.FullName 'profile.json'
            if (-not (Test-Path -LiteralPath $profilePath -PathType Leaf)) { continue }
            $text = Get-Content -Raw -LiteralPath $profilePath
            & $addText $text
            try { $name = [string](ConvertFrom-Json -InputObject $text -AsHashtable)['clientName'] } catch { $name = '' }
            if ($name) { & $addName $name }
        }
    }
    if ($ExtraPath -and (Test-Path -LiteralPath $ExtraPath -PathType Leaf)) {
        foreach ($line in Get-Content -LiteralPath $ExtraPath) {
            $t = $line.Trim()
            if (-not $t -or $t.StartsWith('#')) { continue }
            if ($t.StartsWith('re:')) { $null = $patterns.Add($t.Substring(3)) } else { $null = $literals.Add($t) }
        }
    }

    $parts = @(@($literals | ForEach-Object { [regex]::Escape($_) }) + @($patterns) | Where-Object { $_ })
    if ($parts.Count -eq 0) { return $null }
    return [regex]::new('(?:' + ($parts -join '|') + ')', [System.Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant')
}

function Get-PostureCachedDenyRegex {
    <#
    .SYNOPSIS
        The deny list, built once per process.
    #>
    [CmdletBinding()]
    [OutputType([regex])]
    param()

    if (-not (Get-Variable -Name PostureDenyLoaded -Scope Script -ValueOnly -ErrorAction SilentlyContinue)) {
        $script:PostureDenyRegex = Get-PostureDenyRegex
        $script:PostureDenyLoaded = $true
    }
    return $script:PostureDenyRegex
}

function Test-PostureStagedContent {
    <#
    .SYNOPSIS
        Scans one file's content and returns a finding object per hit. Empty output means clean.
    .PARAMETER Deny
        The deny list. Default: this machine's (Get-PostureDenyRegex). Tests pass their own, or $null for none.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter()] [AllowEmptyString()] [string] $Content = '',
        [Parameter()] [AllowNull()] [regex] $Deny = (Get-PostureCachedDenyRegex)
    )

    $ErrorActionPreference = 'Stop'

    foreach ($p in $script:BlockedPathPatterns) {
        if ($Path -match $p.Pattern) {
            [pscustomobject]@{ Path = $Path; Line = 0; Rule = $p.Name; Text = '(file name)' }
        }
    }
    if ($Deny -and $Deny.IsMatch($Path)) { [pscustomobject]@{ Path = '(withheld)'; Line = 0; Rule = $script:DenyRule; Text = '(file name; text withheld)' } }

    if ($Content.Contains([char]0)) { return }   # binary, path rules only

    $lineNumber = 0
    foreach ($line in ($Content -split "`r?`n")) {
        $lineNumber++
        # The deny list first, and no marker lets it through.
        if ($Deny -and $Deny.IsMatch($line)) {
            [pscustomobject]@{ Path = $Path; Line = $lineNumber; Rule = $script:DenyRule; Text = '(text withheld)' }
            continue
        }
        if ($line.Contains($script:AllowMarker)) { continue }
        $hit = $false
        foreach ($p in $script:ContentPatterns) {
            if ($line -match $p.Pattern) {
                $shown = if ($line.Length -gt 120) { $line.Substring(0, 120) + '...' } else { $line }
                [pscustomobject]@{ Path = $Path; Line = $lineNumber; Rule = $p.Name; Text = $shown.Trim() }
                $hit = $true
                break
            }
        }
        if ($hit) { continue }
        # Mail domains and tenant names: reserved and public names only.
        $unknown = [System.Collections.Generic.List[string]]::new()
        foreach ($m in [regex]::Matches($line, $script:MailPattern)) {
            $domain = $m.Groups[1].Value
            # A version after an at sign (actions/checkout@v4.1.0) is not a mail domain.
            if ($domain -match '\.[A-Za-z]{2,}$' -and -not (Test-PostureAllowedMailDomain -Domain $domain)) { $unknown.Add($domain) }
        }
        if ($unknown.Count -gt 0) {
            [pscustomobject]@{ Path = $Path; Line = $lineNumber; Rule = 'mail domain not on the allow list'; Text = (@($unknown | Select-Object -Unique) -join ', ') }
            continue
        }
        foreach ($m in [regex]::Matches($line, $script:TenantHostPattern)) {
            $label = ($m.Groups[1].Value -replace '-(admin|my)$', '').ToLowerInvariant()
            if ($label -notin $script:AllowedTenantLabels) { $unknown.Add($m.Value) }
        }
        if ($unknown.Count -gt 0) { [pscustomobject]@{ Path = $Path; Line = $lineNumber; Rule = 'tenant name not on the allow list'; Text = (@($unknown | Select-Object -Unique) -join ', ') } }
    }
}

function Write-PostureScanFinding {
    <#
    .SYNOPSIS
        Prints the findings of a scan and what to do about them.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Hook,
        [Parameter(Mandatory)] [string] $What,
        [Parameter(Mandatory)] [object[]] $Finding
    )

    Write-Host "$($Hook): refusing, $What" -ForegroundColor Red
    foreach ($f in $Finding) { Write-Host ("  {0}:{1}  [{2}]  {3}" -f $f.Path, $f.Line, $f.Rule, $f.Text) }
    if (@($Finding | Where-Object { $_.Rule -eq $script:DenyRule }).Count) { Write-Host 'A deny list hit names something in CLAUDE.local.md or a client folder. Take it out; there is no marker for it.' -ForegroundColor Yellow }
    if (@($Finding | Where-Object { $_.Rule -like '*allow list' }).Count) { Write-Host 'Fixtures use reserved names: name@contoso.example, contoso.onmicrosoft.com, contoso.sharepoint.com.' -ForegroundColor Yellow }
    if (@($Finding | Where-Object { $_.Rule -ne $script:DenyRule }).Count) { Write-Host "If a line is a documented fake used by a test, add the marker '$script:AllowMarker' to it." -ForegroundColor Yellow }
}

function Invoke-PostureStagedScan {
    <#
    .SYNOPSIS
        pre-commit: scans the staged files. Returns the exit code.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param()

    $ErrorActionPreference = 'Stop'
    $staged = @(git diff --cached --name-only --diff-filter=ACM -z | ForEach-Object { $_ -split "`0" } | Where-Object { $_ })
    $findings = foreach ($file in $staged) {
        if ($file -eq '.githooks/Test-StagedSecrets.ps1') { continue }   # the pattern list would match itself
        $content = (git show ":$file" | Out-String)
        Test-PostureStagedContent -Path $file -Content $content
    }

    if ($findings) {
        Write-PostureScanFinding -Hook 'pre-commit' -What 'possible secret, tenant data or company information staged:' -Finding @($findings)
        return 1
    }
    Write-Host "pre-commit: scan clean ($($staged.Count) file(s))"
    return 0
}

function Test-PostureCommitMessage {
    <#
    .SYNOPSIS
        Scans a commit message (comment lines left out) and returns a finding object per hit.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Message,
        [string] $Label = 'commit message',
        [Parameter()] [AllowNull()] [regex] $Deny = (Get-PostureCachedDenyRegex)
    )

    $text = (@($Message -split "`r?`n" | ForEach-Object { if ($_.StartsWith('#')) { '' } else { $_ } }) -join "`n")
    Test-PostureStagedContent -Path $Label -Content $text -Deny $Deny
}

function Invoke-PostureMessageScan {
    <#
    .SYNOPSIS
        commit-msg: scans the message file git hands over. Returns the exit code.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)] [string] $Path)

    $ErrorActionPreference = 'Stop'
    $findings = @(Test-PostureCommitMessage -Message ([string](Get-Content -Raw -LiteralPath $Path)))
    if ($findings.Count -gt 0) {
        Write-PostureScanFinding -Hook 'commit-msg' -What 'the commit message carries a possible secret or company information:' -Finding $findings
        return 1
    }
    return 0
}

function Test-PostureOutgoingCommit {
    <#
    .SYNOPSIS
        Scans the commits a push would publish: each message, each added or changed file name, each added line.
        Returns a finding object per hit, with the commit in Path.
    .PARAMETER Range
        What git rev-list takes: "<remote sha>..<local sha>", or "<local sha> --not --remotes" for a new branch.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Range,
        [Parameter()] [AllowNull()] [regex] $Deny = (Get-PostureCachedDenyRegex)
    )

    $ErrorActionPreference = 'Stop'
    $revArgs = @($Range -split '\s+' | Where-Object { $_ })
    $commits = @(git rev-list @revArgs)
    if ($LASTEXITCODE -ne 0) { throw "git rev-list $Range failed." }
    foreach ($sha in $commits) {
        $short = $sha.Substring(0, 7)
        Test-PostureCommitMessage -Message ((git log -1 --format=%B $sha) -join "`n") -Label "$short message" -Deny $Deny
        # Added lines per file, from a zero-context diff. Deleted lines and context are not published by this commit.
        $file = $null
        $added = [System.Collections.Generic.List[string]]::new()
        $flush = {
            if ($file -and $file -ne '.githooks/Test-StagedSecrets.ps1') { Test-PostureStagedContent -Path "$short $file" -Content ($added -join "`n") -Deny $Deny }
            $added.Clear()
        }
        foreach ($line in @(git show --format= --unified=0 --no-color --no-ext-diff --diff-filter=ACMR $sha)) {
            if ($line.StartsWith('+++ ')) { . $flush; $file = $(if ($line -eq '+++ /dev/null') { $null } else { $line.Substring(4) -replace '^b/', '' }); continue }
            if ($line.StartsWith('diff --git ')) { . $flush; $file = $null; continue }
            if ($file -and $line.StartsWith('+')) { $added.Add($line.Substring(1)) }
        }
        . $flush
        # A binary file has no added lines; its name is still checked.
        foreach ($name in @(git show --format= --name-only --diff-filter=ACMR $sha | Where-Object { $_ })) {
            foreach ($p in $script:BlockedPathPatterns) { if ($name -match $p.Pattern) { [pscustomobject]@{ Path = "$short $name"; Line = 0; Rule = $p.Name; Text = '(file name)' } } }
        }
    }
}

function Invoke-PostureOutgoingScan {
    <#
    .SYNOPSIS
        pre-push: scans the commits about to leave. Returns the exit code.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)] [string] $Range)

    $ErrorActionPreference = 'Stop'
    # The same finding from a file name rule and from the diff is reported once.
    $findings = @(Test-PostureOutgoingCommit -Range $Range | Sort-Object Path, Line, Rule -Unique)
    if ($findings.Count -gt 0) {
        Write-PostureScanFinding -Hook 'pre-push' -What 'a commit about to be pushed carries a possible secret or company information:' -Finding $findings
        Write-Host 'The commit is in the history being pushed even when a later commit removed the text: rewrite it before pushing.' -ForegroundColor Yellow
        return 1
    }
    Write-Host 'pre-push: outgoing commits scan clean'
    return 0
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($MessageFile) { exit (Invoke-PostureMessageScan -Path $MessageFile) }
    if ($Outgoing) { exit (Invoke-PostureOutgoingScan -Range $Outgoing) }
    exit (Invoke-PostureStagedScan)
}
