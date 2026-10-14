#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    Pre-commit secret scanner. Refuses the commit when staged content looks like a credential, a key, or tenant evidence.
.DESCRIPTION
    Pure PowerShell, no external dependency. Scans the staged version of every added, copied or modified file.
    Blocks: Entra client secrets, bearer tokens, private key blocks, Azure storage keys and SAS tokens, connection
    string passwords, cloud provider tokens, generic "secret = '...'" assignments, Teams and Slack webhooks, and
    files that should never be committed (.pfx, .pem, CLAUDE.local.md, anything under evidence/).
    A line containing the marker  posture:allow-secret  is skipped, for documented test fixtures only.
    Dot-source this file to get Test-PostureStagedContent for unit tests; run it as a script to scan the index.
#>
[CmdletBinding()]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Hook output is for the console.')]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:AllowMarker = 'posture:allow-secret'

$script:BlockedPathPatterns = @(
    @{ Name = 'certificate or key file'; Pattern = '\.(pfx|p12|pem|key|cer|crt|jks|keystore)$' }
    @{ Name = 'local notes file'; Pattern = '(^|/)CLAUDE\.local\.md$' }
    @{ Name = 'dotenv file'; Pattern = '(^|/)\.env(\..+)?$' }
    @{ Name = 'tenant evidence folder'; Pattern = '(^|/)evidence/' }
    @{ Name = 'CA snapshot folder'; Pattern = '(^|/)\d{8}-\d{4}-ca/' }
    @{ Name = 'transcript or error log'; Pattern = '(^|/)(transcript|errors)\.txt$' }
    @{ Name = 'ssh private key'; Pattern = '(^|/)id_(rsa|dsa|ecdsa|ed25519)$' }
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

function Test-PostureStagedContent {
    <#
    .SYNOPSIS
        Scans one file's content and returns a finding object per hit. Empty output means clean.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter()] [AllowEmptyString()] [string] $Content = ''
    )

    $ErrorActionPreference = 'Stop'

    foreach ($p in $script:BlockedPathPatterns) {
        if ($Path -match $p.Pattern) {
            [pscustomobject]@{ Path = $Path; Line = 0; Rule = $p.Name; Text = '(file name)' }
        }
    }

    if ($Content.Contains([char]0)) { return }   # binary, path rules only

    $lineNumber = 0
    foreach ($line in ($Content -split "`r?`n")) {
        $lineNumber++
        if ($line.Contains($script:AllowMarker)) { continue }
        foreach ($p in $script:ContentPatterns) {
            if ($line -match $p.Pattern) {
                $shown = if ($line.Length -gt 120) { $line.Substring(0, 120) + '...' } else { $line }
                [pscustomobject]@{ Path = $Path; Line = $lineNumber; Rule = $p.Name; Text = $shown.Trim() }
                break
            }
        }
    }
}

function Invoke-PostureStagedScan {
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
        Write-Host 'pre-commit: refusing to commit, possible secret or tenant data staged:' -ForegroundColor Red
        foreach ($f in $findings) {
            Write-Host ("  {0}:{1}  [{2}]  {3}" -f $f.Path, $f.Line, $f.Rule, $f.Text)
        }
        Write-Host "If this is a documented fake used by a test, add the marker '$script:AllowMarker' to that line." -ForegroundColor Yellow
        return 1
    }
    Write-Host "pre-commit: secret scan clean ($($staged.Count) file(s))"
    return 0
}

if ($MyInvocation.InvocationName -ne '.') {
    exit (Invoke-PostureStagedScan)
}
