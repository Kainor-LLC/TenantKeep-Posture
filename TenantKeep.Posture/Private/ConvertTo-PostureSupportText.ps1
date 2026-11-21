# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function ConvertTo-PostureSupportText {
    <#
    .SYNOPSIS
        Text with the tenant's names taken out, for logs an admin sends to whoever supports the module: the names the
        caller knows (tenant, client, account) first, then email addresses, onmicrosoft.com names, SharePoint
        addresses, ids, IP addresses and the home folder.
    .DESCRIPTION
        Best effort, by pattern: read the text before sending it. Microsoft's own app ids stay, so a message about
        Graph or the Exchange app still says which one.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [AllowNull()] [string] $Text,
        [string[]] $Name = @()
    )

    if (-not $Text) { return '' }
    $t = $Text
    # Unique first, then longest first: -Unique on a length key would drop a different name of the same length.
    foreach ($n in @($Name | Where-Object { $_ -and $_.Length -ge 3 } | Select-Object -Unique | Sort-Object { - $_.Length })) { $t = [regex]::Replace($t, [regex]::Escape($n), '{name}', 'IgnoreCase') }
    if ($HOME) { $t = $t.Replace($HOME, '~') }
    $t = $t -replace '[A-Za-z0-9._%+''-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', '{user}'
    $t = $t -replace '[A-Za-z0-9-]+(-my|-admin)?\.sharepoint\.(com|us|cn|de)[^\s"''<>]*', '{site}'
    $t = $t -replace '[A-Za-z0-9-]+\.onmicrosoft\.com', '{tenant}.onmicrosoft.com'
    # Microsoft's first-party app and resource ids say which service answered; the rest name the tenant's objects.
    $keep = '00000003-0000-0000-c000-000000000000|00000003-0000-0ff1-ce00-000000000000|00000002-0000-0ff1-ce00-000000000000|48ac35b8-9aa8-4d74-927d-1f4a14a0b239|797f4846-ba00-4fd7-ba43-dac1f8f63013|fb78d390-0c51-40cd-8e17-fdbfab77341b|00000000-0000-0000-0000-000000000000'
    $t = [regex]::Replace($t, '[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}', [System.Text.RegularExpressions.MatchEvaluator] { param($m) if ($m.Value -match "^($keep)$") { $m.Value } else { '{id}' } })
    $t = $t -replace '(?<![\d.])(\d{1,3}\.){3}\d{1,3}(?![\d.])', '{ip}'
    return $t
}

function Get-PostureSupportDetail {
    <#
    .SYNOPSIS
        One failure as a block of text to copy and send: the module and environment, the run, the step and its cause,
        the request that failed, what it needs, Microsoft's message and where in the module it stopped. Names, ids
        and addresses are taken out (ConvertTo-PostureSupportText).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Failure,
        [string] $RunName,
        [string] $Build,
        [string[]] $Name = @()
    )

    $v = { param([string] $k) if ($Failure.Contains($k) -and $null -ne $Failure[$k]) { $Failure[$k] } else { '' } }
    $needs = @(@(& $v 'roles') | Where-Object { $_ }) + @(@(& $v 'scopes') | Where-Object { $_ } | ForEach-Object { "permission $_" }) + @($(if (& $v 'licence') { "licence $(& $v 'licence')" }))
    $lines = @(
        'TenantKeep Posture support details'
        "Module: $(& $v 'moduleVersion') $(if ($Build) { "($Build)" })".TrimEnd()
        "PowerShell: $(& $v 'powershell') on $(& $v 'os')"
        "Run: $RunName  Failed at: $(& $v 'timeUtc')"
        "Domain: $(& $v 'collector')  Step: $(& $v 'step')  Cause: $(& $v 'cause')"
        "Request: $(if (& $v 'request') { & $v 'request' } else { 'none sent in this step' })"
        "Needs: $(if ($needs.Count) { $needs -join '; ' } else { 'nothing listed' })"
        "Message: $(& $v 'message')"
        'Where:'
        @(@(& $v 'where') | Where-Object { $_ } | ForEach-Object { "  $_" })
    )
    return (ConvertTo-PostureSupportText -Text ((@($lines) | Where-Object { $null -ne $_ }) -join "`n") -Name $Name)
}
