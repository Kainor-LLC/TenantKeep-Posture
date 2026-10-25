# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Read-PostureAnswer {
    <#
    .SYNOPSIS
        One wizard prompt: a question, optional choices, a default. Returns the answer. Tests mock this function.
    .DESCRIPTION
        Empty input takes the default. With -Multi the answer is a comma-separated list. Choices are validated
        case-insensitively and the canonical spelling is returned. Shows the "why" line under the question.
    #>
    [CmdletBinding()]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive wizard.')]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)] [string] $Question,
        [string] $Why,
        [string[]] $Choices = @(),
        [object] $Default,
        [switch] $Multi
    )

    $ErrorActionPreference = 'Stop'
    while ($true) {
        Write-Host ''
        Write-Host $Question -ForegroundColor Cyan
        if ($Why) { Write-Host "  $Why" -ForegroundColor DarkGray }
        if ($Choices.Count -gt 0) { Write-Host "  Choices: $($Choices -join ', ')" -ForegroundColor DarkGray }
        $defaultText = if ($null -eq $Default -or ($Default -is [array] -and $Default.Count -eq 0)) { '' } elseif ($Default -is [array]) { $Default -join ', ' } else { [string]$Default }
        $raw = Read-Host -Prompt $(if ($defaultText) { "  [$defaultText]" } else { '  ' })
        if ([string]::IsNullOrWhiteSpace($raw)) { return $Default }
        $values = if ($Multi) { @($raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) } else { @($raw.Trim()) }
        if ($Choices.Count -gt 0) {
            $bad = @($values | Where-Object { $v = $_; -not ($Choices | Where-Object { $_ -eq $v }) })
            if ($bad.Count -gt 0) { Write-Host "  Not a choice: $($bad -join ', ')" -ForegroundColor Yellow; continue }
            $values = @($values | ForEach-Object { $v = $_; $Choices | Where-Object { $_ -eq $v } | Select-Object -First 1 })
        }
        if ($Multi) { return @($values) }
        return $values[0]
    }
}
