# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureChecks {
    <#
    .SYNOPSIS
        Runs the check catalog against an evidence folder and writes checks.json (spec 6, 10).
    .DESCRIPTION
        Checks are data in checks/*.json; this cmdlet evaluates them. Scope and targets come from -Baseline
        (a shipped name such as standard, or a path), facts about the tenant from -Profile (profile.json), and
        accepted risk from -Exceptions (exceptions.json). Each result carries pass, fail, notEvaluated with the
        reason, notApplicable, acceptedRisk or coveredBy, plus the affected objects and the evidence files used.

        Reads only local files. No Graph session is needed.
    .PARAMETER Evidence
        Evidence folder. For the Conditional Access domain this is an Export-PostureCaSnapshot folder.
    .PARAMETER Baseline
        Baseline name under baselines/ or a path to a baseline JSON. Default: standard.
    .PARAMETER ProfilePath
        Path to profile.json (alias -Profile). Without it every check is evaluated and license gating is off.
    .PARAMETER Exceptions
        Path to exceptions.json.
    .PARAMETER CustomChecks
        Folders with org-specific checks in the catalog schema, rendered alongside and tagged custom.
    .PARAMETER Domain
        Limit to these domains, for example ca.
    .PARAMETER OutputPath
        Folder for checks.json. Default: the evidence folder.
    .PARAMETER PassThru
        Return the full result object instead of the checks.json path.
    .EXAMPLE
        Invoke-PostureChecks -Evidence ~/tenantkeep/evidence/20261013-2231-ca -Domain ca

        Evaluates the Conditional Access checks against that snapshot with the standard baseline.
    .EXAMPLE
        Invoke-PostureChecks -Evidence ./snap -Baseline cisa-scuba -Profile ~/tenantkeep/clients/contoso/profile.json -Exceptions ~/tenantkeep/clients/contoso/exceptions.json -PassThru

        Full result object for a client folder.
    .OUTPUTS
        System.String, the checks.json path. With -PassThru, the result object.
    .LINK
        docs/posture-spec.md sections 6 and 10
    #>
    [CmdletBinding()]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Spec section 6 names the cmdlet Invoke-PostureChecks.')]
    [OutputType([string], [System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory, Position = 0)] [ValidateNotNullOrEmpty()] [string] $Evidence,
        [string] $Baseline = 'standard',
        [Alias('Profile')] [string] $ProfilePath,
        [string] $Exceptions,
        [string[]] $CustomChecks = @(),
        [string[]] $Domain,
        [string] $OutputPath,
        [switch] $PassThru
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    if (-not (Test-Path -LiteralPath $Evidence -PathType Container)) { throw "Evidence folder not found: $Evidence" }
    $evidencePath = (Resolve-Path -LiteralPath $Evidence).Path

    $catalog = Import-PostureCheckCatalog -CustomPath $CustomChecks
    $baselineModel = Import-PostureBaseline -Baseline $Baseline
    $profileModel = Import-PostureProfile -Path $ProfilePath
    $exceptionList = @(Import-PostureException -Path $Exceptions)

    $params = @{ Catalog = $catalog; Baseline = $baselineModel; OrgProfile = $profileModel; Exception = $exceptionList; Evidence = $evidencePath }
    if ($Domain) { $params.Domain = $Domain }
    $run = Invoke-PostureCheckEvaluation @params
    $run.exceptionsFile = $(if ($Exceptions) { (Resolve-Path -LiteralPath $Exceptions).Path } else { $null })
    $run.moduleVersion = $script:ModuleVersion

    $outFolder = if ($OutputPath) { $OutputPath } else { $evidencePath }
    if (-not (Test-Path -LiteralPath $outFolder)) { New-Item -ItemType Directory -Path $outFolder -Force | Out-Null }
    $path = Join-Path (Resolve-Path -LiteralPath $outFolder).Path 'checks.json'
    [System.IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject $run -Depth 20), [System.Text.UTF8Encoding]::new($false))

    $c = $run.counts
    Write-Verbose "checks.json: pass $($c.pass), fail $($c.fail), not evaluated $($c.notEvaluated), not applicable $($c.notApplicable), accepted risk $($c.acceptedRisk), covered $($c.coveredBy)"
    if ($PassThru) { return $run }
    return $path
}
