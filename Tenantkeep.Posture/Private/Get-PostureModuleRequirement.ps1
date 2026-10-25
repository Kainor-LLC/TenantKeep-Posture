# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureModuleRequirement {
    <#
    .SYNOPSIS
        The table of service modules the collectors use, with the version each was last proven on.
    .DESCRIPTION
        One row per module: the collectors that need it and the version the live runs used (Kainor and the first
        customer, October 2026). "tested" is a floor for a warning, not a refusal: an older version is not known to
        fail, it is untested, and the version in use is recorded in collection.json either way. Bump a row when a
        live run proves a newer version. The Graph floor is the one the manifest requires.
    .PARAMETER Name
        One or more module names; default every row.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([string[]] $Name)

    $ErrorActionPreference = 'Stop'
    $table = @(
        @{ name = 'Microsoft.Graph.Authentication'; tested = '2.39.0'; collectors = @('ConditionalAccess', 'Entra', 'Intune', 'Defender'); note = 'Required by the module manifest, 2.0.0 or later.' }
        @{ name = 'ExchangeOnlineManagement'; tested = '3.10.1'; collectors = @('Exchange', 'Purview'); note = 'Connect-ExchangeOnline -AccessToken needs 3.1.0 or later; Exchange and Purview run in their own process.' }
        @{ name = 'PnP.PowerShell'; tested = '3.2.0'; collectors = @('SharePoint'); note = 'Loaded after every Graph read. 2.12.0 signs in with the broker token and reads the tenant and sites (Kainor, 2026-10-25), but its Get-PnPTenantRestrictedSearchMode fails with a licence error where 3.2.0 answers, so the Copilot gate C9 is not evaluated on 2.x.' }
        @{ name = 'MicrosoftTeams'; tested = '7.9.0'; collectors = @('Teams'); note = 'Signed in with access tokens; the browser sign-in fails on macOS.' }
        @{ name = 'Az.Accounts'; tested = '5.5.3'; collectors = @('Azure'); note = 'Signed in with an access token for the Resource Manager audience.' }
        @{ name = 'Az.ResourceGraph'; tested = '1.3.0'; collectors = @('Azure'); note = 'From the Az rollup in Automation; the standalone module did not load there.' }
    )
    foreach ($row in $table) {
        if ($Name -and $row.name -notin $Name) { continue }
        $row
    }
}

function Test-PostureModuleRequirement {
    <#
    .SYNOPSIS
        Compares one module's installed version with the tested one: missing, older, ok, or present when the version is unknown.
    .PARAMETER Name
        The module name, a row of Get-PostureModuleRequirement.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [string] $Name)

    $ErrorActionPreference = 'Stop'
    $row = @(Get-PostureModuleRequirement -Name $Name)
    if ($row.Count -eq 0) { throw "$Name is not a module the collectors use." }
    $row = $row[0]
    $tested = [version]$row.tested
    $install = "Install-Module $Name -Scope CurrentUser"
    $available = @(Get-Module -ListAvailable -Name $Name | Where-Object { $_ })
    $versions = @($available | ForEach-Object { if ($_.PSObject.Properties['Version'] -and $_.Version) { [version]$_.Version } } | Sort-Object -Descending)
    $installed = $(if ($versions.Count -gt 0) { $versions[0] } else { $null })
    $status = if ($available.Count -eq 0) { 'missing' }
    elseif ($null -eq $installed) { 'present' }
    elseif ($installed -lt $tested) { 'older' }
    else { 'ok' }
    $message = switch ($status) {
        'missing' { "$Name is not installed: $install" }
        'older' { "$Name $installed is older than the version the collectors were tested with ($tested). If $($row.collectors -join ' or ') fails, update it: Update-Module $Name" }
        default { '' }
    }
    @{ name = $Name; installed = $installed; tested = $tested; status = $status; collectors = $row.collectors; install = $install; message = $message; note = $row.note }
}

function Get-PostureModuleVersionUsed {
    <#
    .SYNOPSIS
        The version of each service module this process has loaded, else the newest installed, else null; for the run manifest.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param()

    $ErrorActionPreference = 'Stop'
    $used = [ordered]@{}
    foreach ($row in Get-PostureModuleRequirement) {
        $loaded = @(Get-Module -Name $row.name | Where-Object { $_ -and $_.PSObject.Properties['Version'] -and $_.Version } | Sort-Object Version -Descending)
        if ($loaded.Count -gt 0) { $used[$row.name] = [string]$loaded[0].Version; continue }
        $check = Test-PostureModuleRequirement -Name $row.name
        $used[$row.name] = $(if ($check.installed) { [string]$check.installed } else { $null })
    }
    $used
}
