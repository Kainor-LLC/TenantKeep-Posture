# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# The entry points for the Fabric (Power BI) admin API and the Power Platform admin API. Neither has a PowerShell
# module the run can lean on across platforms, so the requests are made here, and only here: this file and the two
# Graph and token files are the only places in the module that may send a web request (the module guard test).
#
# Read-only by construction. Fabric: GET, on the admin read addresses. Power Platform: GET, plus one POST that
# Microsoft made the way to list the tenant settings; its address is fixed in the function that sends it and it
# carries no body. The Power Platform API has no read-only permission, so this file is what keeps it to reads, and
# its permission lives on the second app (app-services.json), never on the shared read app. Power BI's permission,
# Tenant.Read.All, is read-only by name and is on the main app.
$script:PosturePowerHost = @{ powerbi = 'https://api.fabric.microsoft.com'; powerplatform = 'https://api.bap.microsoft.com' }

function Get-PosturePowerToken {
    <#
    .SYNOPSIS
        An access token for Power BI or Power Platform: from the run's sign-in, or in a scheduled run from the
        managed identity's Azure session.
    .DESCRIPTION
        A signed-in run has the broker (Get-PostureToken), which asks for the resource its manifest names with the
        delegated permission the customer approved: Power BI from the main sign-in, Power Platform from the second
        one. A scheduled run has no sign-in of the module's: there the token
        comes from the Azure session the runbook opened as the managed identity. Power BI accepts that identity when
        the customer has let its security group call the read-only admin APIs; Power Platform does not accept an
        identity that is not registered as a management application, which this product does not ask for.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [ValidateSet('powerbi', 'powerplatform')] [string] $Service)

    $ErrorActionPreference = 'Stop'
    if ($script:PostureSession) { return [string](Get-PostureToken -Resource $Service) }
    $audience = [string](Get-PostureAppManifest -Name (Get-PostureResourceApp -Resource $Service))['byName'][$Service]['audience']
    return [string](Get-PostureAzureResourceToken -ResourceUrl $audience)
}

function Test-PosturePowerSession {
    <#
    .SYNOPSIS
        True when a token for Power BI or Power Platform can be asked for: the run's sign-in is open, or an Azure
        session is (a scheduled run). Never connects, and does not ask for the token.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([string] $TenantId)

    $ErrorActionPreference = 'Stop'
    if ($script:PostureSession) { return $true }
    return [bool](Test-PostureAzureSession -TenantId $TenantId)
}

function Get-PosturePowerSkipReason {
    <#
    .SYNOPSIS
        Why a run is not collecting Power BI or Power Platform, in words, from what the sign-in service answered
        when the token was asked for.
    .DESCRIPTION
        The usual reason is that the tenant has not approved the permission yet. Each is optional and approved
        from a link of its own, which the reason carries: Power BI on the main app, Power Platform on the second
        app (the one Azure and Teams are read through). Anything else is passed on as the service said it.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [ValidateSet('PowerBI', 'PowerPlatform')] [string] $Collector,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Message,
        [string] $TenantId
    )

    $ErrorActionPreference = 'Stop'
    $label = @{ PowerBI = 'Power BI'; PowerPlatform = 'Power Platform' }[$Collector]
    # AADSTS65001: no consent. AADSTS650057 and AADSTS70011: the permission is not one this app holds in the tenant
    # (verify the last two on a live run; the wording is from Microsoft's error list).
    if ($Message -match 'AADSTS65001|AADSTS650057|AADSTS70011|consent') {
        $link = $(try { Get-PostureConsentLink -TenantId $TenantId -Optional -App $(if ($Collector -eq 'PowerPlatform') { 'services' } else { 'main' }) } catch { '' })
        if (-not $link) { return "This tenant has not approved the $label read, and this build carries no app id to approve it with yet." }
        return "This tenant has not approved the $label read. It is optional: an administrator approves it once, here: $link"
    }
    # AADSTS500011 and AADSTS650052: the tenant has no service principal for the API, which is a tenant that never
    # used the product (verify on a live run).
    if ($Message -match 'AADSTS500011|AADSTS650052') { return "$label is not set up in this tenant (the sign-in service knows no such API there), so there is nothing to read." }
    return "The $label sign-in failed: $Message"
}

function Invoke-PosturePowerRest {
    <#
    .SYNOPSIS
        One request to the Fabric or Power Platform admin API with the retry policy, the body parsed. Throws on a
        refusal with the status and what the service said, in its own words.
    .DESCRIPTION
        Throttling (429) and a busy service (500, 502, 503, 504) are waited out, after Retry-After when the answer
        carries one. The token is fetched for each attempt, so a long wait does not send an expired one.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [ValidateSet('powerbi', 'powerplatform')] [string] $Service,
        [Parameter(Mandatory)] [ValidateSet('GET', 'POST')] [string] $Method,
        [Parameter(Mandatory)] [ValidatePattern('^https://api\.(fabric\.microsoft|bap\.microsoft)\.com/')] [string] $Uri
    )

    $ErrorActionPreference = 'Stop'
    $policy = $script:PostureGraphRetry
    $label = @{ powerbi = 'Power BI'; powerplatform = 'Power Platform' }[$Service]
    for ($attempt = 1; ; $attempt++) {
        $request = @{ Uri = $Uri; Method = $Method; Headers = @{ Authorization = "Bearer $(Get-PosturePowerToken -Service $Service)"; Accept = 'application/json' }; SkipHttpErrorCheck = $true; ErrorAction = 'Stop' }
        # The one POST lists settings and takes no body; an empty JSON object is what the service expects to be sent.
        if ($Method -eq 'POST') { $request.Body = '{}'; $request.ContentType = 'application/json' }
        $response = Invoke-WebRequest @request
        $status = [int]$response.StatusCode
        if ($status -in 429, 500, 502, 503, 504 -and $attempt -lt $policy.maxAttempts) {
            $asked = 0
            try { $asked = [int]([string]@($response.Headers['Retry-After'])[0]) } catch { $asked = 0 }
            $delay = [Math]::Min($policy.maxWaitSeconds, [Math]::Max($asked, $policy.baseSeconds * [Math]::Pow(2, $attempt - 1)))
            Write-Verbose "$label answered $status; waiting $([int]$delay) s (attempt $attempt of $($policy.maxAttempts))."
            if ($script:PostureProgress) { $script:PostureProgress.label = "waiting $([int]$delay) s: $label asked to slow down ($status)"; Write-PostureProgress -Force }
            if ($delay -gt 0) { Start-Sleep -Seconds $delay }
            continue
        }
        $text = [string]$response.Content
        if ($status -ge 400) {
            # Both services answer a refusal with a small JSON body: a code and a sentence. That is what is passed on.
            $said = $text
            try {
                $body = ConvertFrom-Json -InputObject $text -AsHashtable -Depth 10
                $inner = $(if ($body -is [System.Collections.IDictionary] -and $body['error'] -is [System.Collections.IDictionary]) { $body['error'] } else { $body })
                $code = [string]$(if ($inner['errorCode']) { $inner['errorCode'] } else { $inner['code'] })
                $said = (@($code, [string]$inner['message']) | Where-Object { $_ }) -join ': '
            }
            catch { $said = $text }
            if ($said.Length -gt 300) { $said = $said.Substring(0, 300) }
            throw "$label answered $status to $Method $(ConvertTo-PostureCallTarget -Target $Uri): $said"
        }
        if (-not $text.Trim()) { return @{} }
        return (ConvertFrom-Json -InputObject $text -AsHashtable -Depth 40)
    }
}

function Invoke-PostureFabricRequest {
    <#
    .SYNOPSIS
        The single entry point for the Fabric admin API: GET only, on an admin read address, every page followed.
    .PARAMETER Path
        The address after the host, with the API version in it: /v1/admin/tenantsettings.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)] [ValidatePattern('^/v1/admin/[A-Za-z]+$')] [string] $Path)

    $ErrorActionPreference = 'Stop'
    $items = [System.Collections.Generic.List[object]]::new()
    $next = "$($script:PosturePowerHost.powerbi)$Path"
    while ($next) {
        Add-PostureCallRecord -Service powerbi -Method GET -Target $next
        $body = Invoke-PosturePowerRest -Service powerbi -Method GET -Uri $next
        foreach ($v in @($body['value'])) { if ($null -ne $v) { $items.Add($v) } }
        # The next page comes as a whole address; it is followed only when it is the same address on the same host.
        $next = [string]$body['continuationUri']
        if ($next -and -not $next.StartsWith("$($script:PosturePowerHost.powerbi)$Path", [System.StringComparison]::OrdinalIgnoreCase)) { throw "Power BI gave a next page at an address this run does not read: $(ConvertTo-PostureCallTarget -Target $next)" }
        if ($items.Count -gt 100000) { throw 'Power BI returned more than a hundred thousand tenant settings; stopping.' }
    }
    return $items.ToArray()
}

function Invoke-PosturePowerPlatformRequest {
    <#
    .SYNOPSIS
        The single entry point for reads of the Power Platform admin API: GET only, every page followed.
    .PARAMETER Path
        The address after the host, with its api-version: the provider is Microsoft.BusinessAppPlatform or
        PowerPlatform.Governance, and nothing else is accepted.
    .PARAMETER Single
        The answer is one object, not a list.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [ValidatePattern('^/providers/(Microsoft\.BusinessAppPlatform|PowerPlatform\.Governance)/[A-Za-z0-9/.{}-]+\?api-version=\d{4}-\d{2}-\d{2}$')] [string] $Path,
        [switch] $Single
    )

    $ErrorActionPreference = 'Stop'
    $items = [System.Collections.Generic.List[object]]::new()
    $next = "$($script:PosturePowerHost.powerplatform)$Path"
    while ($next) {
        Add-PostureCallRecord -Service powerplatform -Method GET -Target $next
        $body = Invoke-PosturePowerRest -Service powerplatform -Method GET -Uri $next
        if ($Single -or -not ($body -is [System.Collections.IDictionary] -and $body.Contains('value'))) { return $body }
        foreach ($v in @($body['value'])) { if ($null -ne $v) { $items.Add($v) } }
        $next = [string]$(if ($body.Contains('nextLink')) { $body['nextLink'] } else { '' })
        if ($next -and -not $next.StartsWith("$($script:PosturePowerHost.powerplatform)/providers/", [System.StringComparison]::OrdinalIgnoreCase)) { throw "Power Platform gave a next page at an address this run does not read: $(ConvertTo-PostureCallTarget -Target $next)" }
        if ($items.Count -gt 1000000) { throw 'Power Platform returned more than a million rows for one list; stopping.' }
    }
    return $items.ToArray()
}

function Get-PosturePowerPlatformTenantSetting {
    <#
    .SYNOPSIS
        The Power Platform tenant settings. Microsoft made listing them a POST: it takes no body, changes nothing,
        and is the one request this module sends to Power Platform that is not a GET.
    .DESCRIPTION
        The address is fixed here and takes no parameter, so this cannot become a way to send any other POST.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $ErrorActionPreference = 'Stop'
    $uri = "$($script:PosturePowerHost.powerplatform)/providers/Microsoft.BusinessAppPlatform/listTenantSettings?api-version=2023-06-01"
    Add-PostureCallRecord -Service powerplatform -Method POST -Target $uri   # posture:read-only-post (the ledger entry for the listing below)
    return (Invoke-PosturePowerRest -Service powerplatform -Method POST -Uri $uri)   # posture:read-only-post (listTenantSettings reads)
}
