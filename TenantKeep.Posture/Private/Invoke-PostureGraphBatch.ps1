# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureGraphBatch {
    <#
    .SYNOPSIS
        Many Graph GET requests through $batch, twenty to a request: one answer per URL, in the order asked.
    .DESCRIPTION
        A read that Graph only answers one object at a time (a group's PIM eligibility, a policy's settings) costs a
        round trip each; batched, twenty share one. Each answer is an ordered dictionary: url, status, body (the
        parsed JSON) and error (Graph's message when the status is 400 or more). Read-only: every request inside a
        batch is a GET, and this function builds nothing else.

        Graph throttles inside a batch per request: a 429 or 503 there is sent again after its Retry-After, up to
        the retry policy's attempts, while the answers that did arrive are kept. A collection answer that carries
        a next link is followed with ordinary requests, so "value" is whole.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        # Paths relative to the API version, as Invoke-PostureGraphRequest takes them ("groups/<id>/owners?$select=id").
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $Url,
        [Parameter(Mandatory)] [ValidateSet('v1.0', 'beta')] [string] $ApiVersion,
        [string] $Label
    )

    $ErrorActionPreference = 'Stop'
    $answers = [object[]]::new($Url.Count)
    for ($start = 0; $start -lt $Url.Count; $start += 20) {
        $pending = @($start..([Math]::Min($start + 20, $Url.Count) - 1))
        for ($try = 1; $pending.Count -gt 0; $try++) {
            $requests = @(foreach ($n in $pending) { @{ id = [string]$n; method = 'GET'; url = '/' + $Url[$n].TrimStart('/') } })
            $batch = Invoke-PostureGraphRequest -Uri '$batch' -Method 'POST' -Body @{ requests = $requests } -ApiVersion $ApiVersion -Single   # posture:read-only-post
            $again = [System.Collections.Generic.List[int]]::new(); $wait = 0
            foreach ($response in @(Get-PostureValue $batch 'responses')) {
                $n = [int](Get-PostureValue $response 'id'); $status = [int](Get-PostureValue $response 'status')
                if ($status -in 429, 503 -and $try -lt $script:PostureGraphRetry.maxAttempts) {
                    $again.Add($n)
                    $retryAfter = 0
                    if ([int]::TryParse([string](Get-PostureValue $response 'headers.Retry-After'), [ref]$retryAfter)) { $wait = [Math]::Max($wait, $retryAfter) }
                    continue
                }
                $body = Get-PostureValue $response 'body'
                # A collection that did not fit one answer: the rest comes through ordinary paging.
                if ($status -lt 400 -and $body -is [System.Collections.IDictionary] -and $body.Contains('@odata.nextLink') -and $body.Contains('value')) {
                    $rest = @(Invoke-PostureGraphRequest -Uri ([string]$body['@odata.nextLink']) -ApiVersion $ApiVersion)
                    $body['value'] = @(@($body['value']) + $rest)
                }
                $answers[$n] = [ordered]@{ url = $Url[$n]; status = $status; body = $body; error = $(if ($status -ge 400) { [string](Get-PostureValue $body 'error.message') }) }
            }
            $pending = @($again)
            if ($pending.Count -gt 0) {
                $delay = [Math]::Min($script:PostureGraphRetry.maxWaitSeconds, [Math]::Max($wait, $script:PostureGraphRetry.baseSeconds * [Math]::Pow(2, $try - 1)))
                if ($delay -gt 0) { Start-Sleep -Seconds $delay }
            }
        }
        if ($Label -and $script:PostureProgress -and $Url.Count -gt 40) {
            $script:PostureProgress.label = "$($Label): $('{0:N0}' -f [Math]::Min($start + 20, $Url.Count)) of $('{0:N0}' -f $Url.Count)"
            Write-PostureProgress
        }
    }
    # A request Graph never answered (a batch that lost one) is an answer too: status 0, so the caller sees the hole.
    for ($n = 0; $n -lt $answers.Count; $n++) { if ($null -eq $answers[$n]) { $answers[$n] = [ordered]@{ url = $Url[$n]; status = 0; body = $null; error = 'No answer in the batch response.' } } }
    # Unrolled on purpose: callers gather the answers with @( ).
    return $answers
}
