# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function ConvertFrom-PostureJwt {
    <#
    .SYNOPSIS
        Returns the payload claims of a JWT as a hashtable. No signature check: the token came from the token endpoint
        over TLS and is only read for its tenant, account, scopes and expiry.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [string] $Token)

    $ErrorActionPreference = 'Stop'
    $parts = $Token.Split('.')
    if ($parts.Count -lt 2) { throw 'Not a JWT: expected at least two dot-separated parts.' }
    $payload = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) { 2 { $payload += '==' } 3 { $payload += '=' } }
    $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
    return ($json | ConvertFrom-Json -AsHashtable)
}
