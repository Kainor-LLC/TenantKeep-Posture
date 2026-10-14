# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Initialize-CaDiffFixture {
    <#
    .SYNOPSIS
        Builds a before/after snapshot pair under -Root from samples/ca-snapshot with a known set of changes.
    .DESCRIPTION
        After differs from before by: p-001 loses BreakGlass-02 and drops to the MFA strength; p-002 is disabled and
        gains an exclusion group; p-003 is renamed; p-005 loses compliantDevice; p-008 is removed; p-009 (enabled,
        references a deleted group) is added; HQ egress gains a range and Branch VPN (trusted) is added; the
        phishing-resistant strength gains password,sms; group 201 swaps a member and group 202 grows by 9.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Root,
        [Parameter(Mandatory)] [string] $Sample
    )

    $before = Join-Path $Root 'before'
    $after = Join-Path $Root 'after'
    Copy-Item -Path $Sample -Destination $before -Recurse
    Copy-Item -Path $Sample -Destination $after -Recurse

    $load = { param($dir, $name) Get-Content -Raw -LiteralPath (Join-Path $dir "$name.json") | ConvertFrom-Json -AsHashtable -Depth 30 }
    $save = { param($dir, $name, $obj) ConvertTo-Json -InputObject $obj -Depth 30 | Set-Content -LiteralPath (Join-Path $dir "$name.json") }

    $g = & $load $before 'group-scope'
    ($g | Where-Object groupId -eq '22222222-2222-2222-2222-222222222201').memberCount = 2
    ($g | Where-Object groupId -eq '22222222-2222-2222-2222-222222222201').members = @(
        @{ id = 'm1'; type = 'user'; displayName = 'Member One'; userPrincipalName = 'one@contoso.example' }
        @{ id = 'm2'; type = 'user'; displayName = 'Member Two'; userPrincipalName = 'two@contoso.example' }
    )
    & $save $before 'group-scope' $g

    $policies = & $load $after 'policies'
    $byId = @{}; foreach ($p in $policies) { $byId[$p.id] = $p }
    $byId['p-001'].conditions.users.excludeUsers = @('11111111-1111-1111-1111-111111111111')
    $byId['p-001'].grantControls.authenticationStrength = @{ id = '00000000-0000-0000-0000-000000000002'; displayName = 'Multifactor authentication' }
    $byId['p-002'].state = 'disabled'
    $byId['p-002'].conditions.users.excludeGroups += '22222222-2222-2222-2222-222222222203'
    $byId['p-003'].displayName = 'CA-008-Users-Block legacy authentication'
    $byId['p-005'].grantControls.builtInControls = @('mfa')
    $byId['p-005'].modifiedDateTime = '2026-10-12T10:00:00Z'
    $new = @{
        id = 'p-009'; displayName = 'CA-009-Users-Require MFA for admin portals'; state = 'enabled'
        createdDateTime = '2026-10-12T09:00:00Z'; modifiedDateTime = '2026-10-12T09:00:00Z'
        conditions = @{ users = @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @('22222222-2222-2222-2222-222222222299'); excludeGroups = @(); includeRoles = @(); excludeRoles = @() }; applications = @{ includeApplications = @('MicrosoftAdminPortals'); excludeApplications = @(); includeUserActions = @() }; clientAppTypes = @('all') }
        grantControls = @{ operator = 'OR'; builtInControls = @('mfa') }
    }
    $policies = @($policies | Where-Object { $_.id -ne 'p-008' }) + @($new)
    & $save $after 'policies' $policies

    $names = & $load $after 'resolved-names'
    $names['00000000-0000-0000-0000-000000000002'] = @{ displayName = 'Multifactor authentication'; type = 'authenticationStrength'; deleted = $false }
    $names['MicrosoftAdminPortals'] = @{ displayName = 'Microsoft Admin Portals (built-in app group)'; type = 'builtIn'; deleted = $false }
    & $save $after 'resolved-names' $names

    $locs = & $load $after 'named-locations'
    ($locs | Where-Object id -eq '55555555-5555-5555-5555-555555555501').ipRanges += @{ '@odata.type' = '#microsoft.graph.iPv4CidrRange'; cidrAddress = '198.51.100.0/24' }
    $locs += @{ '@odata.type' = '#microsoft.graph.ipNamedLocation'; id = '55555555-5555-5555-5555-555555555503'; displayName = 'Branch VPN'; isTrusted = $true; ipRanges = @(@{ '@odata.type' = '#microsoft.graph.iPv4CidrRange'; cidrAddress = '192.0.2.0/24' }) }
    & $save $after 'named-locations' $locs

    $str = & $load $after 'auth-strengths'
    ($str | Where-Object id -eq '00000000-0000-0000-0000-000000000004').allowedCombinations += 'password,sms'
    & $save $after 'auth-strengths' $str

    $g = & $load $after 'group-scope'
    ($g | Where-Object groupId -eq '22222222-2222-2222-2222-222222222201').memberCount = 2
    ($g | Where-Object groupId -eq '22222222-2222-2222-2222-222222222201').members = @(
        @{ id = 'm2'; type = 'user'; displayName = 'Member Two'; userPrincipalName = 'two@contoso.example' }
        @{ id = 'm3'; type = 'user'; displayName = 'Member Three'; userPrincipalName = 'three@contoso.example' }
    )
    ($g | Where-Object groupId -eq '22222222-2222-2222-2222-222222222201').memberHash = 'changed'
    $big = $g | Where-Object groupId -eq '22222222-2222-2222-2222-222222222202'
    $big.memberCount = 350; $big.memberHash = 'changed-too'
    & $save $after 'group-scope' $g

    $meta = & $load $after 'metadata'
    $meta.timestampUtc = '2026-10-14T09:05:00.0000000Z'
    & $save $after 'metadata' $meta

    return [pscustomobject]@{ Before = $before; After = $after }
}
