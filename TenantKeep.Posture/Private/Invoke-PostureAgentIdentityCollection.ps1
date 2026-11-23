# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureAgentIdentityCollection {
    <#
    .SYNOPSIS
        The agent part of the Entra collection: agent identities, the blueprints they are made from, the blueprints'
        service principals, the user accounts paired with agents, and the Conditional Access policies that name
        agents. Microsoft Graph, GET only.
    .DESCRIPTION
        Microsoft Entra Agent ID gives an AI agent an identity of its own. An agent identity is a service principal
        made from a blueprint (an application); the blueprint has a service principal in each tenant that uses it;
        an agent can also be paired with a user account. Microsoft lists the three kinds only with permissions of
        their own, all read-only: AgentIdentity.Read.All, AgentIdentityBlueprint.Read.All and
        AgentIdentityBlueprintPrincipal.Read.All. Agent users list with the user read the run already holds.

        One step per list, so a tenant that has not approved one permission still gets the others, and Run Health
        names the permission that is missing. What is saved is settings and counts: names, ids, whether each is
        enabled, how many owners and sponsors it has, what its credentials and redirect addresses look like. Not
        saved: who the owners and sponsors are, a secret or certificate, or anything an agent did.

        A part that cannot be read is left empty and named in NotRead of 10-agent-summary, so a check has no answer
        for it and never reads it as zero:
          - Owners are asked for with the list ($expand=owners), as the service principal list is. When Graph
            refuses that form the list is read without them.
          - Sponsors are asked for in a second pass ($expand=sponsors): Microsoft documents the sponsors address of
            an agent identity for application permissions that write, so the list form is the read-only way in.
            (verify) on a live tenant that it answers.
          - What a blueprint passes on to its agents (inheritable permissions) is one request per blueprint.

        Conditional Access keeps its agent conditions (agent identities as the client, the agent risk level, agent
        users) in the beta form of a policy, which the v1.0 snapshot in policies.json does not carry, so the
        policies are read once more here and only the ones that name agents are kept, as a few fields each.
    .OUTPUTS
        @{ files = <names written> }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [datetime] $AsOf = [datetime]::UtcNow
    )

    $ErrorActionPreference = 'Stop'
    $files = [System.Collections.Generic.List[string]]::new()
    $save = { param($Data, [string] $Name) $files.Add((Write-PostureEvidence -Folder $Folder -Name $Name -InputObject $Data -AsArray -Csv)) }
    $saveOne = { param($Data, [string] $Name) $files.Add((Write-PostureEvidence -Folder $Folder -Name $Name -InputObject $Data)) }
    $get = { param([string] $Uri, [string] $Api = 'v1.0') @(Invoke-PostureGraphRequest -Uri $Uri -ApiVersion $Api) }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $date = { param($s) ConvertTo-PostureUtcDateTime $s }
    $utc = { param($x) $(if ($x) { (ConvertTo-PostureUtcDateTime $x).ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }) }
    # Graph says 400 to a form of a request it does not support. Only that falls back to a lesser read: a refusal
    # (403), throttling or a server error is the step's own failure, with its cause in Run Health.
    $unsupported = { param($e) (Get-PostureHttpStatus -ErrorRecord $e) -eq 400 -or [string]$e.Exception.Message -match '(?i)BadRequest|Request_UnsupportedQuery|Unsupported query' }
    # What was read and what was not, filled in by the steps and written last.
    $state = @{ counts = [ordered]@{ AgentIdentities = $null; Blueprints = $null; BlueprintPrincipals = $null; AgentUsers = $null; PoliciesForAgents = $null }; notRead = [System.Collections.Generic.List[string]]::new() }
    $count = { param($x) @(@($x) | Where-Object { $_ }).Count }

    # A typed list with its owners, and its sponsors from a second pass. Returns the items; each carries
    # '__owners' and '__sponsors': a count, or $null when that part could not be read.
    $listOf = {
        param([string] $Address, [string] $Select, [string] $What)
        $ownersRead = $true
        try { $items = & $get "$($Address)?`$select=$Select&`$expand=owners(`$select=id)" }
        catch {
            if (-not (& $unsupported $_)) { throw }
            Write-Verbose "$What read without owners: $($_.Exception.Message)"
            $ownersRead = $false; $state.notRead.Add("owners of $What")
            # Without the owners first; and if Graph still objects, without naming the properties either.
            try { $items = & $get "$($Address)?`$select=$Select" }
            catch { if (-not (& $unsupported $_)) { throw }; $items = & $get $Address }
        }
        $items = @($items | Where-Object { $_ })
        $sponsors = $null
        if ($items.Count -gt 0) {
            try {
                $sponsors = @{}
                foreach ($s in @(& $get "$($Address)?`$select=id&`$expand=sponsors(`$select=id)" | Where-Object { $_ })) { $sponsors[[string](& $v $s 'id')] = & $count (& $v $s 'sponsors') }
            }
            catch {
                Write-Verbose "Sponsors of $What not read: $($_.Exception.Message)"
                $sponsors = $null; $state.notRead.Add("sponsors of $What")
            }
        }
        foreach ($item in $items) {
            $id = [string](& $v $item 'id')
            $item['__owners'] = $(if ($ownersRead) { & $count (& $v $item 'owners') } else { $null })
            $item['__sponsors'] = $(if ($null -ne $sponsors -and $sponsors.ContainsKey($id)) { $sponsors[$id] } else { $null })
        }
        , $items
    }

    Invoke-PostureStep -Label 'Agent identities' -Folder $Folder -Script {
        $items = & $listOf 'servicePrincipals/microsoft.graph.agentIdentity' 'id,appId,displayName,accountEnabled,createdDateTime,agentIdentityBlueprintId,createdByAppId,disabledByMicrosoftStatus' 'agent identities'
        & $save @($items | ForEach-Object {
                [ordered]@{
                    Id = (& $v $_ 'id'); AppId = (& $v $_ 'appId'); DisplayName = (& $v $_ 'displayName'); AccountEnabled = (& $v $_ 'accountEnabled'); CreatedDateTime = (& $utc (& $v $_ 'createdDateTime'))
                    BlueprintAppId = (& $v $_ 'agentIdentityBlueprintId'); CreatedByAppId = (& $v $_ 'createdByAppId'); DisabledByMicrosoft = (& $v $_ 'disabledByMicrosoftStatus')
                    Owners = $_['__owners']; Sponsors = $_['__sponsors']
                }
            }) '10-agent-identities'
        $state.counts.AgentIdentities = $items.Count
    } | Out-Null

    Invoke-PostureStep -Label 'Agent identity blueprint principals' -Folder $Folder -Script {
        $tenantId = [string](Get-MgContext).TenantId
        $items = & $listOf 'servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal' 'id,appId,displayName,accountEnabled,appOwnerOrganizationId,appRoleAssignmentRequired,appRoles' 'agent blueprint principals'
        & $save @($items | ForEach-Object {
                $ownerTenant = [string](& $v $_ 'appOwnerOrganizationId')
                [ordered]@{
                    Id = (& $v $_ 'id'); AppId = (& $v $_ 'appId'); DisplayName = (& $v $_ 'displayName'); AccountEnabled = (& $v $_ 'accountEnabled')
                    AppOwnerOrganizationId = $ownerTenant; HomeTenant = $(if ($ownerTenant -and $tenantId) { $ownerTenant -eq $tenantId } else { $null })
                    AppRoleAssignmentRequired = (& $v $_ 'appRoleAssignmentRequired'); EnabledAppRoles = @(@(& $v $_ 'appRoles') | Where-Object { $_ -and (& $v $_ 'isEnabled') -eq $true }).Count
                    Owners = $_['__owners']; Sponsors = $_['__sponsors']
                }
            }) '10-agent-blueprint-principals'
        $state.counts.BlueprintPrincipals = $items.Count
    } | Out-Null

    Invoke-PostureStep -Label 'Agent identity blueprints' -Folder $Folder -Script {
        $items = & $listOf 'applications/microsoft.graph.agentIdentityBlueprint' 'id,appId,displayName,createdDateTime,signInAudience,passwordCredentials,keyCredentials,web' 'agent blueprints'
        $inheritRead = $true; $federatedRead = $true
        $rows = @($items | ForEach-Object {
                $item = $_; $id = [string](& $v $item 'id')
                $secrets = @(@(& $v $item 'passwordCredentials') | Where-Object { $_ }); $certs = @(@(& $v $item 'keyCredentials') | Where-Object { $_ })
                $spans = @(@($secrets) + @($certs) | ForEach-Object { [pscustomobject]@{ from = (& $date (& $v $_ 'startDateTime')); to = (& $date (& $v $_ 'endDateTime')) } })
                # A secret that works today: started, and not yet ended (one with no end date counts).
                $active = @($secrets | Where-Object { $from = & $date (& $v $_ 'startDateTime'); $to = & $date (& $v $_ 'endDateTime'); (-not $from -or $from -le $AsOf) -and (-not $to -or $to -ge $AsOf) }).Count
                # Redirect addresses a sign-in result should never be sent to: one with a wildcard, or plain http
                # to anything but this machine.
                $wild = 0; $plain = 0
                foreach ($uri in @(@(& $v $item 'web.redirectUris') | Where-Object { $_ } | ForEach-Object { [string]$_ })) {
                    if ($uri -match '\*') { $wild++; continue }
                    $parsed = $null
                    if ([uri]::TryCreate($uri, [System.UriKind]::Absolute, [ref]$parsed) -and $parsed.Scheme -eq 'http' -and -not $parsed.IsLoopback) { $plain++ }
                }
                # What the blueprint hands to every agent made from it, per API: named permissions, or all of them.
                $allScopes = $null; $allRoles = $null
                if ($inheritRead) {
                    try {
                        $inherit = @(& $get "applications/$id/microsoft.graph.agentIdentityBlueprint/inheritablePermissions" | Where-Object { $_ })
                        $allScopes = @($inherit | Where-Object { [string](& $v $_ 'inheritableScopes.kind') -eq 'allAllowed' }).Count
                        $allRoles = @($inherit | Where-Object { [string](& $v $_ 'inheritableRoles.kind') -eq 'allAllowed' }).Count
                    }
                    catch { Write-Verbose "Inheritable permissions of agent blueprints not read: $($_.Exception.Message)"; $inheritRead = $false; $state.notRead.Add('inheritable permissions of agent blueprints') }
                }
                # A secret kept beside a federated credential is the fallback the federated credential was meant to
                # retire. Asked only of a blueprint that has a working secret.
                $federated = $null
                if ($active -gt 0 -and $federatedRead) {
                    try { $federated = @(& $get "applications/$id/federatedIdentityCredentials?`$select=id" | Where-Object { $_ }).Count }
                    catch { Write-Verbose "Federated credentials of agent blueprints not read: $($_.Exception.Message)"; $federatedRead = $false; $state.notRead.Add('federated credentials of agent blueprints') }
                }
                [ordered]@{
                    Id = $id; AppId = (& $v $item 'appId'); DisplayName = (& $v $item 'displayName'); CreatedDateTime = (& $utc (& $v $item 'createdDateTime')); SignInAudience = (& $v $item 'signInAudience')
                    ActiveSecrets = $active; Certs = $certs.Count
                    ExpiredCredentials = @($spans | Where-Object { $_.to -and $_.to -lt $AsOf }).Count
                    # The longest any secret or certificate is valid for, start to end, in days; 0 with none.
                    LongestCredentialDays = [int](@(@($spans | Where-Object { $_.from -and $_.to } | ForEach-Object { [Math]::Ceiling(($_.to - $_.from).TotalDays) }) + 0 | Measure-Object -Maximum).Maximum)
                    FederatedCredentials = $federated; WildcardRedirects = $wild; HttpRedirects = $plain
                    InheritAllScopes = $allScopes; InheritAllRoles = $allRoles
                    Owners = $item['__owners']; Sponsors = $item['__sponsors']
                }
            })
        & $save $rows '10-agent-blueprints'
        $state.counts.Blueprints = $rows.Count
    } | Out-Null

    Invoke-PostureStep -Label 'Agent users' -Folder $Folder -Script {
        # Microsoft's page writes the type with a capital A and Maester asks for it without; one of the two answers.
        $select = '$select=id,displayName,userPrincipalName,accountEnabled,identityParentId'
        try { $items = & $get "users/microsoft.graph.agentUser?$select" }
        catch { if (-not (& $unsupported $_)) { throw }; $items = & $get "users/microsoft.graph.AgentUser?$select" }
        $items = @($items | Where-Object { $_ })
        & $save @($items | ForEach-Object { [ordered]@{ Id = (& $v $_ 'id'); DisplayName = (& $v $_ 'displayName'); UserPrincipalName = (& $v $_ 'userPrincipalName'); AccountEnabled = (& $v $_ 'accountEnabled'); ParentId = (& $v $_ 'identityParentId') } }) '10-agent-users'
        $state.counts.AgentUsers = $items.Count
    } | Out-Null

    Invoke-PostureStep -Label 'Conditional Access for agents' -Folder $Folder -Script {
        $rows = @(& $get 'identity/conditionalAccess/policies' 'beta' | Where-Object { $_ } | ForEach-Object {
                $include = @(@(& $v $_ 'conditions.clientApplications.includeAgentIdServicePrincipals') | Where-Object { $_ } | ForEach-Object { [string]$_ })
                $exclude = @(@(& $v $_ 'conditions.clientApplications.excludeAgentIdServicePrincipals') | Where-Object { $_ })
                $filter = [string](& $v $_ 'conditions.clientApplications.agentIdServicePrincipalFilter.rule')
                $users = @(@(& $v $_ 'conditions.users.includeUsers') | Where-Object { $_ } | ForEach-Object { [string]$_ }) -contains 'AllAgentIdUsers'
                # One value or several, as a list or as one comma-separated string.
                $risk = @(@(& $v $_ 'conditions.agentIdRiskLevels') | Where-Object { $_ } | ForEach-Object { ([string]$_) -split '\s*,\s*' } | Where-Object { $_ -and $_ -ne 'none' })
                if ($include.Count -eq 0 -and -not $filter -and -not $users -and $risk.Count -eq 0) { return }
                [ordered]@{
                    Name = (& $v $_ 'displayName'); State = (& $v $_ 'state')
                    AgentIdentities = ($include.Count -gt 0 -or [bool]$filter); AllAgentIdentities = ($include -contains 'All' -and $exclude.Count -eq 0 -and -not $filter)
                    AgentUsers = $users; RiskLevels = ($risk -join ','); Blocks = (@(& $v $_ 'grantControls.builtInControls') -contains 'block')
                }
            })
        & $save $rows '10-agent-ca-policies'
        $state.counts.PoliciesForAgents = $rows.Count
    } | Out-Null

    # Written when anything at all was read, so a tenant that approved none of this has no file and every check on
    # agents says the list was not collected.
    if (@($state.counts.Values | Where-Object { $null -ne $_ }).Count -gt 0) {
        $summary = [ordered]@{}
        foreach ($k in $state.counts.Keys) { $summary[$k] = $state.counts[$k] }
        $summary['NotRead'] = @($state.notRead | Select-Object -Unique)
        & $saveOne $summary '10-agent-summary'
    }
    return @{ files = @($files) }
}
