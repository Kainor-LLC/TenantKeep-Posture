# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureAgentFinding {
    <#
    .SYNOPSIS
        What the identity checks on AI agents need (ID-047 to ID-056), from the agent evidence the Entra collector
        writes: agent identities, the blueprints they are made from, the blueprints' service principals and the
        user accounts paired with agents.
    .DESCRIPTION
        Files read: 10-agent-identities, 10-agent-blueprints, 10-agent-blueprint-principals, 10-agent-users,
        04-role-assignments-active, 04-role-assignments-pim-eligible, 04-role-holders, 10-graph-app-permissions.
        None is a long list. Thresholds read: maxAgentCredentialDays, maxAgentActiveSecrets.

        A list that was not collected leaves its checks without an answer (the engine names the file). A part of
        a list that could not be read, such as the owners or the sponsors, comes through as an empty value on
        every row: the fact is then $null and the check is named in notEvaluated. Nothing here turns a part that
        was not read into zero.

        A tenant with no agents passes these checks with nothing found.
    .PARAMETER PrivilegedRole
        The directory role names the identity checks treat as privileged.
    .PARAMETER HighPrivilegePermission
        The Microsoft Graph application permissions the identity checks treat as high privilege.
    .OUTPUTS
        @{ facts; affected; notEvaluated }, to be merged into the identity provider's answer.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Evidence,
        [hashtable] $Thresholds = @{},
        [string[]] $PrivilegedRole = @(),
        [string[]] $HighPrivilegePermission = @()
    )

    $ErrorActionPreference = 'Stop'
    $t = @{ maxAgentCredentialDays = 730; maxAgentActiveSecrets = 2 }
    foreach ($k in @($Thresholds.Keys)) { $t[$k] = $Thresholds[$k] }
    $facts = [ordered]@{}; $affected = [ordered]@{}; $notEvaluated = @{}
    # $null when the file is not in the folder, an array (empty or not) when it is.
    $load = {
        param([string] $Name)
        $parsed = Read-PostureEvidenceFile -Folder $Evidence -Name $Name
        if ($null -eq $parsed) { return $null }
        return , @(@($parsed) | Where-Object { $_ })
    }
    $name = { param($row) $n = [string]$row['DisplayName']; if ($n) { $n } else { "(no name) $([string]$row['Id'])" } }
    $agents = & $load '10-agent-identities'
    $blueprints = & $load '10-agent-blueprints'
    $principals = & $load '10-agent-blueprint-principals'
    $agentUsers = & $load '10-agent-users'
    $kinds = @(
        @{ rows = $agents; kind = 'agent identity'; many = 'agent identities' }
        @{ rows = $blueprints; kind = 'agent blueprint'; many = 'agent blueprints' }
        @{ rows = $principals; kind = 'agent blueprint principal'; many = 'agent blueprint principals' }
    )
    $allThree = ($null -ne $agents -and $null -ne $blueprints -and $null -ne $principals)

    # ID-047 and ID-048: an owner looks after the object, a sponsor answers for why the agent exists. The count on a
    # row is empty when the collector could not read that part.
    foreach ($part in @(@{ id = 'ID-047'; column = 'Owners'; fact = 'agentObjectsWithoutOwner'; word = 'owner' }, @{ id = 'ID-048'; column = 'Sponsors'; fact = 'agentObjectsWithoutSponsor'; word = 'sponsor' })) {
        if (-not $allThree) { continue }
        $unread = [System.Collections.Generic.List[string]]::new(); $without = [System.Collections.Generic.List[object]]::new()
        foreach ($k in $kinds) {
            $rows = @($k.rows)
            if ($rows.Count -gt 0 -and @($rows | Where-Object { $null -ne $_[$part.column] }).Count -eq 0) { $unread.Add($k.many); continue }
            foreach ($row in @($rows | Where-Object { $null -ne $_[$part.column] -and [int]$_[$part.column] -eq 0 })) { $without.Add([ordered]@{ name = (& $name $row); detail = "$($k.kind) with no $($part.word)" }) }
        }
        if ($unread.Count -gt 0) {
            $facts[$part.fact] = $null
            $notEvaluated[$part.id] = "The $($part.word)s of the $($unread -join ' and the ') could not be read: Graph refused that part of the list. 10-agent-summary.json names what was not read."
        }
        else { $facts[$part.fact] = $without.Count; $affected[$part.fact] = $without.ToArray() }
    }

    # ID-049: an agent, or a blueprint's service principal, that was turned off and left where it is.
    if ($null -ne $agents -and $null -ne $principals) {
        $off = @(@($agents | ForEach-Object { @{ row = $_; kind = 'agent identity' } }) + @($principals | ForEach-Object { @{ row = $_; kind = 'agent blueprint principal' } }) | Where-Object { $_.row['AccountEnabled'] -eq $false })
        $facts.disabledAgentObjects = $off.Count
        $affected.disabledAgentObjects = @($off | ForEach-Object { [ordered]@{ name = (& $name $_.row); detail = "$($_.kind), disabled" } })
    }

    # ID-050: an object whose parent is gone. An agent identity names its blueprint by application id; an agent user
    # names its agent identity by object id; a blueprint's service principal in the tenant that owns the blueprint
    # has the blueprint itself beside it. A principal for a blueprint another organisation publishes has none here,
    # and is not judged.
    if ($allThree -and $null -ne $agentUsers) {
        $principalApps = @{}; foreach ($p in $principals) { if ($p['AppId']) { $principalApps[[string]$p['AppId']] = $true } }
        $blueprintApps = @{}; foreach ($b in $blueprints) { if ($b['AppId']) { $blueprintApps[[string]$b['AppId']] = $true } }
        $agentIds = @{}; foreach ($a in $agents) { if ($a['Id']) { $agentIds[[string]$a['Id']] = $true } }
        $orphans = [System.Collections.Generic.List[object]]::new()
        foreach ($a in $agents) { if (-not $a['BlueprintAppId'] -or -not $principalApps.ContainsKey([string]$a['BlueprintAppId'])) { $orphans.Add([ordered]@{ name = (& $name $a); detail = 'agent identity whose blueprint is not in this tenant' }) } }
        foreach ($p in $principals) { if ($p['HomeTenant'] -eq $true -and -not $blueprintApps.ContainsKey([string]$p['AppId'])) { $orphans.Add([ordered]@{ name = (& $name $p); detail = 'agent blueprint principal whose blueprint has been deleted' }) } }
        foreach ($u in $agentUsers) { if (-not $u['ParentId'] -or -not $agentIds.ContainsKey([string]$u['ParentId'])) { $orphans.Add([ordered]@{ name = $(if ($u['UserPrincipalName']) { [string]$u['UserPrincipalName'] } else { & $name $u }); detail = 'agent user whose agent identity is gone' }) } }
        $facts.orphanedAgentObjects = $orphans.Count
        $affected.orphanedAgentObjects = $orphans.ToArray()
    }

    # ID-051: a privileged directory role held by an agent, by a blueprint's service principal or by an agent's user
    # account: assigned, eligible, or through a group that holds the role. The role assignments name the kind of
    # principal, and the agent lists name the ids; either is enough to know an agent when one holds a role.
    $active = & $load '04-role-assignments-active'
    if ($null -ne $active -and $null -ne $agents -and $null -ne $principals -and $null -ne $agentUsers) {
        $who = @{}
        foreach ($a in $agents) { $who[[string]$a['Id']] = @{ name = (& $name $a); kind = 'agent identity' } }
        foreach ($p in $principals) { $who[[string]$p['Id']] = @{ name = (& $name $p); kind = $(if ($p['HomeTenant'] -eq $false) { 'agent blueprint principal published by another organisation' } else { 'agent blueprint principal' }) } }
        foreach ($u in $agentUsers) { $who[[string]$u['Id']] = @{ name = $(if ($u['UserPrincipalName']) { [string]$u['UserPrincipalName'] } else { & $name $u }); kind = 'agent user' } }
        $agentTypes = @{ agentIdentity = 'agent identity'; agentIdentityBlueprintPrincipal = 'agent blueprint principal'; agentUser = 'agent user' }
        $held = [System.Collections.Generic.List[object]]::new(); $seen = @{}
        $note = {
            param([string] $Id, [string] $Type, [string] $Shown, [string] $Role, [string] $How)
            if ($Role -notin $PrivilegedRole) { return }
            $known = $(if ($Id -and $who.ContainsKey($Id)) { $who[$Id] } elseif ($agentTypes.ContainsKey($Type)) { @{ name = $(if ($Shown) { $Shown } else { $Id }); kind = $agentTypes[$Type] } })
            if (-not $known) { return }
            $key = "$Id|$Role"
            if ($seen.ContainsKey($key)) { return }
            $seen[$key] = $true
            $held.Add([ordered]@{ name = "$($known.name): $Role"; detail = "$($known.kind), $How" })
        }
        # The eligible assignments and the people who hold a role through a group add to the answer when their files
        # are there; a run without them is judged on the assignments.
        $eligible = & $load '04-role-assignments-pim-eligible'
        $throughGroups = & $load '04-role-holders'
        foreach ($row in $active) { & $note ([string]$row['PrincipalId']) ([string]$row['PrincipalType']) ([string]$row['PrincipalName']) ([string]$row['Role']) 'assigned' }
        foreach ($row in @($eligible | Where-Object { $_ })) { & $note ([string]$row['PrincipalId']) ([string]$row['PrincipalType']) ([string]$row['PrincipalName']) ([string]$row['Role']) 'eligible' }
        foreach ($row in @($throughGroups | Where-Object { $_ -and [string]$_['Held'] -in 'Group', 'EligibleGroup' })) { & $note ([string]$row['UserId']) '' ([string]$row['UserPrincipalName']) ([string]$row['Role']) "through the group $([string]$row['GroupName'])" }
        $facts.agentsWithPrivilegedRoles = $held.Count
        $affected.agentsWithPrivilegedRoles = $held.ToArray()
    }

    # ID-052: a Microsoft Graph application permission that can change the directory, its policies or who holds a
    # role, granted to an agent or to a blueprint's service principal (whose agents can be given what it holds).
    $perms = & $load '10-graph-app-permissions'
    if ($null -ne $perms -and $null -ne $agents -and $null -ne $principals) {
        $holders = @{}
        foreach ($a in $agents) { $holders[[string]$a['Id']] = 'agent identity' }
        foreach ($p in $principals) { $holders[[string]$p['Id']] = 'agent blueprint principal' }
        $hits = @($perms | Where-Object { $holders.ContainsKey([string]$_['PrincipalId']) -and [string]$_['Permission'] -in $HighPrivilegePermission })
        $facts.agentsWithHighPrivilegeGraphPermissions = $hits.Count
        $affected.agentsWithHighPrivilegeGraphPermissions = @($hits | ForEach-Object { [ordered]@{ name = "$([string]$_['PrincipalDisplayName']): $([string]$_['Permission'])"; detail = "$($holders[[string]$_['PrincipalId']]), application permission" } })
    }

    if ($null -ne $blueprints) {
        # ID-053: a blueprint that passes on every permission it holds on an API, now and later, to every agent made
        # from it. Empty on every row when the collector could not read what blueprints pass on.
        if ($blueprints.Count -gt 0 -and @($blueprints | Where-Object { $null -ne $_['InheritAllScopes'] -or $null -ne $_['InheritAllRoles'] }).Count -eq 0) {
            $facts.agentBlueprintsPassingOnEverything = $null
            $notEvaluated['ID-053'] = 'What the agent blueprints pass on to their agents could not be read (inheritable permissions; needs AgentIdentityBlueprint.Read.All).'
        }
        else {
            $all = @($blueprints | Where-Object { [int]$_['InheritAllScopes'] + [int]$_['InheritAllRoles'] -gt 0 })
            $facts.agentBlueprintsPassingOnEverything = $all.Count
            $affected.agentBlueprintsPassingOnEverything = @($all | ForEach-Object { [ordered]@{ name = (& $name $_); detail = "passes on everything it holds on $([int]$_['InheritAllScopes']) API(s) as delegated permissions and on $([int]$_['InheritAllRoles']) as application permissions" } })
        }

        # ID-055: a redirect address with a wildcard, or plain http to another machine.
        $unsafe = @($blueprints | Where-Object { [int]$_['WildcardRedirects'] + [int]$_['HttpRedirects'] -gt 0 })
        $facts.agentBlueprintsWithUnsafeRedirects = $unsafe.Count
        $affected.agentBlueprintsWithUnsafeRedirects = @($unsafe | ForEach-Object { [ordered]@{ name = (& $name $_); detail = "$([int]$_['WildcardRedirects']) redirect address(es) with a wildcard, $([int]$_['HttpRedirects']) over plain http" } })

        # ID-056: credentials on a blueprint: none expired, none valid for longer than the threshold, no more working
        # secrets than the threshold, and no secret kept beside a federated credential.
        $problems = [System.Collections.Generic.List[object]]::new(); $unknownFederated = 0
        foreach ($b in $blueprints) {
            $why = [System.Collections.Generic.List[string]]::new()
            if ([int]$b['ExpiredCredentials'] -gt 0) { $why.Add("$([int]$b['ExpiredCredentials']) expired credential(s)") }
            if ([int]$b['LongestCredentialDays'] -gt [int]$t.maxAgentCredentialDays) { $why.Add("a credential valid for $([int]$b['LongestCredentialDays']) days") }
            if ([int]$b['ActiveSecrets'] -gt [int]$t.maxAgentActiveSecrets) { $why.Add("$([int]$b['ActiveSecrets']) working secrets") }
            if ([int]$b['ActiveSecrets'] -gt 0) {
                if ($null -eq $b['FederatedCredentials']) { $unknownFederated++ }
                elseif ([int]$b['FederatedCredentials'] -gt 0) { $why.Add('a secret kept beside a federated credential') }
            }
            if ($why.Count -gt 0) { $problems.Add([ordered]@{ name = (& $name $b); detail = ($why -join '; ') }) }
        }
        if ($problems.Count -eq 0 -and $unknownFederated -gt 0) {
            $facts.agentBlueprintsWithCredentialProblems = $null
            $notEvaluated['ID-056'] = "Whether $unknownFederated agent blueprint(s) with a working secret also have a federated credential could not be read; nothing else is wrong with their credentials."
        }
        else { $facts.agentBlueprintsWithCredentialProblems = $problems.Count; $affected.agentBlueprintsWithCredentialProblems = $problems.ToArray() }
    }

    # ID-054: a blueprint's service principal that exposes application roles and hands them to any caller.
    if ($null -ne $principals) {
        $open = @($principals | Where-Object { [int]$_['EnabledAppRoles'] -gt 0 -and $_['AppRoleAssignmentRequired'] -eq $false })
        $facts.agentBlueprintsOpenToAnyCaller = $open.Count
        $affected.agentBlueprintsOpenToAnyCaller = @($open | ForEach-Object { [ordered]@{ name = (& $name $_); detail = "exposes $([int]$_['EnabledAppRoles']) application role(s) and does not require assignment" } })
    }

    return @{ facts = $facts; affected = $affected; notEvaluated = $notEvaluated }
}
