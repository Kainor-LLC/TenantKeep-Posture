# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Get-PostureRoleHolder {
    <#
    .SYNOPSIS
        Everyone who holds a directory role in an evidence folder: the people, how each holds each role, and which
        groups' people are unknown.
    .DESCRIPTION
        A role is held directly, as eligible, or through a group that holds it: as a member, or as someone PIM for
        Groups lets become one. The role assignments name the group, never its people, so a tenant that assigns its
        roles to groups had "one administrator" per group and its real administrators went uncounted.

        Reads 04-role-holders, which the Entra collector writes from the assignments and the groups' members (since
        2026-11-21). For a run made before it, falls back to the people the assignments name themselves; source is
        then 'assignments' and every group that holds a role is listed in unread. Every admin set in the module
        (registration, users, sign-in tallies, the checks, the admins table) comes from here, so they agree.

        Held is one of Direct, Eligible, Group, EligibleGroup. EligibleGroup covers both ways a group makes a role
        something a person can take up: the group is eligible for the role, or the person is eligible to join it.
    .OUTPUTS
        Hashtable: available (false when no role file is in the folder), source ('holders' or 'assignments'),
        people (ordered, by user principal name in lower case: upn, id, name, synced, enabled, roles = list of role,
        held, assignmentType, groupId, groupName, membership), upns (a case-insensitive set of the names), unread
        (one entry per group whose people are not all known: name, missing = 'members' or 'eligible', roles = list
        of role and assignmentType), servicePrincipals and groups (the assignment rows of those principal types).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Folder
    )

    $ErrorActionPreference = 'Stop'
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $rows = { param($o) @($o | Where-Object { $_ }) }
    $out = @{
        available = $false; source = $null
        people = [ordered]@{}; upns = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        unread = @(); servicePrincipals = @(); groups = @()
    }
    $add = {
        param([string] $Upn, [string] $Id, [string] $Name, $Synced, $Enabled, [hashtable] $Role)
        if (-not $Upn) { return }
        $key = $Upn.ToLowerInvariant()
        if (-not $out.people.Contains($key)) { $out.people[$key] = @{ upn = $Upn; id = $Id; name = $Name; synced = $Synced; enabled = $Enabled; roles = [System.Collections.Generic.List[object]]::new() }; $null = $out.upns.Add($Upn) }
        $person = $out.people[$key]
        if ($null -eq $person.synced -and $null -ne $Synced) { $person.synced = $Synced }
        if ($null -eq $person.enabled -and $null -ne $Enabled) { $person.enabled = $Enabled }
        $person.roles.Add($Role)
    }

    $active = Read-PostureEvidenceFile -Folder $Folder -Name '04-role-assignments-active'
    $eligible = Read-PostureEvidenceFile -Folder $Folder -Name '04-role-assignments-pim-eligible'
    $holders = Read-PostureEvidenceFile -Folder $Folder -Name '04-role-holders'
    if ($null -eq $active -and $null -eq $eligible -and $null -eq $holders) { return $out }
    $out.available = $true
    $assignments = @(& $rows $active) + @(& $rows $eligible)
    $out.servicePrincipals = @($assignments | Where-Object { [string](& $v $_ 'PrincipalType') -eq 'servicePrincipal' })
    $out.groups = @($assignments | Where-Object { [string](& $v $_ 'PrincipalType') -eq 'group' })
    # What each group holds, by the group's name: the roles a group's unread people would hold.
    $held = @{}
    foreach ($g in $out.groups) {
        $name = [string](& $v $g 'PrincipalName')
        if (-not $held.ContainsKey($name)) { $held[$name] = [System.Collections.Generic.List[object]]::new() }
        $held[$name].Add(@{ role = [string](& $v $g 'Role'); assignmentType = [string](& $v $g 'AssignmentType') })
    }
    $unread = { param([string] $Name, [string] $Missing) @{ name = $Name; missing = $Missing; roles = @($(if ($held.ContainsKey($Name)) { $held[$Name] })) } }

    if ($null -ne $holders) {
        $out.source = 'holders'
        foreach ($h in @(& $rows $holders)) {
            & $add ([string](& $v $h 'UserPrincipalName')) ([string](& $v $h 'UserId')) ([string](& $v $h 'DisplayName')) (& $v $h 'Synced') (& $v $h 'AccountEnabled') @{
                role = [string](& $v $h 'Role'); held = [string](& $v $h 'Held'); assignmentType = [string](& $v $h 'AssignmentType')
                groupId = [string](& $v $h 'GroupId'); groupName = [string](& $v $h 'GroupName'); membership = [string](& $v $h 'Membership')
            }
        }
        $summary = Read-PostureEvidenceFile -Folder $Folder -Name '04-role-holders-summary'
        $out.unread = @(
            @(& $v $summary 'GroupsNotRead' | Where-Object { $_ } | ForEach-Object { & $unread ([string]$_) 'members' }) +
            @(& $v $summary 'EligibleMembersNotRead' | Where-Object { $_ } | ForEach-Object { & $unread ([string]$_) 'eligible' })
        )
        return $out
    }

    # A run from before 04-role-holders: the people the assignments name, and every group left unopened.
    $out.source = 'assignments'
    foreach ($a in $assignments) {
        # A row with a sign-in name is a person, whether or not it says so (older rows carry no PrincipalType).
        if ([string](& $v $a 'PrincipalType') -notin 'user', '' -or -not (& $v $a 'PrincipalUpn')) { continue }
        $type = [string](& $v $a 'AssignmentType')
        & $add ([string](& $v $a 'PrincipalUpn')) ([string](& $v $a 'PrincipalId')) ([string](& $v $a 'PrincipalName')) (& $v $a 'PrincipalSynced') $null @{
            role = [string](& $v $a 'Role'); held = $(if ($type -eq 'Eligible') { 'Eligible' } else { 'Direct' }); assignmentType = $type; groupId = ''; groupName = ''; membership = ''
        }
    }
    $out.unread = @($held.get_Keys() | Sort-Object | ForEach-Object { & $unread ([string]$_) 'members' })
    return $out
}

function Get-PostureRoleHolderGap {
    <#
    .SYNOPSIS
        One sentence saying which role holders are unknown for a question, or nothing when everyone it asks about
        was read.
    .DESCRIPTION
        A check that counts administrators can only speak for the people in the list. When a group that holds a role
        was not opened, the check says so: a gap it saw is still a finding, judged on those read; with no gap among
        them it has no answer. -Role narrows the question to groups holding one of those roles. -Standing asks only
        about people who hold a role today: groups assigned the role (not eligible for it) whose members are unread;
        who could join a group later does not change who holds the role now.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [hashtable] $Holder,
        [string[]] $Role = @(),
        [switch] $Standing
    )

    $ErrorActionPreference = 'Stop'
    $relevant = @(foreach ($u in @($Holder.unread)) {
            if ($Standing -and $u.missing -ne 'members') { continue }
            $roles = @($u.roles | Where-Object { (-not $Standing -or $_.assignmentType -ne 'Eligible') -and ($Role.Count -eq 0 -or $_.role -in $Role) })
            # A group the summary names with no assignment row beside it still counts when no role is asked for.
            if ($roles.Count -gt 0 -or ($Role.Count -eq 0 -and -not $Standing -and @($u.roles).Count -eq 0)) { $u }
        })
    if ($relevant.Count -eq 0) { return $null }
    $what = $(if ($Role.Count -eq 1) { $Role[0] } else { 'a role' })
    $names = { param($list) $n = @($list | ForEach-Object { [string]$_.name }); "$(@($n | Select-Object -First 5) -join ', ')$(if ($n.Count -gt 5) { " and $($n.Count - 5) more" })" }
    $members = @($relevant | Where-Object { $_.missing -eq 'members' }); $eligible = @($relevant | Where-Object { $_.missing -eq 'eligible' })
    $parts = @(
        $(if ($members.Count -gt 0 -and $Holder.source -eq 'assignments') { "$($members.Count) group(s) hold $what and this evidence is from before their members were read ($(& $names $members))" })
        $(if ($members.Count -gt 0 -and $Holder.source -ne 'assignments') { "the members of $($members.Count) group(s) that hold $what were not read ($(& $names $members))" })
        $(if ($eligible.Count -gt 0) { "who can join $($eligible.Count) group(s) that hold $what through PIM for Groups was not read ($(& $names $eligible))" })
    ) | Where-Object { $_ }
    return (@($parts) -join '; ')
}
