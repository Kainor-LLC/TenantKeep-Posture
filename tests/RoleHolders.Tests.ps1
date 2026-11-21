# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# Everyone who holds a role. A role is held directly, as eligible, or through a group; the assignments name the
# group and not its people. These tests hold every admin set to the same list (04-role-holders): an administrator
# who is only eligible, or only in a group, is counted, and a group nobody opened is never taken for "no one".
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-holders-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $script:Write = { param([string] $Dir, [string] $Name, $Data) ConvertTo-Json -InputObject $Data -Depth 10 | Set-Content -LiteralPath (Join-Path $Dir "$Name.json") }

    # A made-up tenant: two break-glass accounts and a group hold Global Administrator, Alice holds Exchange
    # Administrator, Erin is eligible for Global Administrator and nothing else. Tina and Tom are in the group.
    $script:People = [ordered]@{
        bg1   = @{ Id = 'u-bg1'; Upn = 'breakglass01@contoso.example'; Name = 'BreakGlass-01'; Methods = 'fido2'; Licenses = 0 }
        bg2   = @{ Id = 'u-bg2'; Upn = 'breakglass02@contoso.example'; Name = 'BreakGlass-02'; Methods = 'fido2'; Licenses = 0 }
        alice = @{ Id = 'u-alice'; Upn = 'alice.admin@contoso.example'; Name = 'Alice Admin'; Methods = 'passKeyDeviceBound'; Licenses = 0 }
        erin  = @{ Id = 'u-erin'; Upn = 'erin.eligible@contoso.example'; Name = 'Erin Eligible'; Methods = 'mobilePhone'; Licenses = 0 }
        tina  = @{ Id = 'u-tina'; Upn = 'tina.tier0@contoso.example'; Name = 'Tina Tier'; Methods = 'windowsHelloForBusiness'; Licenses = 1 }
        tom   = @{ Id = 'u-tom'; Upn = 'tom.tier0@contoso.example'; Name = 'Tom Tier'; Methods = 'mobilePhone'; Licenses = 0 }
    }
    $script:Group = @{ Id = 'g-tier0'; Name = 'SG-Tier0-Admins' }
    $script:Tenant = {
        param([string] $Name, [switch] $NoHolders, [string[]] $GroupsNotRead = @(), [string[]] $EligibleNotRead = @(), [hashtable] $Methods = @{}, [int] $ExtraGlobalAdmins = 0)
        $dir = Join-Path $script:Root $Name
        New-Item -ItemType Directory -Path $dir | Out-Null
        $p = $script:People; $g = $script:Group
        $assign = { param([string] $Role, [string] $Type, [hashtable] $Who, [string] $PrincipalType = 'user') [ordered]@{ Role = $Role; RoleDefinitionId = "r-$($Role -replace ' ', '')"; AssignmentType = $Type; MemberType = 'Direct'; DirectoryScopeId = '/'; PrincipalType = $PrincipalType; PrincipalName = $Who.Name; PrincipalUpn = $Who.Upn; PrincipalSynced = $false; PrincipalId = $Who.Id } }
        $extra = @(1..[Math]::Max(1, $ExtraGlobalAdmins) | Where-Object { $_ -le $ExtraGlobalAdmins } | ForEach-Object { @{ Id = "u-x$_"; Upn = "extra$_@contoso.example"; Name = "Extra $_"; Methods = 'fido2'; Licenses = 0 } })
        $active = @(
            (& $assign 'Global Administrator' 'Assigned' $p.bg1), (& $assign 'Global Administrator' 'Assigned' $p.bg2)
            (& $assign 'Global Administrator' 'Assigned' @{ Id = $g.Id; Name = $g.Name; Upn = $null } 'group')
            (& $assign 'Exchange Administrator' 'Assigned' $p.alice)
        ) + @($extra | ForEach-Object { & $assign 'Global Administrator' 'Assigned' $_ })
        $eligible = @((& $assign 'Global Administrator' 'Eligible' $p.erin))
        & $script:Write $dir '04-role-assignments-active' $active
        & $script:Write $dir '04-role-assignments-pim-eligible' $eligible
        if (-not $NoHolders) {
            $row = { param($a, [hashtable] $Who, [string] $Held, [string] $Membership = '') [ordered]@{ UserId = $Who.Id; UserPrincipalName = $Who.Upn; DisplayName = $Who.Name; AccountEnabled = $true; Synced = $false; Role = $a.Role; RoleDefinitionId = $a.RoleDefinitionId; DirectoryScopeId = '/'; AssignmentType = $a.AssignmentType; Held = $Held; GroupId = $(if ($Membership) { $g.Id }); GroupName = $(if ($Membership) { $g.Name }); Membership = $Membership } }
            $opened = $g.Name -notin $GroupsNotRead
            $holders = @(foreach ($a in @($active) + @($eligible)) {
                    if ($a.PrincipalType -eq 'user') { & $row $a @{ Id = $a.PrincipalId; Upn = $a.PrincipalUpn; Name = $a.PrincipalName } $(if ($a.AssignmentType -eq 'Eligible') { 'Eligible' } else { 'Direct' }) }
                    elseif ($opened) { foreach ($who in $p.tina, $p.tom) { & $row $a $who 'Group' 'Member' } }
                })
            & $script:Write $dir '04-role-holders' $holders
            & $script:Write $dir '04-role-holders-summary' @{ Holders = @($holders | ForEach-Object { $_.UserPrincipalName } | Sort-Object -Unique).Count; GroupsHoldingRoles = 1; GroupsRead = $(if ($opened) { 1 } else { 0 }); GroupsNotRead = @($GroupsNotRead); EligibleMembersNotRead = @($EligibleNotRead) }
        }
        $everyone = @($p.get_Values()) + @($extra)
        & $script:Write $dir '05-auth-registration-admins' @($everyone | ForEach-Object { $m = $(if ($Methods.ContainsKey($_.Upn)) { $Methods[$_.Upn] } else { $_.Methods }); [ordered]@{ UserPrincipalName = $_.Upn; UserDisplayName = $_.Name; UserType = 'member'; IsAdmin = $false; IsMfaRegistered = $true; MethodsRegistered = $m } })
        & $script:Write $dir '06-users-admins' @($everyone | ForEach-Object { [ordered]@{ Id = $_.Id; UserPrincipalName = $_.Upn; DisplayName = $_.Name; AccountEnabled = $true; UserType = 'Member'; OnPremisesSyncEnabled = $false; LicenseCount = $_.Licenses } })
        & $script:Write $dir '06-users-breakglass-candidates' @($p.bg1, $p.bg2 | ForEach-Object { [ordered]@{ Id = $_.Id; UserPrincipalName = $_.Upn; DisplayName = $_.Name; AccountEnabled = $true; OnPremisesSyncEnabled = $false } })
        & $script:Write $dir '06-users-guests' @()
        & $script:Write $dir '06-users-summary' @{ Total = 40; Members = 40; Guests = 0 }
        $dir
    }
    $script:Checks = {
        param([string] $Dir)
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache -Confirm:$false }
        $run = Invoke-PostureChecks -Evidence $Dir -Domain auth, identity -PassThru
        $by = @{}; foreach ($x in $run.results) { $by[[string]$x.id] = $x }
        @{ by = $by; auth = $run.domains['auth'].facts; identity = $run.domains['identity'].facts }
    }
    $script:Holders = { param([string] $Dir) InModuleScope TenantKeep.Posture -Parameters @{ D = $Dir } { param($D) Clear-PostureEvidenceCache -Confirm:$false; Get-PostureRoleHolder -Folder $D } }
}

AfterAll {
    Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = $null }
}

Describe 'Get-PostureRoleHolder' {
    It 'lists the people, how each holds each role, and nothing unread when every group was opened' {
        $h = & $script:Holders (& $script:Tenant 'helper')
        $h.available | Should -BeTrue
        $h.source | Should -Be 'holders'
        $h.people.get_Count() | Should -Be 6
        $h.upns.Contains('TINA.TIER0@contoso.example') | Should -BeTrue -Because 'names are matched whatever their case'
        $tina = $h.people['tina.tier0@contoso.example']
        $tina.roles[0].held | Should -Be 'Group'
        $tina.roles[0].groupName | Should -Be 'SG-Tier0-Admins'
        $h.people['erin.eligible@contoso.example'].roles[0].held | Should -Be 'Eligible'
        @($h.unread).Count | Should -Be 0
        InModuleScope TenantKeep.Posture -Parameters @{ H = $h } { param($H) Get-PostureRoleHolderGap -Holder $H | Should -BeNullOrEmpty }
    }

    It 'falls back to the people the assignments name on an older run, and says which groups it could not open' {
        $h = & $script:Holders (& $script:Tenant 'helper-old' -NoHolders)
        $h.source | Should -Be 'assignments'
        @($h.people.get_Keys()) | Should -Be @('breakglass01@contoso.example', 'breakglass02@contoso.example', 'alice.admin@contoso.example', 'erin.eligible@contoso.example')
        @($h.unread | ForEach-Object { "$($_.name)|$($_.missing)" }) | Should -Be @('SG-Tier0-Admins|members')
        InModuleScope TenantKeep.Posture -Parameters @{ H = $h } {
            param($H)
            Get-PostureRoleHolderGap -Holder $H | Should -Be '1 group(s) hold a role and this evidence is from before their members were read (SG-Tier0-Admins)'
            Get-PostureRoleHolderGap -Holder $H -Role 'Global Administrator' -Standing | Should -Match '1 group\(s\) hold Global Administrator'
            Get-PostureRoleHolderGap -Holder $H -Role 'Exchange Administrator' | Should -BeNullOrEmpty -Because 'the unopened group does not hold that role'
        }
    }

    It 'takes a row with a sign-in name and no principal type for a person, as older evidence wrote it' {
        $d = Join-Path $script:Root 'untyped'; New-Item -ItemType Directory -Path $d | Out-Null
        & $script:Write $d '04-role-assignments-active' @(@{ Role = 'Exchange Administrator'; PrincipalUpn = 'admin1@contoso.example' }, @{ Role = 'Global Administrator'; PrincipalName = 'Deleted principal'; PrincipalUpn = $null })
        $h = & $script:Holders $d
        @($h.people.get_Keys()) | Should -Be @('admin1@contoso.example')
    }

    It 'is not available without any role file' {
        $d = Join-Path $script:Root 'none'; New-Item -ItemType Directory -Path $d | Out-Null
        (& $script:Holders $d).available | Should -BeFalse
    }
}

Describe 'Administrators who hold a role as eligible only, or through a group' {
    BeforeAll { $script:T = & $script:Checks (& $script:Tenant 'whole') }

    It 'counts all six people as administrators' {
        $script:T.auth.admins | Should -Be 6 -Because 'two break-glass accounts, Alice, Erin (eligible only), Tina and Tom (through the group)'
    }

    It 'holds the eligible-only administrator and the one in the group to a phishing-resistant method (AU-008)' {
        $r = $script:T.by['AU-008']
        $r.status | Should -Be 'fail'
        @($r.affected | ForEach-Object { $_.name }) | Should -Be @('erin.eligible@contoso.example', 'tom.tier0@contoso.example')
        $r.reason | Should -BeNullOrEmpty -Because 'everyone was read'
    }

    It 'counts Global Administrators as people: the group''s two members, not the group as one (ID-001)' {
        $r = $script:T.by['ID-001']
        $r.observed['globalAdmins'] | Should -Be 4
        $r.status | Should -Be 'pass'
        @($r.affected | Where-Object { $_.name -eq 'Tina Tier' })[0].detail | Should -Be 'user tina.tier0@contoso.example (through the group SG-Tier0-Admins)'
    }

    It 'lists a permanent role held through a group among the permanent assignments (ID-002)' {
        @($script:T.by['ID-002'].affected | ForEach-Object { $_.name } | Sort-Object) | Should -Be @('Alice Admin: Exchange Administrator', 'Tina Tier: Global Administrator', 'Tom Tier: Global Administrator')
        @($script:T.by['ID-002'].affected | Where-Object { $_.name -like 'Tom*' })[0].detail | Should -Be 'permanent Global Administrator for tom.tier0@contoso.example through the group SG-Tier0-Admins'
    }

    It 'finds the licensed account among the people in the group (ID-004)' {
        @($script:T.by['ID-004'].affected | ForEach-Object { $_.name }) | Should -Be @('tina.tier0@contoso.example')
    }

    It 'shows them in the admins table with the group they hold the role through' {
        $rep = New-PostureReport -Evidence (Join-Path $script:Root 'whole') -OutputPath (Join-Path $script:Root 'whole-out') -Format Markdown -PassThru
        $tina = @($rep.Report.admins | Where-Object { $_.upn -eq 'tina.tier0@contoso.example' })[0]
        $tina.permanent | Should -Be @('Global Administrator (through SG-Tier0-Admins)')
        $tina.strongestMethod | Should -Be 'Windows Hello for Business'
        @($rep.Report.admins | Where-Object { $_.type -eq 'group' })[0].name | Should -Be 'SG-Tier0-Admins' -Because 'the group keeps its own row: what was assigned'
        $rep.Report.headline.permanentGlobalAdmins | Should -Be 4
    }
}

Describe 'A group that holds a role and was not opened' {
    Context 'evidence from before the members were read' {
        BeforeAll { $script:T = & $script:Checks (& $script:Tenant 'old' -NoHolders) }

        It 'still fails AU-008 on the administrator it saw, and says who it did not look at' {
            $r = $script:T.by['AU-008']
            $r.status | Should -Be 'fail'
            @($r.affected | ForEach-Object { $_.name }) | Should -Be @('erin.eligible@contoso.example')
            $r.reason | Should -Be 'Judged on the 4 administrators that were read; 1 group(s) hold a role and this evidence is from before their members were read (SG-Tier0-Admins).'
        }

        It 'has no count of Global Administrators: two were seen and the group''s people are unknown (ID-001)' {
            $r = $script:T.by['ID-001']
            $r.status | Should -Be 'notEvaluated' -Because 'two would pass, and the group could hold twenty more'
            $r.reason | Should -Match '^2 Global Administrator\(s\) among the role holders that were read, but 1 group\(s\) hold Global Administrator'
            $r.reason | Should -Match 'Resume-PostureRun -Collector Entra'
        }

        It 'has no answer where it saw nothing wrong (ID-003), and a finding with a note where it did (ID-002)' {
            $script:T.by['ID-003'].status | Should -Be 'notEvaluated'
            $script:T.by['ID-003'].reason | Should -Match '^No administrator synced from on-premises AD among the role holders that were read, but 1 group'
            $script:T.by['ID-002'].status | Should -Be 'fail'
            $script:T.by['ID-002'].reason | Should -Match '^Judged on the role holders that were read; 1 group'
        }

        It 'keeps the floor out of the headline' {
            $rep = New-PostureReport -Evidence (Join-Path $script:Root 'old') -OutputPath (Join-Path $script:Root 'old-out') -Format Markdown -PassThru
            $rep.Report.headline.permanentGlobalAdmins | Should -BeNullOrEmpty -Because 'the check itself could not stand behind the number'
        }
    }

    It 'has no answer for AU-008 when everyone it saw is fine and a group is unopened' {
        $t = & $script:Checks (& $script:Tenant 'old-fine' -NoHolders -Methods @{ 'erin.eligible@contoso.example' = 'fido2' })
        $t.by['AU-008'].status | Should -Be 'notEvaluated' -Because 'a pass would speak for people nobody looked at'
        $t.by['AU-008'].reason | Should -Match '^No administrator without a phishing-resistant method among the 4 that were read, but 1 group'
    }

    It 'fails ID-001 on a floor that is already over the limit' {
        $t = & $script:Checks (& $script:Tenant 'old-many' -NoHolders -ExtraGlobalAdmins 5)
        $t.by['ID-001'].status | Should -Be 'fail'
        $t.by['ID-001'].reason | Should -Match '^At least 7: 1 group\(s\) hold Global Administrator'
    }

    It 'says so in the collector''s own words when it could not open the group' {
        $t = & $script:Checks (& $script:Tenant 'denied' -GroupsNotRead 'SG-Tier0-Admins')
        $t.by['AU-008'].reason | Should -Be 'Judged on the 4 administrators that were read; the members of 1 group(s) that hold a role were not read (SG-Tier0-Admins).'
        $t.by['ID-001'].status | Should -Be 'notEvaluated'
    }

    It 'treats who can join a group as unknown for who is an administrator, not for who holds the role today' {
        $t = & $script:Checks (& $script:Tenant 'pim-denied' -EligibleNotRead 'SG-Tier0-Admins')
        $t.by['AU-008'].reason | Should -Match 'who can join 1 group\(s\) that hold a role through PIM for Groups was not read \(SG-Tier0-Admins\)'
        $t.by['ID-001'].status | Should -Be 'pass' -Because 'the members were read: the people who hold the role today are known'
        $t.by['ID-001'].reason | Should -BeNullOrEmpty
    }
}
