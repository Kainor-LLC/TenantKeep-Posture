# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-governance-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $script:Write = { param([string] $Dir, [string] $Name, $Data) New-Item -ItemType Directory -Path $Dir -Force | Out-Null; ConvertTo-Json -InputObject $Data -Depth 10 | Set-Content -LiteralPath (Join-Path $Dir "$Name.json") }
    # A tenant with $Assignable role-assignable groups and the PIM for Groups summary the collector wrote.
    $script:Pim = {
        param([string] $Name, [int] $Assignable, [hashtable] $Summary)
        $d = Join-Path $script:Root $Name
        & $script:Write $d '06-users-summary' @{ Members = 40; Guests = 2; EnabledInactiveMembers = 0 }
        & $script:Write $d '07-groups' @(@(1..$Assignable | ForEach-Object { @{ Id = "ra$_"; DisplayName = "Admins $_"; IsAssignableToRole = $true } }) + @(@{ Id = 'g-plain'; DisplayName = 'Staff'; IsAssignableToRole = $false }))
        & $script:Write $d 'gov-04-pim-groups-summary' $Summary
        $pf = Join-Path $d 'profile.json'
        @{ version = 1; licenses = @('P2') } | ConvertTo-Json | Set-Content -LiteralPath $pf
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache -Confirm:$false }
        @((Invoke-PostureChecks -Evidence $d -Domain governance -ProfilePath $pf -PassThru).results | Where-Object { $_.id -eq 'GV-006' })[0]
    }
}

AfterAll {
    Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = $null }
}

Describe 'PIM for Groups (GV-006) when some role-assignable groups were not read' {
    It 'fails when every group was read and none is under PIM' {
        (& $script:Pim 'all-read' 3 @{ EligibleAssignments = 0; Groups = 0; RoleAssignableGroups = 3; GroupsRead = 3 }).status | Should -Be 'fail'
    }

    It 'has no answer when none is under PIM among those read and others were not read' {
        $r = & $script:Pim 'short' 5 @{ EligibleAssignments = 0; Groups = 0; RoleAssignableGroups = 5; GroupsRead = 2 }
        $r.status | Should -Be 'notEvaluated' -Because 'the three groups nobody asked about are not groups without PIM'
        $r.reason | Should -Match 'among the 2 role-assignable groups that were read; the other 3 were not read'
    }

    It 'passes on one group under PIM, however many were read' {
        (& $script:Pim 'short-found' 5 @{ EligibleAssignments = 4; Groups = 1; RoleAssignableGroups = 5; GroupsRead = 2 }).status | Should -Be 'pass'
    }

    It 'takes evidence from before the collector read them all as the first 100' {
        (& $script:Pim 'old-small' 40 @{ EligibleAssignments = 0; Groups = 0 }).status | Should -Be 'fail' -Because 'up to 100 groups the old collector read every one'
        $r = & $script:Pim 'old-large' 130 @{ EligibleAssignments = 0; Groups = 0 }
        $r.status | Should -Be 'notEvaluated'
        $r.reason | Should -Match 'the other 30 were not read'
    }
}
