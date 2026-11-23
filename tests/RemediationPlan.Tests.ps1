# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    # A catalog of made-up checks in a temporary folder, with the projects file a test writes.
    $script:NewCatalog = {
        param([string] $Dir, [string[]] $Checks, [object[]] $Projects)
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        @{ description = 'made up'; projects = @($Projects) } | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $Dir 'projects.json')
        @{ path = $Dir; checks = @($Checks | ForEach-Object { [ordered]@{ id = $_; title = "Title of $_"; effort = 'M'; category = 'fix' } }) }
    }
    $script:P = { param([string] $Id, [string] $Name, [string[]] $Checks, [object[]] $Needs = @(), [object[]] $After = @()) [ordered]@{ id = $Id; name = $Name; what = "What $Name is."; checks = @($Checks); needs = @($Needs); after = @($After) } }
    $script:E = { param([string] $Project, [string] $Why = 'A reason.') [ordered]@{ project = $Project; why = $Why } }
}

Describe 'Projects: the checks grouped into pieces of work' {
    It 'puts every shipped check in exactly one project, each dependency with its reason' {
        InModuleScope TenantKeep.Posture {
            $catalog = Import-PostureCheckCatalog
            $projects = @(Import-PostureProject -Catalog $catalog)
            $projects.Count | Should -BeGreaterThan 30
            @($projects | ForEach-Object { $_.checks }).Count | Should -Be @($catalog.checks).Count -Because 'the import refuses a check in two projects or in none'
            foreach ($p in $projects) { foreach ($e in @($p.needs) + @($p.after)) { ([string]$e.why).Length | Should -BeGreaterThan 20 -Because "$($p.id) says why it waits on $($e.project)" } }
            Get-Content -Raw (Join-Path $catalog.path 'projects.json') | Should -Not -Match ([char]0x2014) -Because 'no em dashes in text a customer reads'
        }
    }

    It 'refuses <Case>' -ForEach @(
        @{ Case = 'a check in no project'; Checks = 'AA-001', 'AA-002'; Message = '*no project holds AA-002*'; Build = { @((& $P 'PJ-001' 'One' 'AA-001')) } }
        @{ Case = 'a check in two projects'; Checks = 'AA-001', 'AA-002'; Message = '*AA-001 is in PJ-001 and in PJ-002*'; Build = { @((& $P 'PJ-001' 'One' 'AA-001'), (& $P 'PJ-002' 'Two' 'AA-001', 'AA-002')) } }
        @{ Case = 'a check the catalog lacks'; Checks = 'AA-001'; Message = "*names 'ZZ-999'*"; Build = { @((& $P 'PJ-001' 'One' 'AA-001', 'ZZ-999')) } }
        @{ Case = 'an id that is not a project id'; Checks = 'AA-001'; Message = "*'P1' is not a project id*"; Build = { @((& $P 'P1' 'One' 'AA-001')) } }
        @{ Case = 'a project that waits on itself'; Checks = 'AA-001'; Message = '*PJ-001 needs itself*'; Build = { @((& $P 'PJ-001' 'One' 'AA-001' @((& $E 'PJ-001')))) } }
        @{ Case = 'a dependency without a reason'; Checks = 'AA-001', 'AA-002'; Message = '*PJ-002 needs PJ-001 without saying why*'; Build = { @((& $P 'PJ-001' 'One' 'AA-001'), (& $P 'PJ-002' 'Two' 'AA-002' @((& $E 'PJ-001' ' ')))) } }
        @{ Case = 'a dependency on a project that is not there'; Checks = 'AA-001'; Message = "*PJ-001 after 'PJ-009'*"; Build = { @((& $P 'PJ-001' 'One' 'AA-001' @() @((& $E 'PJ-009')))) } }
        @{ Case = 'the same project under needs and after'; Checks = 'AA-001', 'AA-002'; Message = '*PJ-002 names PJ-001 twice*'; Build = { @((& $P 'PJ-001' 'One' 'AA-001'), (& $P 'PJ-002' 'Two' 'AA-002' @((& $E 'PJ-001')) @((& $E 'PJ-001')))) } }
        @{ Case = 'a loop'; Checks = 'AA-001', 'AA-002'; Message = '*a loop*'; Build = { @((& $P 'PJ-001' 'One' 'AA-001' @((& $E 'PJ-002'))), (& $P 'PJ-002' 'Two' 'AA-002' @() @((& $E 'PJ-001')))) } }
    ) {
        $P = $script:P; $E = $script:E
        $catalog = & $script:NewCatalog (Join-Path $TestDrive ([guid]::NewGuid().ToString('n'))) $Checks (& $Build)
        InModuleScope TenantKeep.Posture -Parameters @{ Catalog = $catalog; Message = $Message } { { Import-PostureProject -Catalog $Catalog } | Should -Throw $Message }
    }

    It 'gives an empty list for a catalog folder without the file' {
        InModuleScope TenantKeep.Posture -Parameters @{ Dir = $TestDrive } {
            @(Import-PostureProject -Catalog @{ path = (Join-Path $Dir 'nothing-here'); checks = @() }).Count | Should -Be 0
            Get-PosturePlan -Catalog @{ path = (Join-Path $Dir 'nothing-here'); checks = @() } -Result @() | Should -BeNullOrEmpty
        }
    }
}

Describe 'The remediation plan for one run' {
    BeforeAll {
        $P = $script:P; $E = $script:E
        # Base (done) <- Mfa (needed) <- Strong (needed) <- Final (needed, also better after Mail)
        # Mail (needed, nothing waits on it but Final), Side (needed, alone), Dark (not judged) <- Wait (needed), Off (no answers) <- Free (needed)
        $projects = @(
            (& $P 'PJ-001' 'Base' 'AA-001'), (& $P 'PJ-002' 'Mfa' 'AA-002', 'AA-003' @((& $E 'PJ-001' 'Lockout otherwise.'))), (& $P 'PJ-003' 'Strong' 'AA-004' @((& $E 'PJ-002'))),
            (& $P 'PJ-004' 'Mail' 'AA-005'), (& $P 'PJ-005' 'Final' 'AA-006' @((& $E 'PJ-003'), (& $E 'PJ-001')) @((& $E 'PJ-004'))), (& $P 'PJ-006' 'Side' 'AA-007'),
            (& $P 'PJ-007' 'Dark' 'AA-008'), (& $P 'PJ-008' 'Wait' 'AA-009' @((& $E 'PJ-007'))), (& $P 'PJ-009' 'Off' 'AA-010'), (& $P 'PJ-010' 'Free' 'AA-011' @((& $E 'PJ-009'))),
            (& $P 'PJ-011' 'Tidy' 'AA-012')
        )
        $script:Catalog = & $script:NewCatalog (Join-Path $TestDrive 'plan') @(1..12 | ForEach-Object { 'AA-{0:d3}' -f $_ }) $projects
        $script:Catalog.checks[11].category = 'improve'
        $r = { param($id, $status, $severity = 'High') [ordered]@{ id = $id; title = "Title of $id"; status = $status; severity = $severity } }
        $script:Results = @(
            (& $r 'AA-001' 'pass'), (& $r 'AA-002' 'fail' 'Critical'), (& $r 'AA-003' 'fail' 'Medium'), (& $r 'AA-004' 'fail'), (& $r 'AA-005' 'fail' 'Medium'), (& $r 'AA-006' 'fail'),
            (& $r 'AA-007' 'fail' 'Low'), (& $r 'AA-008' 'notEvaluated'), (& $r 'AA-009' 'fail'), (& $r 'AA-011' 'fail' 'Medium'), (& $r 'AA-012' 'fail' 'Low')
        )
    }

    It 'judges each project, orders the needed ones and says what could not be judged' {
        InModuleScope TenantKeep.Posture -Parameters @{ Catalog = $script:Catalog; Results = $script:Results } {
            $plan = Get-PosturePlan -Catalog $Catalog -Result $Results
            $plan.counts.needed | Should -Be 8
            $plan.counts.done | Should -Be 1
            $plan.counts.unknown | Should -Be 1
            $plan.counts.notApplicable | Should -Be 1
            @($plan.columns.key) | Should -Be @('inPlace', 'start', 'then', 'after')
            $col = @{}; foreach ($c in $plan.columns) { $col[$c.key] = @($c.projects.name) }
            $col.inPlace | Should -Be @('Base')
            $col.start | Should -Be @('Mfa', 'Wait', 'Free', 'Mail', 'Side', 'Tidy') -Because 'highest risk first, then the points to earn, then the name'
            $col.then | Should -Be @('Strong')
            $col.after | Should -Be @('Final') -Because 'one column after the last needed project it waits on, a recommended order included'
            $mfa = @($plan.columns[1].projects)[0]
            $mfa.risk | Should -Be 'Critical'
            $mfa.toFix | Should -Be 2
            @($mfa.checks.id) | Should -Be @('AA-002', 'AA-003')
            @($mfa.waitsOn)[0].state | Should -Be 'done'
            $wait = @($plan.columns[1].projects | Where-Object name -eq 'Wait')[0]
            @($wait.checkFirst) | Should -Be @('Dark') -Because 'a prerequisite that could not be judged does not hold a project back, and is not read as done'
            @(@($plan.columns[1].projects | Where-Object name -eq 'Free')[0].waitsOn).Count | Should -Be 0 -Because 'a prerequisite with no answers in this run is left out'
            @($plan.columns[1].projects | Where-Object name -eq 'Tidy')[0].improvementsOnly | Should -BeTrue
            @($plan.notJudged.name) | Should -Be @('Dark')
            @($plan.edges | ForEach-Object { "$($_.from)>$($_.to):$($_.kind)" }) | Should -Be @('PJ-001>PJ-002:needs', 'PJ-002>PJ-003:needs', 'PJ-003>PJ-005:needs') -Because 'arrows join neighbouring columns only'
            @($plan.whenever).Count | Should -Be 0
        }
    }

    It 'keeps what unlocks other work in the first column and lists the rest as ready' {
        InModuleScope TenantKeep.Posture -Parameters @{ Catalog = $script:Catalog; Results = $script:Results } {
            $plan = Get-PosturePlan -Catalog $Catalog -Result $Results -StartLimit 2
            @(@($plan.columns | Where-Object key -eq 'start')[0].projects.name) | Should -Be @('Mfa', 'Mail') -Because 'Mfa and Mail have projects waiting on them; the limit only cuts the ones nothing waits on'
            @($plan.whenever.name) | Should -Be @('Wait', 'Free', 'Side', 'Tidy')
        }
    }

    It 'draws the chart, the same plan in words, and nothing when there is nothing to plan' {
        InModuleScope TenantKeep.Posture -Parameters @{ Catalog = $script:Catalog; Results = $script:Results } {
            $html = ConvertTo-PosturePlanHtml -Plan (Get-PosturePlan -Catalog $Catalog -Result $Results)
            foreach ($t in 'Already in place', 'Start now', 'These 6 can run side by side', 'Then', 'After that') { $html | Should -Match ([regex]::Escape($t)) }
            [regex]::Matches($html, '<path class="plan-edge needs"').Count | Should -Be 3
            $html | Should -Match '<a class="plan-node start r-critical" href="#plan-PJ-002">'
            $html | Should -Match '<g class="plan-node done">' -Because 'a finished project is not a link: it has nothing to fix'
            $html | Should -Match 'class="plan-node start r-high flag"' -Because 'a project told to check something first is marked'
            $html | Should -Match '\+2 earlier' -Because 'Final also waits on Base and Mail, further left than an arrow reaches'
            $html | Should -Match '<li id="plan-PJ-005" class="plan-item r-high">'
            $html | Should -Match 'Needs <strong>Strong</strong> \(in this plan\)\. A reason\.'
            $html | Should -Match 'Better after <strong>Mail</strong>'
            $html | Should -Match 'Needs <strong>Dark</strong> \(could not be judged in this run, so check it first\)'
            $html | Should -Match 'data-check="AA-006"'
            $html | Should -Match '8 projects have something to fix and 1 has nothing to fix\. Not judged in this run: Dark\.'
            $html | Should -Match 'data-plan-risk'
            $allGood = @($Results | ForEach-Object { $x = [ordered]@{}; foreach ($k in $_.Keys) { $x[$k] = $_[$k] }; if ($x.status -eq 'fail') { $x.status = 'pass' }; $x })
            ConvertTo-PosturePlanHtml -Plan (Get-PosturePlan -Catalog $Catalog -Result $allGood) | Should -Be ''
            ConvertTo-PosturePlanHtml -Plan $null | Should -Be ''
        }
    }
}
