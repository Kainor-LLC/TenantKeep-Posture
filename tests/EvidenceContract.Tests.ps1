# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# Missing data must never read as pass or fail. This test takes the made-up demo run, removes one evidence file at a
# time, evaluates the real catalog with the real providers, and holds every result to the evidence contract:
#   1. a check is not judged without a file its evidence list requires;
#   2. a result that is still pass or fail did not change because of a file the check does not name;
#   3. no provider stops on one missing file (that would take its whole domain down with an error for a reason);
#   4. no reason carries the path of the run folder;
#   5. no result turns from pass to fail or from fail to pass: a missing file can take an answer away, never change it.
# It keeps the catalog's evidence lists true: a provider that starts reading a file a check does not name fails here.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'demo tenant, made-up data' } }
    $made = & (Join-Path $PSScriptRoot '..' 'samples' 'demo' 'New-PostureDemoRun.ps1') -Path (Join-Path $TestDrive 'fernquill')
    $ev = $made.Evidence
    $hold = Join-Path $TestDrive 'hold'
    New-Item -ItemType Directory -Path $hold | Out-Null

    $script:Findings = InModuleScope TenantKeep.Posture -Parameters @{ Ev = $ev; Hold = $hold; ProfilePath = (Join-Path $made.Client 'profile.json') } {
        $catalog = Import-PostureCheckCatalog
        $baseline = Import-PostureBaseline -Baseline 'standard'
        $orgProfile = Import-PostureProfile -Path $ProfilePath
        $entitlement = Get-PostureEntitlement -Evidence $Ev
        $evaluate = { Invoke-PostureCheckEvaluation -Catalog $catalog -Baseline $baseline -OrgProfile $orgProfile -Exception @() -Evidence $Ev -Entitlement $entitlement }
        $name = { param($x) ([string]$x) -replace '\.(json|csv)$', '' }
        $observed = { param($r) if ($r.observed) { (@($r.observed.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ') } else { '' } }

        # What each check says it needs: every name, the optional ones, the any-of groups.
        $contract = @{}
        foreach ($c in $catalog.checks) {
            $groups = [System.Collections.Generic.List[object]]::new()
            if ($c.Contains('evidenceAnyOf') -and $null -ne $c['evidenceAnyOf']) { foreach ($g in [object[]]$c['evidenceAnyOf']) { $groups.Add(@(@($g) | ForEach-Object { & $name $_ })) } }
            $contract[[string]$c['id']] = @{
                names    = @($c['evidence'] | ForEach-Object { & $name $_ })
                optional = @($(if ($c.Contains('evidenceOptional')) { $c['evidenceOptional'] }) | ForEach-Object { & $name $_ })
                groups   = $groups
            }
        }

        $base = @{}
        foreach ($r in (& $evaluate).results) { $base[[string]$r.id] = @{ status = [string]$r.status; observed = (& $observed $r) } }
        $found = [System.Collections.Generic.List[object]]::new()
        $files = @(Get-ChildItem -LiteralPath $Ev -File | Where-Object { $_.Extension -in '.json', '.csv' -and $_.BaseName -ne 'collection' } | ForEach-Object { $_.BaseName } | Sort-Object -Unique)
        foreach ($file in $files) {
            $moved = @(Get-ChildItem -LiteralPath $Ev -File | Where-Object { $_.BaseName -eq $file -and $_.Extension -in '.json', '.csv' })
            foreach ($m in $moved) { Move-Item -LiteralPath $m.FullName -Destination $Hold }
            try { $run = & $evaluate }
            finally { foreach ($m in $moved) { Move-Item -LiteralPath (Join-Path $Hold $m.Name) -Destination $Ev } }
            foreach ($r in $run.results) {
                $id = [string]$r.id; $k = $contract[$id]; $judged = [string]$r.status -in 'pass', 'fail'
                $grouped = @(foreach ($g in $k.groups) { foreach ($n in $g) { $n } })
                $required = $file -in $k.names -and $file -notin $k.optional -and $file -notin $grouped
                # The last member of an any-of group left in the folder is required too.
                foreach ($g in $k.groups) { if ($file -in $g -and @($g | Where-Object { $_ -ne $file -and ((Test-Path -LiteralPath (Join-Path $Ev "$_.json")) -or (Test-Path -LiteralPath (Join-Path $Ev "$_.csv"))) }).Count -eq 0) { $required = $true } }
                if ($required -and $judged) { $found.Add([pscustomobject]@{ Rule = 'judged without a file it needs'; File = $file; Check = $id; Detail = "$($r.status), $(& $observed $r)" }) }
                if ($judged -and $file -notin $k.names -and ([string]$r.status -ne $base[$id].status -or (& $observed $r) -ne $base[$id].observed)) { $found.Add([pscustomobject]@{ Rule = 'changed by a file it does not name'; File = $file; Check = $id; Detail = "$($base[$id].status) [$($base[$id].observed)] to $($r.status) [$(& $observed $r)]" }) }
                if ($judged -and $base[$id].status -in 'pass', 'fail' -and [string]$r.status -ne $base[$id].status) { $found.Add([pscustomobject]@{ Rule = 'answer changed'; File = $file; Check = $id; Detail = "$($base[$id].status) to $($r.status), $(& $observed $r)" }) }
                if ([string]$r.reason -match 'Fact provider for') { $found.Add([pscustomobject]@{ Rule = 'provider stopped'; File = $file; Check = $id; Detail = [string]$r.reason }) }
                if ([string]$r.reason -like "*$Ev*") { $found.Add([pscustomobject]@{ Rule = 'reason carries the folder path'; File = $file; Check = $id; Detail = [string]$r.reason }) }
            }
        }
        , $found.ToArray()
    }
    $script:Say = { param([string] $Rule) @($script:Findings | Where-Object { $_.Rule -eq $Rule } | ForEach-Object { "$($_.Check) without $($_.File): $($_.Detail)" }) }
}

AfterAll { InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = $null } }

Describe 'The evidence contract, one missing file at a time' {
    It 'judges no check without a file its evidence list requires' {
        & $script:Say 'judged without a file it needs' | Should -BeNullOrEmpty
    }

    It 'changes no pass or fail because of a file the check does not name' {
        & $script:Say 'changed by a file it does not name' | Should -BeNullOrEmpty
    }

    It 'turns no pass into a fail and no fail into a pass: a missing file takes an answer away, it never changes it' {
        & $script:Say 'answer changed' | Should -BeNullOrEmpty
    }

    It 'stops no provider: one missing file never takes a whole domain down' {
        # One line per file is enough to say which provider and why.
        @($script:Findings | Where-Object { $_.Rule -eq 'provider stopped' } | Group-Object File | ForEach-Object { "without $($_.Name): $($_.Group[0].Detail) ($($_.Count) checks)" }) | Should -BeNullOrEmpty
    }

    It 'never writes the run folder''s path into a reason' {
        @($script:Findings | Where-Object { $_.Rule -eq 'reason carries the folder path' } | Group-Object File | ForEach-Object { "without $($_.Name): $($_.Group[0].Check) and $($_.Count - 1) more" }) | Should -BeNullOrEmpty
    }
}
