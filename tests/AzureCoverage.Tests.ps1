# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# The per-subscription Azure reads (Defender plans, security contacts, activity log export, classic administrators,
# budgets, spend) cover some of the subscriptions on a large tenant. A subscription that was never read has no
# contact, no export and no plan in the files; that is not a finding. These tests hold the checks to it: judged on
# what was read, a gap that was seen is a finding with a note, and no gap among those read is no answer.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-azcov-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $script:Write = { param([string] $Dir, [string] $Name, $Data) ConvertTo-Json -InputObject $Data -Depth 10 | Set-Content -LiteralPath (Join-Path $Dir "$Name.json") }
    $script:Id = { param([int] $n) '{0:x8}-0000-4000-8000-000000000000' -f $n }

    # A tenant of $Total enabled subscriptions of which the first $Read were read in detail, every one of those in
    # order: all Defender plans on, a security contact, an activity log export, a budget, no classic administrator.
    # -Flag $false writes the subscriptions as evidence from before the collector recorded DetailRead.
    $script:Tenant = {
        param([string] $Name, [int] $Total, [int] $Read, [bool] $Flag = $true, [scriptblock] $Change)
        $dir = Join-Path $script:Root $Name
        New-Item -ItemType Directory -Path $dir | Out-Null
        $subs = @(foreach ($n in 1..$Total) {
                $row = [ordered]@{ SubscriptionId = (& $script:Id $n); Name = "sub-$n"; State = 'Enabled'; ManagementGroupChain = 'Tenant Root Group / Landing zones'; ManagementGroupNames = @('root', 'mg-lz'); AtTenantRoot = $false }
                if ($Flag) { $row.DetailRead = ($n -le $Read) }
                $row
            })
        $covered = @($subs | Select-Object -First $Read)
        $files = [ordered]@{
            'az-01-subscriptions'          = $subs
            'az-02-defender-pricings'      = @($covered | ForEach-Object { $s = $_.SubscriptionId; 'VirtualMachines', 'StorageAccounts', 'KeyVaults', 'Arm', 'CloudPosture' | ForEach-Object { [ordered]@{ SubscriptionId = $s; Plan = $_; Tier = 'Standard'; SubPlan = $null } } })
            'az-02-security-contacts'      = @($covered | ForEach-Object { [ordered]@{ SubscriptionId = $_.SubscriptionId; Name = 'default'; Emails = 'soc@contoso.example'; AlertState = 'On'; MinimalSeverity = 'High'; NotifyRoles = @('Owner'); IsEnabled = $true } })
            'az-04-activity-log-exports'   = @($covered | ForEach-Object { [ordered]@{ SubscriptionId = $_.SubscriptionId; Name = 'to-workspace'; WorkspaceId = '/subscriptions/x/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law'; EventHub = $null; StorageAccountId = $null; Categories = 8 } })
            'az-05-classic-administrators' = @()
            'az-06-resources-by-type'      = @($subs | ForEach-Object { $s = $_.SubscriptionId; 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts' | ForEach-Object { [ordered]@{ SubscriptionId = $s; Type = $_; Count = 3 } } })
            'az-10-m365-payg'              = @()
            'az-13-budgets'                = @($covered | ForEach-Object { [ordered]@{ SubscriptionId = $_.SubscriptionId; Budgets = 1 } })
        }
        if ($Change) { & $Change $files }
        foreach ($k in $files.get_Keys()) { & $script:Write $dir $k @($files[$k]) }
        $pf = Join-Path $dir 'profile.json'
        @{ version = 1; azure = 'workloads' } | ConvertTo-Json | Set-Content -LiteralPath $pf
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache -Confirm:$false }
        $run = Invoke-PostureChecks -Evidence $dir -Domain azure -ProfilePath $pf -PassThru
        $by = @{}; foreach ($x in $run.results) { $by[[string]$x.id] = $x }
        @{ by = $by; facts = $run.domains['azure'].facts }
    }
    $script:PerSubscription = 'AZ-003', 'AZ-005', 'AZ-006', 'AZ-017', 'AZ-023', 'AZ-025'
}

AfterAll {
    Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = $null }
}

Describe 'Azure checks on a tenant with more subscriptions than were read in detail' {
    Context '260 subscriptions, 200 read, all of those in order' {
        BeforeAll { $script:T = & $script:Tenant 'healthy' 260 200 }

        It 'says how many subscriptions were read' {
            $script:T.facts.subscriptions | Should -Be 260
            $script:T.facts.subscriptionsRead | Should -Be 200
        }

        It 'flags none of the 60 that were not read' {
            $script:T.facts.subscriptionsWithoutSecurityContact | Should -Be 0 -Because 'a subscription nobody read is not a subscription without a contact'
            $script:T.facts.subscriptionsWithoutActivityLogExport | Should -Be 0
            $script:T.facts.defenderPlanGaps | Should -Be 0
        }

        It 'has no answer for <_>: nothing wrong among those read, and the rest unknown' -ForEach @('AZ-003', 'AZ-005', 'AZ-006', 'AZ-017', 'AZ-023', 'AZ-025') {
            $r = $script:T.by[$_]
            $r.status | Should -Be 'notEvaluated' -Because 'a pass would speak for 60 subscriptions that were never read'
            $r.reason | Should -Match 'among the 200 subscriptions that were read; the other 60 were not read'
        }

        It 'passes the check that one subscription can answer for the tenant' {
            $script:T.by['AZ-004'].status | Should -Be 'pass' -Because 'Defender CSPM is on at least one subscription, whatever the unread ones have'
        }
    }

    Context '260 subscriptions, 200 read, gaps among those read' {
        BeforeAll {
            $script:T = & $script:Tenant 'gaps' 260 200 $true {
                param($files)
                # Two read subscriptions lose their security contact, one its export, one its budget.
                $drop = (& $script:Id 3), (& $script:Id 4)
                $files['az-02-security-contacts'] = @($files['az-02-security-contacts'] | Where-Object { $_.SubscriptionId -notin $drop })
                $files['az-04-activity-log-exports'] = @($files['az-04-activity-log-exports'] | ForEach-Object { if ($_.SubscriptionId -eq (& $script:Id 5)) { $_.WorkspaceId = $null; $_.Categories = 0 }; $_ })
                $files['az-13-budgets'] = @($files['az-13-budgets'] | ForEach-Object { if ($_.SubscriptionId -eq (& $script:Id 6)) { $_.Budgets = 0 }; $_ })
            }
        }

        It 'fails <Id> on the <Count> it saw and says how much it looked at' -ForEach @(
            @{ Id = 'AZ-005'; Count = 2 }
            @{ Id = 'AZ-006'; Count = 1 }
            @{ Id = 'AZ-025'; Count = 1 }
        ) {
            $r = $script:T.by[$Id]
            $r.status | Should -Be 'fail'
            $r.affectedCount | Should -Be $Count -Because 'only subscriptions that were read and lack it are listed'
            $r.reason | Should -Be 'Judged on 200 of 260 subscriptions; the other 60 were not read.'
        }

        It 'lists the subscriptions by name, none of them an unread one' {
            @($script:T.by['AZ-005'].affected | ForEach-Object { $_.name }) | Should -Be @('sub-3', 'sub-4')
        }

        It 'still has no answer where nothing was wrong among those read' {
            $script:T.by['AZ-003'].status | Should -Be 'notEvaluated'
            $script:T.by['AZ-017'].status | Should -Be 'notEvaluated'
        }
    }

    Context 'every subscription read' {
        BeforeAll { $script:T = & $script:Tenant 'whole' 40 40 }

        It 'passes <_> with no note' -ForEach @('AZ-003', 'AZ-004', 'AZ-005', 'AZ-006', 'AZ-017', 'AZ-023', 'AZ-025') {
            $script:T.by[$_].status | Should -Be 'pass' -Because $script:T.by[$_].reason
            $script:T.by[$_].reason | Should -BeNullOrEmpty
        }
    }

    Context 'evidence from before the collector recorded which subscriptions it read' {
        It 'takes a tenant of up to 200 subscriptions as read whole' {
            $t = & $script:Tenant 'old-small' 40 40 $false
            $t.facts.subscriptionsRead | Should -Be 40
            $t.by['AZ-005'].status | Should -Be 'pass'
        }

        It 'reads which ones from the budgets file above 200' {
            $t = & $script:Tenant 'old-large' 260 200 $false
            $t.facts.subscriptionsRead | Should -Be 200 -Because 'az-13-budgets has one row for every subscription read'
            $t.facts.subscriptionsWithoutSecurityContact | Should -Be 0
            $t.by['AZ-005'].status | Should -Be 'notEvaluated'
        }

        It 'has no answer, and says to collect again, when nothing says which were read' {
            $t = & $script:Tenant 'old-unknown' 260 200 $false { param($files) $files.Remove('az-13-budgets') }
            foreach ($id in 'AZ-003', 'AZ-005', 'AZ-006', 'AZ-017') {
                $t.by[$id].status | Should -Be 'notEvaluated'
                $t.by[$id].reason | Should -Match 'does not say which of the 260 subscriptions were read in detail'
            }
            $t.by['AZ-025'].status | Should -Be 'notEvaluated' -Because 'the budgets file itself is not there'
        }
    }
}
