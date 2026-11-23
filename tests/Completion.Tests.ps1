# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# "To complete this assessment": what a run still lacks, who can add it and how. The rows are data in
# checks/catalog.json; these tests hold the data to the catalog and the commands to the module.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-complete-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    $script:Catalog = InModuleScope TenantKeep.Posture { Import-PostureCheckCatalog }
    $script:Entries = @($script:Catalog.completion)
    $script:EntryFor = {
        param([string] $Name)
        foreach ($e in $script:Entries) { foreach ($p in @($e['evidence'])) { if (($p.EndsWith('-') -and $Name.StartsWith($p)) -or $Name -eq $p) { return [string]$e['id'] } } }
    }
    # A run in the folders layout with the collection fixture as its evidence.
    . (Join-Path $PSScriptRoot 'Fixtures' 'CollectionFixture.ps1')
    $script:NewRun = {
        param([string] $Name, [hashtable] $Plan = @{}, [string[]] $Collectors = @('ConditionalAccess', 'Entra'))
        $run = Join-Path $script:Root $Name
        foreach ($d in 'errors', 'logs') { New-Item -ItemType Directory -Path (Join-Path $run $d) -Force | Out-Null }
        $null = Initialize-CollectionFixture -Root (Join-Path $run 'evidence')
        $client = Join-Path $script:Root "client of $Name"; New-Item -ItemType Directory -Path $client -Force | Out-Null
        $doc = @{ tenantId = '33333333-3333-3333-3333-333333333333'; client = $client; planned = @('Entra'); skipped = @{} }
        foreach ($k in @($Plan.get_Keys())) { $doc[$k] = $Plan[$k] }
        $doc | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $run 'logs' 'run.json')
        @{ tenantId = '33333333-3333-3333-3333-333333333333'; collectors = $Collectors; authType = 'Delegated'; scopes = @('Policy.Read.All', 'Directory.Read.All'); timestampUtc = '2026-11-21T10:00:00Z' } | ConvertTo-Json | Set-Content (Join-Path $run 'evidence' 'collection.json')
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache -Confirm:$false }
        $run
    }
}

AfterAll {
    Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = $null }
}

Describe 'The completion block of the catalog' {
    It 'covers every evidence file a check names, apart from what no command collects' {
        # The profile and the two attestation files are answers the admin gives, not evidence a collector writes.
        $answers = 'profile', 'portal-evidence', 'admin-center-evidence'
        $names = @($script:Catalog.checks | ForEach-Object { @($_['evidence']) } | ForEach-Object { ([string]$_) -replace '\.(json|csv)$', '' } | Sort-Object -Unique)
        $names.Count | Should -BeGreaterThan 100
        $uncovered = @($names | Where-Object { $_ -notin $answers -and -not (& $script:EntryFor $_) })
        $uncovered | Should -BeNullOrEmpty -Because 'a check whose evidence no row explains waits with no way said to finish it'
    }

    It 'sends the files of the Windows collectors to the rows that say how to run them' {
        & $script:EntryFor 'ad-01-forest-domain' | Should -Be 'active-directory'
        & $script:EntryFor 'spo-sites' | Should -Be 'sharepoint-admin'
        & $script:EntryFor 'spo-tenant-settings' | Should -Be 'sharepoint-admin'
        & $script:EntryFor 'spo-tenant-settings-graph' | Should -Be 'entra' -Because 'the Graph read of the settings comes with the Entra collector'
        & $script:EntryFor 'spo-dag-site-permissions' | Should -Be 'sharing-report'
        & $script:EntryFor '06-signins-summary' | Should -Be 'signins' -Because 'the sign-in log is its own collector, not the user list''s'
        & $script:EntryFor '06-users' | Should -Be 'entra'
    }

    It 'names only commands the module has, and collectors it can collect' {
        $public = @((Get-Module TenantKeep.Posture).ExportedFunctions.Keys)
        $collectors = (Get-Command Invoke-PostureCollection).Parameters['Collector'].Attributes.Where({ $_ -is [System.Management.Automation.ValidateSetAttribute] })[0].ValidValues
        foreach ($e in $script:Entries) {
            foreach ($text in [string]$e['get'], [string]$e['bring']) {
                foreach ($m in [regex]::Matches($text, '\b(?:Export|Import|Resume|Start|New|Invoke)-Posture[A-Za-z]+')) { $public | Should -Contain $m.Value -Because "$($e['id']) tells the reader to run it" }
                foreach ($m in [regex]::Matches($text, '-Collector (\w+)')) { $collectors | Should -Contain $m.Groups[1].Value }
                foreach ($m in [regex]::Matches($text, '\{(\w+)\}')) { $m.Groups[1].Value | Should -BeIn @('run', 'client', 'imports') }
            }
            if ($e.Contains('collector')) { $collectors | Should -Contain ([string]$e['collector']) }
            foreach ($field in 'title', 'who', 'where', 'get', 'bring') { [string]$e[$field] | Should -Not -Match ([string][char]0x2014) }
        }
    }

    It 'is refused by the loader when an entry lacks a field, names no evidence, or repeats an id' {
        $checks = InModuleScope TenantKeep.Posture { Get-PostureDataFolder -Name checks }
        $copy = Join-Path $script:Root 'bad-catalog'
        foreach ($case in @(
                @{ Break = { param($c) $c.completion[0].Remove('who') }; Says = '*has no who*' }
                @{ Break = { param($c) $c.completion[0].evidence = @() }; Says = '*names no evidence*' }
                @{ Break = { param($c) $c.completion[1].id = $c.completion[0].id }; Says = '*two completion entries*' }
            )) {
            if (Test-Path $copy) { Remove-Item -LiteralPath $copy -Recurse -Force }
            Copy-Item -LiteralPath $checks -Destination $copy -Recurse
            $doc = Get-Content -Raw (Join-Path $copy 'catalog.json') | ConvertFrom-Json -AsHashtable -Depth 20
            & $case.Break $doc
            $doc | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $copy 'catalog.json')
            { InModuleScope TenantKeep.Posture -Parameters @{ P = $copy } { param($P) Import-PostureCheckCatalog -Path $P } } | Should -Throw $case.Says
        }
    }
}

Describe 'What a run still lacks' {
    It 'lists Active Directory for a hybrid tenant with no AD read, with the checks that wait and both commands for this run' {
        $run = & $script:NewRun "o'brien run"
        # The tenant syncs from a domain, and the Windows collector has not been run.
        ConvertTo-Json -InputObject @(@{ id = 't'; features = @{ passwordSyncEnabled = $true } }) -Depth 5 | Set-Content (Join-Path $run 'evidence' '01-onprem-sync-features.json')
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache -Confirm:$false }
        $r = New-PostureReport -Evidence (Join-Path $run 'evidence') -PassThru 6>$null
        $ad = @($r.Report.completion | Where-Object { $_.id -eq 'active-directory' })
        $ad.Count | Should -Be 1
        $ad[0].checks | Should -BeGreaterThan 10
        $ad[0].checks | Should -Be @($r.Report.results | Where-Object { $_.domain -eq 'hybrid' -and $_.status -eq 'notEvaluated' -and $_.evidence -match '^ad-' }).Count
        $quoted = "'" + $run.Replace("'", "''") + "'"
        $ad[0].get | Should -Be "Export-PostureCollector -Kind ActiveDirectory -Run $quoted"
        $ad[0].bring | Should -Be "Import-PostureEvidence -Path <the folder the script wrote> -Run $quoted -Client '$((Join-Path $script:Root "client of o'brien run").Replace("'", "''"))'"
        $html = Get-Content -Raw (@($r.Files) -like '*.html')[0]
        $html | Should -Match 'To Complete This Assessment'
        $html | Should -Match ([regex]::Escape([System.Net.WebUtility]::HtmlEncode($ad[0].get)))
        $md = Get-Content -Raw (@($r.Files) -like '*.md')[0]
        $md | Should -Match '## To complete this assessment'
        $md | Should -Match 'Active Directory \(the on-premises domain\)'
    }

    It 'lists a collector that was skipped, with why, and not one that ran' {
        $run = & $script:NewRun 'skipped' @{ planned = @('Entra', 'Exchange'); skipped = @{ Exchange = 'ExchangeOnlineManagement is not installed: Install-Module ExchangeOnlineManagement' } }
        $r = New-PostureReport -Evidence (Join-Path $run 'evidence') -PassThru 6>$null
        $exo = @($r.Report.completion | Where-Object { $_.id -eq 'exchange' })
        $exo.Count | Should -Be 1
        $exo[0].note | Should -Be 'Skipped when the run started: ExchangeOnlineManagement is not installed: Install-Module ExchangeOnlineManagement'
        $exo[0].get | Should -Match "^Resume-PostureRun -Path '.*' -Collector Exchange$"
        @($r.Report.completion | Where-Object { $_.id -eq 'entra' }) | Should -BeNullOrEmpty -Because 'Entra ran: a file it lacks is a failed step, which Run Health explains'
    }

    It 'gives one row for the steps that failed, and names the permissions the sign-in lacks' {
        $run = & $script:NewRun 'failed-step'
        InModuleScope TenantKeep.Posture -Parameters @{ Ev = (Join-Path $run 'evidence') } {
            param($Ev)
            $script:PostureCurrentCollector = 'Entra'
            try { $null = Invoke-PostureStep -Label 'Risky users' -Folder $Ev -Script { throw 'Response status code does not indicate success: Forbidden (Forbidden).' } -WarningAction SilentlyContinue }
            finally { $script:PostureCurrentCollector = $null }
        }
        $r = New-PostureReport -Evidence (Join-Path $run 'evidence') -PassThru 6>$null
        $row = @($r.Report.completion | Where-Object { $_.id -eq 'failed-steps' })
        $row.Count | Should -Be 1
        $row[0].title | Should -Be '1 step that could not be read'
        # The step's scopes from requirements.json, less the ones the run's sign-in has.
        $row[0].note | Should -Match '^The sign-in does not carry: .*IdentityRiskyUser\.Read\.All'
        $row[0].note | Should -Not -Match 'Directory\.Read\.All' -Because 'the sign-in has that one'
        $row[0].get | Should -Match "^Consent again so the sign-in carries .*IdentityRiskyUser\.Read\.All.*, then: Resume-PostureRun -Path '"
        $row[0].where | Should -Match 'Run Health'
    }

    It 'tells a person who signed in through the TenantKeep app to approve it again, and only a scheduled run to grant the identity' {
        # Seen live 2026-11-23: the Graph SDK reports the module's own sign-in as UserProvidedAccessToken, and the
        # advice for a local run named the managed identity script.
        foreach ($case in @(@{ AuthType = 'UserProvidedAccessToken'; Expect = '^Consent again so the sign-in carries .*IdentityRiskyUser\.Read\.All' }, @{ AuthType = 'ManagedIdentity'; Expect = '^Grant the identity .*IdentityRiskyUser\.Read\.All.* \(deploy/automation/Grant-ManagedIdentityGraphRole\.ps1 -IncludePosture\)' })) {
            $run = & $script:NewRun "failed-step-$($case.AuthType)"
            @{ tenantId = '33333333-3333-3333-3333-333333333333'; collectors = @('ConditionalAccess', 'Entra'); authType = $case.AuthType; scopes = @('Policy.Read.All', 'Directory.Read.All'); timestampUtc = '2026-11-21T10:00:00Z' } | ConvertTo-Json | Set-Content (Join-Path $run 'evidence' 'collection.json')
            InModuleScope TenantKeep.Posture -Parameters @{ Ev = (Join-Path $run 'evidence') } {
                param($Ev)
                Clear-PostureEvidenceCache -Confirm:$false
                $script:PostureCurrentCollector = 'Entra'
                try { $null = Invoke-PostureStep -Label 'Risky users' -Folder $Ev -Script { throw 'Response status code does not indicate success: Forbidden (Forbidden).' } -WarningAction SilentlyContinue }
                finally { $script:PostureCurrentCollector = $null }
            }
            $r = New-PostureReport -Evidence (Join-Path $run 'evidence') -PassThru 6>$null
            @($r.Report.completion | Where-Object { $_.id -eq 'failed-steps' })[0].get | Should -Match $case.Expect -Because $case.AuthType
        }
        InModuleScope TenantKeep.Posture {
            foreach ($person in 'Delegated', 'UserProvidedAccessToken', '', $null) { Test-PostureAppOnlySignIn -AuthType $person | Should -BeFalse -Because "'$person' is a person, or unknown" }
            foreach ($app in 'AppOnly', 'ManagedIdentity') { Test-PostureAppOnlySignIn -AuthType $app | Should -BeTrue -Because $app }
        }
    }

    It 'does not count a check that waits for a licence, and lists nothing when nothing can be added' {
        InModuleScope TenantKeep.Posture -Parameters @{ Root = $script:Root; Catalog = $script:Catalog } {
            param($Root, $Catalog)
            $ev = Join-Path $Root 'unit'; New-Item -ItemType Directory -Path $ev | Out-Null
            $ad = @($Catalog.checks | Where-Object { @($_['evidence']) -match '^ad-' } | Select-Object -First 3)
            $results = @(
                [ordered]@{ id = [string]$ad[0]['id']; status = 'notEvaluated'; reason = 'Requires Entra ID P2.' }
                [ordered]@{ id = [string]$ad[1]['id']; status = 'notApplicable'; reason = 'Cloud-only tenant.' }
                [ordered]@{ id = [string]$ad[2]['id']; status = 'pass'; reason = $null }
            )
            @(Get-PostureCompletion -Catalog $Catalog -Result $results -Evidence $ev) | Should -BeNullOrEmpty
            $results += [ordered]@{ id = [string]$ad[2]['id']; status = 'notEvaluated'; reason = 'ad-01-forest-domain.json was not collected' }
            $rows = @(Get-PostureCompletion -Catalog $Catalog -Result $results -Evidence $ev)
            $rows.Count | Should -Be 1
            $rows[0].checks | Should -Be 1
            $rows[0].bring | Should -Match '-Client <the client folder>$' -Because 'a run that does not record its client folder says so in the command'
        }
    }

    It 'lists every source in Run Health with where the run stands, also when nothing is missing' {
        # "To Complete This Assessment" speaks only when a check waits. A run that lacks nothing then explained
        # nothing, and a reader could not tell "not needed for this tenant" from "nobody told me".
        $run = & $script:NewRun 'sources' @{ skipped = @{ Azure = 'the profile says azure: none' } }
        # A cloud-only tenant, by its profile: nothing waits for an Active Directory read.
        $client = Join-Path $script:Root 'client of sources'
        '{ "version": 1, "identityModel": "cloud-only" }' | Set-Content (Join-Path $client 'profile.json')
        $r = New-PostureReport -Evidence (Join-Path $run 'evidence') -Client $client -PassThru 6>$null
        $sources = @($r.Report.runHealth.sources)
        @($sources.id | Sort-Object) | Should -Be @($script:Entries | ForEach-Object { [string]$_['id'] } | Sort-Object) -Because 'every entry of the catalog is a row, once'
        $by = @{}; foreach ($s in $sources) { $by[[string]$s.id] = $s }
        $by['entra'].state | Should -Be 'collected'
        $by['entra'].detail | Should -Match '^\d+ files\.'
        $by['active-directory'].state | Should -Be 'notNeeded' -Because 'the profile says the tenant does not sync from a domain'
        $by['active-directory'].detail | Should -Be 'No check in this run waits for it. Needed by: A tenant that syncs users from an on-premises Active Directory domain.'
        $by['azure'].state | Should -Be 'notCollected'
        $by['azure'].detail | Should -Match '^Skipped when the run started: the profile says azure: none\. .*To Complete This Assessment'
        @($sources.state)[0] | Should -Be 'collected' -Because 'what the run holds comes first'
        @($sources.state)[-1] | Should -Be 'notNeeded'
        $html = Get-Content -Raw (@($r.Files) -like '*.html')[0]
        $html | Should -Match '<h3>Where This Run&#39;s Evidence Comes From</h3>|<h3>Where This Run''s Evidence Comes From</h3>'
        $html | Should -Match '<td>Active Directory \(the on-premises domain\)</td><td><span class="status notApplicable">Not needed here</span></td>'
        (Get-Content -Raw (@($r.Files) -like '*.md')[0]) | Should -Match '(?m)^\| Entra ID \| Collected \| \d+ files\. \|\r?$'
    }

    It 'says Active Directory is not collected when a hybrid tenant has no AD read, and collected once it has' {
        $run = & $script:NewRun 'sources-hybrid'
        ConvertTo-Json -InputObject @(@{ id = 't'; features = @{ passwordSyncEnabled = $true } }) -Depth 5 | Set-Content (Join-Path $run 'evidence' '01-onprem-sync-features.json')
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache -Confirm:$false }
        $ad = @((New-PostureReport -Evidence (Join-Path $run 'evidence') -PassThru 6>$null).Report.runHealth.sources | Where-Object { $_.id -eq 'active-directory' })[0]
        $ad.state | Should -Be 'notCollected'
        $ad.detail | Should -Match '^\d+ checks wait for it\. '
        '{ "DomainName": "contoso.example" }' | Set-Content (Join-Path $run 'evidence' 'ad-01-domain.json')
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache -Confirm:$false }
        $after = @((New-PostureReport -Evidence (Join-Path $run 'evidence') -PassThru 6>$null).Report.runHealth.sources | Where-Object { $_.id -eq 'active-directory' })[0]
        $after.files | Should -Be 1
    }

    It 'offers the command to collect again only when collecting again can change something' {
        # Seen on a live run: five steps that wait for a licence or for a read Microsoft does not give the sign-in,
        # under "After granting a role, collect only what failed" and a command that would have said the same again.
        $run = & $script:NewRun 'no-retry'
        $errors = Join-Path $run 'errors' 'errors.jsonl'
        @(
            @{ collector = 'Teams'; step = 'Teams app availability'; message = 'Not readable with this sign-in: the Teams module reads Get-AllM365TeamsApps with a Microsoft 365 token (substrate.office.com) that a session opened with access tokens does not carry.' }
            @{ collector = 'Entra'; step = 'Lifecycle workflows'; message = 'Forbidden: Entra ID Governance (Entra Suite) is not licensed in this tenant, or LifecycleWorkflows.Read.All was not consented. GV-005 needs that licence.' }
        ) | ForEach-Object { $_ | ConvertTo-Json -Compress } | Set-Content $errors
        $r = New-PostureReport -Evidence (Join-Path $run 'evidence') -PassThru 6>$null
        $html = Get-Content -Raw (@($r.Files) -like '*.html')[0]
        $html | Should -Match '2 step\(s\) could not be read\. Each row says why\. None of them is fixed by collecting again'
        $html | Should -Not -Match 'id="cmd-resume"'
        $html | Should -Match 'Run Health</a> says why for each; none of them is fixed by collecting again'
        (Get-Content -Raw (@($r.Files) -like '*.md')[0]) | Should -Match '2 step\(s\) could not be read\. None of them is fixed by collecting again'

        Add-Content $errors (@{ collector = 'Entra'; step = 'Risky users'; message = 'Response status code does not indicate success: Forbidden (Forbidden).' } | ConvertTo-Json -Compress)
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache -Confirm:$false }
        $again = Get-Content -Raw (@((New-PostureReport -Evidence (Join-Path $run 'evidence') -PassThru 6>$null).Files) -like '*.html')[0]
        $again | Should -Match 'After granting a role, collect only what failed'
        $again | Should -Match '<code id="cmd-resume">Resume-PostureRun -Path '
    }

    It 'says nothing in the Conditional Access tier, where the other domains are not waiting for evidence' {
        $run = & $script:NewRun 'free-tier'
        InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = $null }
        try { $r = New-PostureReport -Evidence (Join-Path $run 'evidence') -PassThru 6>$null 3>$null }
        finally { InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } } }
        @($r.Report.completion) | Should -BeNullOrEmpty
        Get-Content -Raw (@($r.Files) -like '*.html')[0] | Should -Not -Match 'To Complete This Assessment'
        Get-Content -Raw (@($r.Files) -like '*.html')[0] | Should -Not -Match 'Evidence Comes From' -Because 'the source list is about every domain, and this tier reports one'
    }
}

Describe 'A site permissions report saved straight into imports' {
    BeforeAll {
        $script:Csv = {
            param([string] $Path, [string] $Tenant = '33333333-3333-3333-3333-333333333333', [switch] $Other)
            if ($Other) { "Name,Value`nA,1" | Set-Content $Path; return }
            "Site URL,Site Name,Anyone link count,People In Your Org link count,EEEU permission count,Everyone permission count,Report Date,TenantID`nhttps://contoso.sharepoint.com/sites/hr,HR,2,5,1,0,2026-11-18,$Tenant" | Set-Content $Path
        }
    }

    It 'is filed once with the cmdlet''s checks, and a CSV of something else is left alone' {
        InModuleScope TenantKeep.Posture -Parameters @{ Root = $script:Root; Csv = $script:Csv } {
            param($Root, $Csv)
            $client = Join-Path $Root 'client-drop'; New-Item -ItemType Directory -Path (Join-Path $client 'imports') -Force | Out-Null
            $report = Join-Path $client 'imports' 'SitePermissions.csv'; & $Csv $report
            $other = Join-Path $client 'imports' 'something-else.csv'; & $Csv $other -Other
            $target = Add-PostureSharingReportFile -Client $client -Path $report -TenantId '33333333-3333-3333-3333-333333333333' -Confirm:$false
            $target | Should -Be (Join-Path $client 'imports' 'sam-dag' 'site-permissions-sharepoint-2026-11-18.csv')
            $target | Should -Exist
            Add-PostureSharingReportFile -Client $client -Path $report -TenantId '33333333-3333-3333-3333-333333333333' -Confirm:$false | Should -BeNullOrEmpty -Because 'it is already filed, byte for byte'
            Add-PostureSharingReportFile -Client $client -Path $other -Confirm:$false | Should -BeNullOrEmpty
            { Add-PostureSharingReportFile -Client $client -Path $other -Strict -Confirm:$false } | Should -Throw '*is not the Site permissions across your organization report*'
            $report | Should -Exist -Because 'the admin''s file is never moved or deleted'
        }
    }

    It 'is refused when it is another tenant''s' {
        InModuleScope TenantKeep.Posture -Parameters @{ Root = $script:Root; Csv = $script:Csv } {
            param($Root, $Csv)
            $client = Join-Path $Root 'client-wrong'; New-Item -ItemType Directory -Path (Join-Path $client 'imports') -Force | Out-Null
            $report = Join-Path $client 'imports' 'SitePermissions.csv'; & $Csv $report '44444444-4444-4444-4444-444444444444'
            { Add-PostureSharingReportFile -Client $client -Path $report -TenantId '33333333-3333-3333-3333-333333333333' -Confirm:$false } | Should -Throw '*is for tenant 44444444*Nothing was filed*'
            Join-Path $client 'imports' 'sam-dag' | Should -Not -Exist
        }
    }
}
