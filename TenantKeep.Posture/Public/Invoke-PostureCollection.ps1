# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureCollection {
    <#
    .SYNOPSIS
        Collects evidence from the tenant into one run folder with the audit plan's file names (spec 6, Appendix A).
    .DESCRIPTION
        Read-only. The Entra collector (A.1 identity sections): organization and licensing, tenant-wide
        policies, privileged roles active and PIM-eligible, authentication method registration, users, groups,
        app registrations and service principals with credential expiry, Graph application permissions, delegated
        grants, Identity Protection. The Conditional Access snapshot (spec 5.1) is written into the same folder, so
        one folder feeds every domain's checks. Each step logs a failure to errors.txt and the run continues.

        Requires an existing Graph session with Policy.Read.All, Directory.Read.All and Group.Read.All. Optional
        scopes unlock more: User.Read.All and AuditLog.Read.All (sign-in activity, registration report),
        UserAuthenticationMethod.Read.All (registration report), RoleManagement.Read.Directory (PIM),
        OnPremDirectorySynchronization.Read.All (hybrid sync features), IdentityRiskyUser.Read.All and
        IdentityRiskEvent.Read.All (Identity Protection). Missing ones are reported
        with the steps they would unlock. Never connects on its own.
    .PARAMETER OutRoot
        Root folder for evidence. Default: ~/tenantkeep/evidence. The run folder <yyyyMMdd-HHmm> is created under it.
    .PARAMETER OutputFolder
        Write into this exact folder instead.
    .PARAMETER Collector
        Which collectors to run: Entra (A.1 identity sections), SignIns (the Entra sign-in log for -SignInDays,
        streamed and tallied, checkpointed and self-resuming; Entra ID P1), Intune (A.1 section 9 and the spec 4.4 additions),
        Exchange (A.2 Exchange Online and the mail DNS records), SharePoint (A.3 tenant settings and sites through
        PnP.PowerShell), Teams (A.3 Teams policies), Defender (effective state through Graph advanced hunting,
        incidents and Secure Score), Purview (A.2 labels, DLP, retention and the rest through Connect-IPPSSession,
        in a process of its own because its cmdlet names overlap Exchange's), Azure (spec 4.13 through Resource Graph
        and Resource Manager reads on a Connect-AzAccount session). Default all nine; a collector whose session is missing is skipped with a warning,
        and refused when it was asked for by name; Defender runs on the Graph session and is skipped with a warning
        when ThreatHunting.Read.All was not granted. See docs/collection.md for the sign-ins.
    .PARAMETER SignInDays
        Days of sign-in log the SignIns collector reads, 1 to 30. Default 7. A large tenant has millions of records a
        week; the read streams and can take hours, and resumes from its checkpoint when it stops.
    .PARAMETER StaleDays
        Threshold for inactive users and devices in the summaries. Default 90.
    .PARAMETER IncludeMembers
        Store group member lists in the Conditional Access snapshot.
    .PARAMETER SkipCaSnapshot
        Do not write the Conditional Access snapshot into the folder.
    .PARAMETER ProfilePath
        profile.json of the tenant. When it carries tenantId, a Graph session in any other tenant is refused before
        anything is read: the guard for a machine that holds sessions to several tenants.
    .PARAMETER FullPerUserMfa
        Read the per-user MFA state of every member. Default: every member up to 5,000; above that a sample, every
        admin and 1,000 members at random, and the check says it judged a sample. Reading everyone is a request
        per account: hours on a tenant of hundreds of thousands.
    .PARAMETER SkipPerUserMfa
        Skip the per-user MFA state read (one batched Graph read per member; slow at tens of thousands of users).
    .PARAMETER SkipSiteEnumeration
        Skip the SharePoint site list (Get-PnPTenantSite, the slow read on a tenant with tens of thousands of
        sites); the checks that read sites are then not evaluated.
    .PARAMETER IncludeOneDriveSites
        List every OneDrive in the SharePoint site list as well. No check reads them, and on a large tenant there
        is one per user, so they are left out unless this is given.
    .PARAMETER SkipMailboxEnumeration
        Skip the Exchange mailbox and CAS mailbox pulls (10 to 20 minutes at 20k mailboxes); the forwarding, shared
        mailbox and per-mailbox protocol checks are then not evaluated.
    .PARAMETER PassThru
        Return a summary object instead of the folder path.
    .EXAMPLE
        Connect-MgGraph -Scopes Policy.Read.All, Directory.Read.All, Group.Read.All, User.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All, RoleManagement.Read.Directory, OnPremDirectorySynchronization.Read.All, IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All -NoWelcome
        Invoke-PostureCollection

        Writes ~/tenantkeep/evidence/<stamp>/ with the A.1 files and the CA snapshot.
    .EXAMPLE
        Connect-ExchangeOnline -UserPrincipalName reader@contoso.example -ShowBanner:$false
        Invoke-PostureCollection -Collector Exchange -SkipCaSnapshot

        Writes the A.2 exo-* files and dns-01-mail-records into a new run folder. Needs View-Only Organization Management or equivalent.
    .EXAMPLE
        Connect-AzAccount -Tenant <tenant id>
        Invoke-PostureCollection -Collector Azure -SkipCaSnapshot -OutputFolder <the run folder>

        Writes the az-* files (spec 4.13); Reader on the subscriptions or the management group, plus Security Reader.
    .EXAMPLE
        Connect-IPPSSession -UserPrincipalName reader@contoso.example
        Invoke-PostureCollection -Collector Purview -SkipCaSnapshot -OutputFolder <the run folder>

        Writes the A.2 pv-* files into an existing run folder from a process of its own.
    .EXAMPLE
        Connect-PnPOnline -Url https://contoso-admin.sharepoint.com -ClientId <sharePointClientId> -Interactive
        Connect-MicrosoftTeams
        Invoke-PostureCollection -Collector SharePoint, Teams -SkipCaSnapshot

        Writes the A.3 spo-* and teams-* files. The app registration comes from deploy/setup/New-PostureSharePointApp.ps1.
    .EXAMPLE
        Invoke-PostureCollection -OutRoot ./evidence -PassThru | Select-Object Folder, Errors
    .OUTPUTS
        System.String, the run folder. With -PassThru, a summary object.
    .LINK
        docs/m365-environment-audit-plan.md Appendix A
    #>
    [CmdletBinding()]
    [OutputType([string], [pscustomobject])]
    param(
        [ValidateNotNullOrEmpty()] [string] $OutRoot = (Join-Path $HOME 'tenantkeep' 'evidence'),
        [string] $OutputFolder,
        [ValidateSet('Entra', 'SignIns', 'Intune', 'Exchange', 'SharePoint', 'Teams', 'Defender', 'Purview', 'Azure')] [string[]] $Collector = @('Entra', 'SignIns', 'Intune', 'Exchange', 'SharePoint', 'Teams', 'Defender', 'Purview', 'Azure'),
        [ValidateRange(1, 30)] [int] $SignInDays = 7,
        [ValidateRange(1, 3650)] [int] $StaleDays = 90,
        [Alias('Profile')] [string] $ProfilePath,
        [switch] $IncludeMembers,
        [switch] $SkipCaSnapshot,
        [switch] $SkipPerUserMfa,
        [switch] $FullPerUserMfa,
        [switch] $SkipMailboxEnumeration,
        [switch] $SkipSiteEnumeration,
        [switch] $IncludeOneDriveSites,
        [switch] $PassThru
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $core = @('Policy.Read.All', 'Directory.Read.All', 'Group.Read.All')
    $context = Assert-PostureGraphScope -RequiredScope $core
    if ($ProfilePath) {
        $orgProfile = Import-PostureProfile -Path $ProfilePath
        $expected = [string]$(if ($orgProfile.Contains('tenantId')) { $orgProfile['tenantId'] })
        if ($expected -and $expected -ne [string]$context.TenantId) { throw "The Graph session is in tenant $($context.TenantId), but $ProfilePath belongs to tenant $expected. Sign in to that tenant first, Connect-MgGraph -TenantId $expected, or pass the right profile." }
        # A tenant with nothing in Azure (azure: none in the profile) is never asked for an Azure session; the domain reads as not applicable.
        if (-not $PSBoundParameters.ContainsKey('Collector') -and [string]$(if ($orgProfile.Contains('azure')) { $orgProfile['azure'] }) -eq 'none' -and 'Azure' -in $Collector) {
            $Collector = @($Collector | Where-Object { $_ -ne 'Azure' })
            Write-Verbose 'Profile says azure: none; the Azure collector is skipped.'
        }
    }
    $optional = [ordered]@{
        'User.Read.All'                     = 'Users'
        'OnPremDirectorySynchronization.Read.All' = 'Hybrid sync features'
        'AuditLog.Read.All'                 = 'Users sign-in activity, Auth method registration'
        'UserAuthenticationMethod.Read.All' = 'Auth method registration'
        'RoleManagement.Read.Directory'     = 'PIM eligible assignments, PIM role policies'
        'IdentityRiskyUser.Read.All'        = 'Risky users'
        'IdentityRiskEvent.Read.All'        = 'Risk detections'
        'DeviceManagementManagedDevices.Read.All' = 'Intune managed devices, Autopilot'
        'DeviceManagementConfiguration.Read.All'  = 'Intune compliance and configuration policies, enrollment restrictions, cleanup rule'
        'DeviceManagementServiceConfig.Read.All'  = 'Apple push certificate, MDE connector'
        'DeviceManagementApps.Read.All'           = 'Intune apps, Apple VPP tokens'
        'BitLockerKey.ReadBasic.All'              = 'BitLocker recovery key presence'
        'AttackSimulation.Read.All'               = 'Attack simulation campaigns (skipped quietly when missing)'
        'AccessReview.Read.All'                   = 'Access review definitions'
        'EntitlementManagement.Read.All'          = 'Access packages, catalogs, connected organizations'
        'LifecycleWorkflows.Read.All'             = 'Lifecycle workflows'
        'PrivilegedEligibilitySchedule.Read.AzureADGroup' = 'PIM for Groups, Role holders (who can join a group that holds a role)'
        'AdministrativeUnit.Read.All'             = 'Administrative units'
        'NetworkAccess.Read.All'                  = 'Global Secure Access (only where licensed)'
        'BackupRestore-Configuration.Read.All'    = 'Microsoft 365 Backup (with the Azure collector)'
        'ThreatHunting.Read.All'                  = 'Defender devices, antivirus state, secure configuration, vulnerabilities (advanced hunting)'
        'SecurityIncident.Read.All'               = 'Defender incidents'
        'SecurityEvents.Read.All'                 = 'Secure Score'
    }
    $granted = @($context.Scopes)
    foreach ($scope in $optional.Keys) {
        if ($scope -notin $granted) { Write-Warning "Scope $scope not granted; expect '$($optional[$scope])' to land in errors.txt." }
    }
    # Session-bound collectors: skipped with a warning by default, refused when named. The module never connects. Exchange,
    # Purview and Azure must be in the Graph session's tenant: a session left open for another tenant is not used.
    $tenant = [string]$context.TenantId
    $sessions = [ordered]@{
        Exchange   = @{ test = { Test-PostureExoSession -TenantId $tenant }; hint = "Connect-ExchangeOnline -UserPrincipalName <reader> (in tenant $tenant)" }
        SharePoint = @{ test = { Test-PosturePnpSession }; hint = 'Connect-PnPOnline -Url https://<tenant>-admin.sharepoint.com -ClientId <sharePointClientId from profile.json> -Interactive' }
        Teams      = @{ test = { Test-PostureTeamsSession }; hint = 'Connect-MicrosoftTeams' }
        Purview    = @{ test = { Test-PosturePurviewSession -TenantId $tenant }; hint = "Connect-IPPSSession -UserPrincipalName <reader> (in tenant $tenant)" }
        Azure      = @{ test = { Test-PostureAzureSession -TenantId $tenant }; hint = "Connect-AzAccount -Tenant $tenant" }
    }
    $run = @{}
    $run['Defender'] = $Collector -contains 'Defender'
    if ($run['Defender'] -and 'ThreatHunting.Read.All' -notin $granted) {
        if ($PSBoundParameters.ContainsKey('Collector')) { throw 'The Defender collector needs ThreatHunting.Read.All on the Graph session (plus SecurityIncident.Read.All and SecurityEvents.Read.All for incidents and Secure Score).' }
        Write-Warning 'ThreatHunting.Read.All not granted; skipping the Defender collector. Add it to Connect-MgGraph -Scopes, or name the collectors you want in -Collector to silence this.'
        $run['Defender'] = $false
    }
    foreach ($name in $sessions.Keys) {
        $run[$name] = $Collector -contains $name
        if ($run[$name] -and -not (& $sessions[$name].test)) {
            if ($PSBoundParameters.ContainsKey('Collector')) { throw "The $name collector needs an open session: $($sessions[$name].hint) first. The module never connects on its own." }
            Write-Warning "No $name session; skipping the $name collector. Run $($sessions[$name].hint) first, or name the collectors you want in -Collector to silence this."
            $run[$name] = $false
        }
    }

    $startedUtc = [datetime]::UtcNow
    $folder = if ($OutputFolder) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
        (Resolve-Path -LiteralPath $OutputFolder).Path
    }
    else { New-PostureEvidenceFolder -OutRoot $OutRoot }
    $script:GraphApiVersionsUsed.Clear()
    # The journal of this collection (logs/journal.jsonl): steps, files and finished collectors as they happen.
    $journalBefore = $script:PostureJournalFolder
    $script:PostureJournalFolder = $folder

    try {
        $files = [System.Collections.Generic.List[string]]::new()
        $ran = [System.Collections.Generic.List[string]]::new()
        Write-PostureJournal -Folder $folder -Entry @{ kind = 'run'; state = 'started'; collectors = @($Collector); moduleVersion = [string]$script:ModuleVersion }

        # Each collector is a progress phase, and its time and step count go into the manifest for the next run's estimate.
        $timings = [ordered]@{}
        $errorsPath = Join-Path (Get-PostureRunLayout -Folder $folder).errors 'errors.txt'
        # Collectors may run in separate processes into one folder, at the same time (Start-PostureRun runs Exchange
        # and Purview alongside the rest): the manifest is read, merged and written under the folder's lock, and
        # keeps what the other process recorded (collectors, start time, API versions, scopes, timings).
        $writeManifest = {
            param([switch] $Final)
            Invoke-PostureFolderLock -Folder $folder -Script {
                $errors = @(if (Test-Path -LiteralPath $errorsPath) { Get-Content -LiteralPath $errorsPath })   # @( ) outside the if: an empty array inside it unrolls to null
                $previous = $null
                $manifestPath = Join-Path $folder 'collection.json'
                if ($OutputFolder -and (Test-Path -LiteralPath $manifestPath)) { try { $previous = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json -AsHashtable -Depth 10 } catch { $previous = $null } }
                $allCollectors = @(@($(if ($previous) { $previous['collectors'] })) + $ran.ToArray() | Where-Object { $_ } | Select-Object -Unique)
                # Module versions: what this process loaded, over what an earlier process into the same folder recorded.
                $modules = [ordered]@{}
                if ($previous -and $previous['modules']) { foreach ($k in @($previous['modules'].Keys)) { $modules[$k] = $previous['modules'][$k] } }
                $used = Get-PostureModuleVersionUsed
                foreach ($k in @($used.Keys)) { if ($used[$k] -or -not $modules.Contains($k)) { $modules[$k] = $used[$k] } }
                $versions = @(@($(if ($previous -and $previous['graphApiVersions']) { $previous['graphApiVersions'] })) + @($script:GraphApiVersionsUsed) | Where-Object { $_ } | Sort-Object -Unique)
                $allScopes = @(@($(if ($previous -and $previous['scopes']) { $previous['scopes'] })) + @($granted) | Where-Object { $_ } | Sort-Object -Unique)
                $allTimings = [ordered]@{}
                if ($previous -and $previous['timings']) { foreach ($k in @($previous['timings'].Keys)) { $allTimings[$k] = $previous['timings'][$k] } }
                foreach ($k in @($timings.Keys)) { $allTimings[$k] = $timings[$k] }
                $doc = [ordered]@{
                    product          = 'TenantKeep.Posture'
                    moduleVersion    = $script:ModuleVersion
                    collectors       = $allCollectors
                    tenantId         = $context.TenantId
                    account          = $context.Account
                    authType         = $context.AuthType
                    scopes           = $allScopes
                    timestampUtc     = $(if ($previous -and $previous['timestampUtc']) { (ConvertTo-PostureUtcDateTime $previous['timestampUtc']).ToString('o') } else { $startedUtc.ToString('o') })   # ConvertFrom-Json turned it into a DateTime
                    completedUtc     = [datetime]::UtcNow.ToString('o')
                    graphApiVersions = $versions
                    modules          = $modules
                    powerShell       = $PSVersionTable.PSVersion.ToString()
                    os               = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
                    staleDays        = $StaleDays
                    files            = @(Get-ChildItem -LiteralPath $folder -File | Where-Object { $_.Name -notin @('transcript.txt', 'run.json') -and -not $_.Name.StartsWith('errors') -and -not $_.Name.StartsWith('.') -and $_.Extension -ne '.part' } | ForEach-Object { $_.Name } | Sort-Object)
                    errorCount       = $errors.Count
                    errors           = $errors
                    timings          = $allTimings
                }
                # Written after every collector, so a run that dies later has a manifest of what finished; the row
                # count line and the call ledger come once, at the end.
                $written = Write-PostureEvidence -Folder $folder -Name 'collection' -InputObject $doc -Quiet:(-not $Final)
                if ($Final) { $files.Add($written); $null = Save-PostureCallLedger -Folder $folder -Confirm:$false }
                $doc
            }
        }
        $timed = {
            param([string] $Name, [scriptblock] $Block)
            Set-PostureProgressPhase -Name $Name
            $script:PostureCurrentCollector = $Name
            $clock = [System.Diagnostics.Stopwatch]::StartNew(); $steps0 = $script:PostureStepCount
            Write-PostureJournal -Folder $folder -Entry @{ kind = 'collector'; state = 'started'; collector = $Name }
            $result = & $Block
            $timings[$Name] = [ordered]@{ seconds = [Math]::Round($clock.Elapsed.TotalSeconds, 1); steps = [Math]::Max(1, $script:PostureStepCount - $steps0) }
            $ran.Add($Name)
            # Finished, whatever its steps did: the journal and the manifest say so now, not at the end of the run, so
            # a run that stops in a later collector is resumed from there.
            Write-PostureJournal -Folder $folder -Entry @{ kind = 'collector'; state = 'done'; collector = $Name; seconds = $timings[$Name].seconds; steps = $timings[$Name].steps }
            $null = & $writeManifest
            # A collector whose step failed returns nothing: record nothing, and never let that stop the others.
            if ($result -is [System.Collections.IDictionary] -and $result.Contains('files')) { foreach ($f in @($result['files'])) { if ($f) { $files.Add($f) } } }
        }
        if (-not $SkipCaSnapshot) {
            Set-PostureProgressPhase -Name 'ConditionalAccess'
            $clock = [System.Diagnostics.Stopwatch]::StartNew()
            $snap = Export-PostureCaSnapshot -OutputFolder $folder -IncludeMembers:$IncludeMembers -PassThru
            foreach ($f in $snap.Files) { $files.Add($f) }
            $timings['ConditionalAccess'] = [ordered]@{ seconds = [Math]::Round($clock.Elapsed.TotalSeconds, 1); steps = 1 }
            $ran.Add('ConditionalAccess')
            Write-PostureJournal -Folder $folder -Entry @{ kind = 'collector'; state = 'done'; collector = 'ConditionalAccess'; seconds = $timings['ConditionalAccess'].seconds; steps = 1 }
            $null = & $writeManifest
        }
        if ($Collector -contains 'Entra') { & $timed 'Entra' { Invoke-PostureEntraCollection -Folder $folder -StaleDays $StaleDays -AsOf $startedUtc -SkipPerUserMfa:$SkipPerUserMfa -FullPerUserMfa:$FullPerUserMfa } }
        # A step like any other, so a refusal or a missing licence is recorded with its cause and the run goes on.
        if ($Collector -contains 'SignIns') { & $timed 'SignIns' { Invoke-PostureStep -Label 'Sign-in log' -Folder $folder -Script { Invoke-PostureSignInCollection -Folder $folder -Days $SignInDays -AsOf $startedUtc } } }
        if ($Collector -contains 'Intune') { & $timed 'Intune' { Invoke-PostureIntuneCollection -Folder $folder -StaleDays $StaleDays -AsOf $startedUtc } }
        if ($run.Exchange) { & $timed 'Exchange' { Invoke-PostureExchangeCollection -Folder $folder -SkipMailboxEnumeration:$SkipMailboxEnumeration } }
        if ($run.SharePoint) { & $timed 'SharePoint' { Invoke-PostureSharePointCollection -Folder $folder -SkipSiteEnumeration:$SkipSiteEnumeration -IncludeOneDriveSites:$IncludeOneDriveSites } }
        if ($run.Teams) { & $timed 'Teams' { Invoke-PostureTeamsCollection -Folder $folder } }
        if ($run.Purview) { & $timed 'Purview' { Invoke-PosturePurviewCollection -Folder $folder } }
        if ($run.Azure) { & $timed 'Azure' { Invoke-PostureAzureCollection -Folder $folder } }
        if ($run.Defender) { & $timed 'Defender' { Invoke-PostureDefenderCollection -Folder $folder -AsOf $startedUtc } }

        $manifest = & $writeManifest -Final
        $errors = @($manifest['errors'])
        if ($errors.Count -gt 0) { Write-Warning "$($errors.Count) step(s) failed; see $errorsPath" }

        if ($PassThru) {
            return [pscustomobject]@{ Folder = $folder; Collectors = @($manifest['collectors']); Files = $files.ToArray(); Errors = $errors; Manifest = $manifest }
        }
        return $folder
    }
    finally {
        $script:PostureJournalFolder = $journalBefore
        $script:PostureCurrentStep = $null
        if (-not $OutputFolder) { try { Stop-Transcript | Out-Null } catch { Write-Verbose 'No transcript to stop.' } }
    }
}
