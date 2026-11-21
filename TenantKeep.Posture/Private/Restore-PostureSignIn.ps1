# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
# A run that outlives its sign-in. An admin account is the account most likely to have a Conditional Access sign-in
# frequency of a few hours; past it the identity platform refuses every renewal, for Graph, SharePoint, Teams and
# Azure alike, until the admin signs in again. This file is what happens then:
#   - In a run with someone at the console, the run pauses and asks the same admin to sign in again, then repeats
#     the request it was making (Restore-PostureSignIn, called from Get-PostureToken).
#   - Otherwise, or when the new sign-in does not complete, the run records once that the sign-in ended. The steps
#     that depend on it are then not attempted (Invoke-PostureStep), in one line instead of one failure each, the
#     domains they belong to are not recorded as finished, and Resume-PostureRun carries on after a new sign-in.
# Before any of that, the run says what to expect: Get-PostureSignInFrequencyNotice reads the Conditional Access
# snapshot for a sign-in frequency that applies to the account.

# Which sign-in has ended in this process: 'main' (everything but SharePoint) or 'sharepoint', each with when and why.
$script:PostureSessionEnded = @{}
$script:PostureSignInRenewalLimit = 3

function Test-PostureInteractive {
    <#
    .SYNOPSIS
        Whether there can be someone at the console to sign in again: an interactive session that was not started
        with -NonInteractive.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (-not [System.Environment]::UserInteractive) { return $false }
    return @([System.Environment]::GetCommandLineArgs() | Where-Object { $_ -match '^-NonI' }).Count -eq 0
}

function Test-PostureSignInEnded {
    <#
    .SYNOPSIS
        Whether the identity platform's answer to a renewal says the sign-in itself is over, so that no renewal will
        work until the admin signs in again.
    .DESCRIPTION
        A refused refresh comes back as invalid_grant or interaction_required: a sign-in frequency that has passed
        (AADSTS70043, AADSTS70044), a refresh token that expired or was revoked (AADSTS700082, AADSTS50173), a
        second factor asked for again (AADSTS50076, AADSTS50078, AADSTS50079). Consent and assignment refusals use
        invalid_grant too and are not this: a new sign-in would be refused the same way.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowEmptyString()] [string] $Message)

    if ($Message -match '(?i)AADSTS65001|consent_required|AADSTS650\d\d|AADSTS50105|AADSTS7000112|AADSTS700016|AADSTS5300\d|AADSTS530032') { return $false }
    return [bool]($Message -match '(?i)Sign-in failed \((invalid_grant|interaction_required)\)|AADSTS70043|AADSTS70044|AADSTS700082|AADSTS50173')
}

function Get-PostureEndedSignIn {
    <#
    .SYNOPSIS
        For the collector that is running: the record of its sign-in having ended (@{ holder; utc; reason }), or
        nothing. Exchange and Purview sign in through the Exchange module and are never in it.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([string] $Collector = $script:PostureCurrentCollector)

    if ($script:PostureSessionEnded.get_Count() -eq 0 -or -not $Collector -or $Collector -in 'Exchange', 'Purview') { return $null }
    $holder = $(if ($Collector -eq 'SharePoint') { 'sharepoint' } else { 'main' })
    if (-not $script:PostureSessionEnded.ContainsKey($holder)) { return $null }
    $record = $script:PostureSessionEnded[$holder]
    return @{ holder = $holder; utc = $record.utc; reason = $record.reason }
}

function Restore-PostureSignIn {
    <#
    .SYNOPSIS
        Called when a renewal was refused because the sign-in has ended. With someone at the console, pauses the
        run, signs the same admin in again and puts the new refresh token in the session. Otherwise, or when that
        does not complete, records that the sign-in ended and throws.
    .DESCRIPTION
        The new sign-in must be the same account in the same tenant; anyone else is refused and the run stops
        there, since everything collected so far was read as the first account. At most three new sign-ins in one
        run. The token service that renews for the second process gets the new refresh token as well.
    .PARAMETER Holder
        main, or sharepoint for the SharePoint app's own sign-in.
    .PARAMETER Reason
        The identity platform's message for the refused renewal.
    #>
    [CmdletBinding()]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'The run is paused for a sign-in: the console is where the admin is told.')]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Session,
        [Parameter(Mandatory)] [ValidateSet('main', 'sharepoint')] [string] $Holder,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Reason
    )

    $ErrorActionPreference = 'Stop'
    $code = [regex]::Match($Reason, 'AADSTS\d+').Value
    $ended = $script:PostureSessionEnded
    $say = { param([datetime] $When, [string] $Why) "The sign-in ended at $($When.ToString('HH:mm')) UTC and could not be renewed: $Why Resume-PostureRun carries on after a new sign-in." }
    # The thread that renews for the second process cannot ask anyone and keeps no record: once the main thread
    # has signed in again its next renewal works.
    if ($Session.Contains('serviceThread') -and $Session['serviceThread']) { throw (& $say ([datetime]::UtcNow) "the main window has to sign in again$(if ($code) { " ($code)" }).") }
    if ($ended.ContainsKey($Holder)) { throw (& $say $ended[$Holder].utc $ended[$Holder].reason) }
    $stop = {
        param([string] $Why)
        $ended[$Holder] = @{ utc = [datetime]::UtcNow; reason = $Why }
        throw (& $say $ended[$Holder].utc $Why)
    }
    if (-not ($Session.Contains('interactive') -and $Session['interactive']) -or -not (Test-PostureInteractive)) { & $stop "there is no one to ask in this run$(if ($code) { " ($code)" })." }
    $renewed = [int]$(if ($Session.Contains('signInsRenewed')) { $Session['signInsRenewed'] } else { 0 })
    if ($renewed -ge $script:PostureSignInRenewalLimit) { & $stop "it was renewed $renewed times in this run already$(if ($code) { " ($code)" })." }

    $account = [string]$Session['account']
    $target = $(if ($Holder -eq 'sharepoint') { $Session['sharepoint'] } else { $Session })
    $appName = $(if ($Holder -eq 'sharepoint') { 'TenantKeep Posture for SharePoint' } else { 'TenantKeep Posture' })
    $resourceScope = $(if ($Holder -eq 'sharepoint') { Get-PostureResourceScope -Resource sharepoint -TenantName $Session['tenantName'] } else { 'https://graph.microsoft.com/.default' })
    $mode = [string]$(if ($Session.Contains('signInMode')) { $Session['signInMode'] } else { 'browser' })
    Write-Host ''
    Write-Host "The sign-in for $account has ended$(if ($code) { " ($code)" }). The run is paused: nothing is lost, and it carries on from the request it was making once $account has signed in again." -ForegroundColor Yellow
    try {
        $tokens = Invoke-PostureSignIn -ClientId ([string]$target['clientId']) -Scope "openid profile offline_access $resourceScope" -TenantId ([string]$Session['tenantId']) -AppName $appName -LoginHint $account -DeviceCode:($mode -eq 'device') -NoBrowser:($mode -eq 'nobrowser') -TimeoutSeconds 900
        $claims = ConvertFrom-PostureJwt -Token ([string]$tokens['access_token'])
        $who = [string]$(foreach ($k in 'upn', 'preferred_username', 'unique_name') { if ($claims.ContainsKey($k) -and $claims[$k]) { $claims[$k]; break } })
        if ([string]$claims['tid'] -ne [string]$Session['tenantId']) { throw "the new sign-in went to tenant $($claims['tid']), not the run's tenant" }
        if ($who -and -not [string]::Equals($who, $account, [System.StringComparison]::OrdinalIgnoreCase)) { throw "the new sign-in was as $who, and the run is $account's" }
        if (-not $tokens['refresh_token']) { throw 'the new sign-in returned no refresh token' }
    }
    catch { & $stop "the new sign-in did not complete ($((([string]$_.Exception.Message) -replace '\s*[\r\n]+\s*', ' ').Trim()))." }

    $now = [datetime]::UtcNow
    $target['refreshToken'] = [string]$tokens['refresh_token']
    $Session['signInsRenewed'] = $renewed + 1
    $Session['signedInUtc'] = $now
    $Session['tokens'][$(if ($Holder -eq 'sharepoint') { 'sharepoint' } else { 'graph' })] = @{ accessToken = [string]$tokens['access_token']; expiresUtc = $now.AddSeconds([int]$tokens['expires_in']); scope = [string]$(if ($tokens.ContainsKey('scope')) { $tokens['scope'] }) }
    # The second process renews through the token service, which holds its own copy of the session.
    if ($Holder -eq 'main' -and $script:PostureTokenServer -and $script:PostureTokenServer['session']) { $script:PostureTokenServer['session']['refreshToken'] = [string]$tokens['refresh_token'] }
    Write-Host "Signed in again as $account. Carrying on." -ForegroundColor Green
}

function Get-PostureSignInFrequencyNotice {
    <#
    .SYNOPSIS
        From the Conditional Access snapshot in a run folder: the shortest sign-in frequency that applies, or may
        apply, to the account running the collection, as @{ hours; policy; certain; text }, or nothing.
    .DESCRIPTION
        A policy counts when it is enabled, sets a sign-in frequency in hours or days, covers all cloud apps or
        Microsoft Graph or Office 365, and includes the account: by id, by "All users", or by a directory role the
        account holds now (the role template ids in its token). A policy that excludes the account by id or by one
        of those roles does not count. Membership of a group is not read here, so a policy that includes or
        excludes by group may apply: it is reported as "may".
    .PARAMETER ObjectId
        The account's object id, when known (the oid claim of its token).
    .PARAMETER RoleTemplateId
        The role template ids the account holds now, when known (the wids claim).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [string] $ObjectId,
        [string[]] $RoleTemplateId = @(),
        [switch] $Interactive
    )

    $pol = Read-PostureEvidenceFile -Folder $Folder -Name 'policies'
    if ($null -eq $pol) { return $null }
    $items = @($(if ($pol -is [System.Collections.IDictionary] -and $pol.Contains('value')) { $pol['value'] } else { $pol }) | Where-Object { $_ })
    $list = { param($policy, [string] $path) @(Get-PostureValue $policy $path | Where-Object { $_ } | ForEach-Object { [string]$_ }) }
    $graphApps = @('All', 'Office365', '00000003-0000-0000-c000-000000000000')
    $best = $null
    foreach ($p in $items) {
        $f = Get-PostureValue $p 'sessionControls.signInFrequency'
        if ([string](Get-PostureValue $p 'state') -ne 'enabled' -or -not $f -or (Get-PostureValue $f 'isEnabled') -ne $true) { continue }
        if ([string](Get-PostureValue $f 'frequencyInterval') -eq 'everyTime') { continue }
        $hours = [double](Get-PostureValue $f 'value') * $(if ([string](Get-PostureValue $f 'type') -eq 'days') { 24 } else { 1 })
        if ($hours -le 0) { continue }
        if (@(& $list $p 'conditions.applications.includeApplications' | Where-Object { $_ -in $graphApps }).Count -eq 0) { continue }
        # @( ) around each call: a block hands back one name as a string and none as nothing.
        $includeUsers = @(& $list $p 'conditions.users.includeUsers'); $excludeUsers = @(& $list $p 'conditions.users.excludeUsers')
        $includeRoles = @(& $list $p 'conditions.users.includeRoles'); $excludeRoles = @(& $list $p 'conditions.users.excludeRoles')
        $includeGroups = @(& $list $p 'conditions.users.includeGroups'); $excludeGroups = @(& $list $p 'conditions.users.excludeGroups')
        if ($ObjectId -and $excludeUsers -contains $ObjectId) { continue }
        if (@($excludeRoles | Where-Object { $_ -in $RoleTemplateId }).Count -gt 0) { continue }
        $byUser = $includeUsers -contains 'All' -or ($ObjectId -and $includeUsers -contains $ObjectId)
        $byRole = @($includeRoles | Where-Object { $_ -in $RoleTemplateId }).Count -gt 0
        # Roles are known only from a token; without one, a policy on any role may be the account's.
        $maybe = $includeGroups.Count -gt 0 -or ($includeRoles.Count -gt 0 -and $RoleTemplateId.Count -eq 0)
        if (-not ($byUser -or $byRole -or $maybe)) { continue }
        $certain = ($byUser -or $byRole) -and $excludeGroups.Count -eq 0
        if ($null -eq $best -or $hours -lt $best.hours -or ($hours -eq $best.hours -and $certain -and -not $best.certain)) { $best = @{ hours = $hours; policy = [string](Get-PostureValue $p 'displayName'); certain = $certain } }
    }
    if ($null -eq $best) { return $null }
    $every = $(if ($best.hours -ge 48 -and $best.hours % 24 -eq 0) { "$([int]($best.hours / 24)) days" } elseif ($best.hours -eq 1) { 'hour' } else { "$($best.hours) hours" })
    $then = $(if ($Interactive) { 'When this run outlasts that, it pauses and asks for the sign-in again, then carries on.' } else { 'When this run outlasts that, it stops there, and Resume-PostureRun carries on after a new sign-in.' })
    $best.text = "Sign-in frequency: the Conditional Access policy '$($best.policy)' $(if ($best.certain) { 'asks this account' } else { 'may ask this account' }) to sign in again every $every. $then"
    return $best
}

function Write-PostureSignInFrequencyNotice {
    <#
    .SYNOPSIS
        Says on the console, and in the run's journal, which sign-in frequency applies to the account that is
        collecting, when the Conditional Access snapshot in the folder shows one. Says nothing in the second
        collection process, which the main one renews for, and never stops a collection.
    #>
    [CmdletBinding()]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'One line of what to expect of the sign-in, before the long reads: a user-facing CLI convention.')]
    [OutputType([void])]
    param([Parameter(Mandatory)] [string] $Folder)

    $session = $script:PostureSession
    if ($session -and $session.ContainsKey('tokenPipe') -and $session['tokenPipe']) { return }
    $noticeArgs = @{ Folder = $Folder }
    if ($session) {
        if ($session.ContainsKey('objectId') -and $session['objectId']) { $noticeArgs.ObjectId = [string]$session['objectId'] }
        if ($session.ContainsKey('roleTemplateIds')) { $noticeArgs.RoleTemplateId = @($session['roleTemplateIds']) }
        $noticeArgs.Interactive = [bool]($session.ContainsKey('interactive') -and $session['interactive'] -and (Test-PostureInteractive))
    }
    $notice = $(try { Get-PostureSignInFrequencyNotice @noticeArgs } catch { Write-Verbose "Sign-in frequency not read: $($_.Exception.Message)"; $null })
    if (-not $notice) { return }
    Write-Host $notice.text -ForegroundColor Yellow
    Write-PostureJournal -Folder $Folder -Entry @{ kind = 'run'; state = 'signInFrequency'; hours = $notice.hours; policy = $notice.policy; certain = $notice.certain }
}
