#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    Writes a complete run folder for Fernquill Engineering, a made-up tenant, for screenshots, demos and the end-to-end
    test. Every name, address, id and number is invented; nothing comes from a real tenant.
.DESCRIPTION
    A cloud-only organisation of about 400 people on Microsoft 365 E5 with a Copilot pilot: Intune and Defender on
    Windows, macOS and phones, Exchange Online with Defender for Office 365, SharePoint and Teams, Purview labels and
    DLP. The posture is a believable mix: most of the basics in place, a few real gaps. Azure and Active Directory are
    not part of it (the run says so), so those areas read as not collected.

    The values are fixed (a seeded random generator), so the same report comes out every time. The domain is
    fernquill.example, reserved for examples; fernquilldemo.onmicrosoft.com was checked unregistered on 2026-11-20.
    The Conditional Access policies are the anonymized sample in samples/ca-snapshot, renamed to this tenant.
.PARAMETER Path
    The run folder to write. Created; an existing folder must be empty unless -Force.
.PARAMETER Client
    The client folder to write beside it (profile.json and exceptions.json, as Start-PostureRun's wizard and
    Add-PostureException leave them). Default: client/ inside the run folder.
.PARAMETER AsOf
    The run's date. Sign-ins, expiry dates and ages are relative to it. Default: 2026-11-16 09:00 UTC.
.EXAMPLE
    ./samples/demo/New-PostureDemoRun.ps1 -Path ./out/demo/fernquill
    Invoke-PostureChecks -Evidence ./out/demo/fernquill/evidence -OutputPath ./out/demo/fernquill/logs
    New-PostureReport -Evidence ./out/demo/fernquill -Client ./out/demo/fernquill/client
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Path,
    [string] $Client,
    [datetime] $AsOf = [datetime]::new(2026, 11, 16, 9, 0, 0, [System.DateTimeKind]::Utc),
    [switch] $Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
if ((Test-Path -LiteralPath $root) -and @(Get-ChildItem -LiteralPath $root -Force).Count -and -not $Force) { throw "$root is not empty. Pass -Force to write over it." }
$ev = Join-Path $root 'evidence'
$clientPath = $(if ($Client) { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Client) } else { Join-Path $root 'client' })
foreach ($p in $ev, (Join-Path $root 'logs'), (Join-Path $root 'errors'), $clientPath) { New-Item -ItemType Directory -Path $p -Force | Out-Null }

$tenantId = '0d3e0f9a-7c41-4b6e-9a2d-5f0e1c7b3a01'
$domain = 'fernquill.example'
$initial = 'fernquilldemo.onmicrosoft.com'
$utf8 = [System.Text.UTF8Encoding]::new($false)
$written = [System.Collections.Generic.List[string]]::new()
$rnd = [System.Random]::new(20261116)
function Write-Demo([string] $Name, $Data) {
    [System.IO.File]::WriteAllText((Join-Path $ev "$Name.json"), (ConvertTo-Json -InputObject $Data -Depth 20), $utf8)
    $written.Add("$Name.json")
}
function Get-DemoDate([double] $DaysAgo) { $AsOf.AddDays(-$DaysAgo).ToString('yyyy-MM-ddTHH:mm:ssZ') }
function Get-DemoId([string] $Prefix, [int] $N) { '{0}-{1:x4}-4{2:x3}-8{3:x3}-{4:x12}' -f $Prefix, ($N % 65536), ($N % 4096), (($N * 7) % 4096), ($N * 2654435761 % 281474976710656) }
function Test-DemoChance([double] $P) { $rnd.NextDouble() -lt $P }
function Get-DemoPick([object[]] $From) { $From[$rnd.Next($From.Count)] }

# --- Organisation, domains, licences ---------------------------------------------------------------------------------
Write-Demo '01-organization' @{
    id = $tenantId; displayName = 'Fernquill Engineering'; countryLetterCode = 'US'; tenantType = 'AAD'; createdDateTime = '2019-03-04T15:20:00Z'
    onPremisesSyncEnabled = $null; onPremisesLastSyncDateTime = $null
    verifiedDomains = @(@{ name = $domain; type = 'Managed'; capabilities = 'Email, OfficeCommunicationsOnline'; isDefault = $true; isInitial = $false }, @{ name = $initial; type = 'Managed'; capabilities = 'Email, OfficeCommunicationsOnline'; isDefault = $false; isInitial = $true })
}
Write-Demo '01-domains' @(
    @{ Id = $domain; IsDefault = $true; IsInitial = $false; IsVerified = $true; AuthenticationType = 'Managed'; PasswordValidityPeriodInDays = 2147483647 }
    @{ Id = $initial; IsDefault = $false; IsInitial = $true; IsVerified = $true; AuthenticationType = 'Managed'; PasswordValidityPeriodInDays = 2147483647 }
)
$sku = { param([string] $Part, [int] $Enabled, [int] $Used, [int] $N) @{ id = Get-DemoId '5c0e0000' $N; skuId = Get-DemoId '6d1f0000' $N; skuPartNumber = $Part; appliesTo = 'User'; capabilityStatus = 'Enabled'; consumedUnits = $Used; prepaidUnits = @{ enabled = $Enabled; suspended = 0; warning = 0; lockedOut = 0 }; servicePlans = @() } }
Write-Demo '01-subscribed-skus' @(
    (& $sku 'SPE_E5' 400 384 1)
    (& $sku 'Microsoft_365_Copilot' 40 31 2)
    (& $sku 'POWER_BI_STANDARD' 1000000 22 3)
)
# What was bought, with its state. The Copilot add-on trial ends in twelve days and is on the expiry calendar; the
# old Visio plan was not renewed and is in its grace period (OP-010).
Write-Demo '01-subscriptions' @(
    @{ SkuPartNumber = 'SPE_E5'; SkuId = (Get-DemoId 'f3000000' 1); Status = 'Enabled'; IsTrial = $false; TotalLicenses = 400; CreatedDateTime = Get-DemoDate 700; NextLifecycleDateTime = Get-DemoDate -160 }
    @{ SkuPartNumber = 'Microsoft_365_Copilot'; SkuId = (Get-DemoId 'f3000000' 2); Status = 'Enabled'; IsTrial = $false; TotalLicenses = 40; CreatedDateTime = Get-DemoDate 240; NextLifecycleDateTime = Get-DemoDate -125 }
    @{ SkuPartNumber = 'Microsoft_Teams_Premium'; SkuId = (Get-DemoId 'f3000000' 4); Status = 'Enabled'; IsTrial = $true; TotalLicenses = 25; CreatedDateTime = Get-DemoDate 18; NextLifecycleDateTime = Get-DemoDate -12 }
    @{ SkuPartNumber = 'VISIOCLIENT'; SkuId = (Get-DemoId 'f3000000' 5); Status = 'Warning'; IsTrial = $false; TotalLicenses = 6; CreatedDateTime = Get-DemoDate 1100; NextLifecycleDateTime = Get-DemoDate -19 }
    @{ SkuPartNumber = 'POWER_BI_STANDARD'; SkuId = (Get-DemoId 'f3000000' 3); Status = 'Enabled'; IsTrial = $false; TotalLicenses = 1000000; CreatedDateTime = Get-DemoDate 900; NextLifecycleDateTime = $null }
)
# No federated domain, so no signing certificate to watch.
Write-Demo '01-federation-settings' @()
# What Microsoft had open on the day, and the Message Center posts with a date to act by (OP-011).
Write-Demo '12-service-health' @(@{ Id = 'EX1180456'; Title = 'Some users may see delays receiving external email'; Service = 'Exchange Online'; Feature = 'E-Mail timely delivery'; Classification = 'advisory'; Status = 'serviceDegradation'; StartDateTime = Get-DemoDate 0.4; LastModifiedDateTime = Get-DemoDate 0.1 })
Write-Demo '12-message-center' @(
    @{ Id = 'MC1198342'; Title = 'Retirement of legacy per-user MFA and self-service password reset policies'; Category = 'planForChange'; Severity = 'high'; IsMajorChange = $true; ActionRequiredByDateTime = Get-DemoDate -20; Services = 'Microsoft Entra'; LastModifiedDateTime = Get-DemoDate 12 }
    @{ Id = 'MC1201877'; Title = 'New default for external meeting chat in Microsoft Teams'; Category = 'planForChange'; Severity = 'normal'; IsMajorChange = $false; ActionRequiredByDateTime = Get-DemoDate -75; Services = 'Microsoft Teams'; LastModifiedDateTime = Get-DemoDate 5 }
)
Write-Demo '12-message-center-summary' @{ Posts = 214; MajorChanges = 9; WithActionDate = 2 }
Write-Demo '01-onprem-sync-features' @{ id = $tenantId; configuration = $null; features = @{ passwordSyncEnabled = $false; passwordWritebackEnabled = $false; blockSoftMatchEnabled = $true; blockCloudObjectTakeoverThroughHardMatchEnabled = $true } }
Write-Demo '01-company-branding' @{ Present = $true; HasBannerLogo = $true; HasSquareLogo = $true; HasSignInText = $true }

# --- People ------------------------------------------------------------------------------------------------------------
$first = 'Avery', 'Jordan', 'Riley', 'Morgan', 'Casey', 'Quinn', 'Rowan', 'Sasha', 'Emerson', 'Hayden', 'Kendall', 'Marlowe', 'Parker', 'Reese', 'Sawyer', 'Tatum', 'Blake', 'Dakota', 'Ellis', 'Finley', 'Harper', 'Jules', 'Lennox', 'Noel', 'Oakley', 'Peyton', 'Remy', 'Sage', 'Teagan', 'Wren'
$last = 'Abernathy', 'Bellweather', 'Calloway', 'Draycott', 'Ellsworth', 'Fairbanks', 'Greaves', 'Holloway', 'Ingram', 'Jessup', 'Kettering', 'Lindqvist', 'Marchetti', 'Northcott', 'Okonkwo', 'Pembrook', 'Quintero', 'Rasmussen', 'Silvestri', 'Thornbury', 'Underhill', 'Vasquez', 'Whitlock', 'Yarrow', 'Zielinski'
$departments = 'Engineering', 'Engineering', 'Engineering', 'Projects', 'Projects', 'Field Services', 'Finance', 'Operations', 'Sales', 'People', 'IT'
$titles = @{ Engineering = 'Design Engineer'; Projects = 'Project Manager'; 'Field Services' = 'Field Technician'; Finance = 'Accountant'; Operations = 'Operations Coordinator'; Sales = 'Account Executive'; People = 'People Partner'; IT = 'Systems Engineer' }
$users = [System.Collections.Generic.List[object]]::new()
$newUser = {
    param([string] $Id, [string] $Upn, [string] $Name, [string] $Type, [int] $Licenses, [double] $LastDays, [string] $Dept, [bool] $Enabled = $true)
    [ordered]@{
        Id = $Id; UserPrincipalName = $Upn; DisplayName = $Name; AccountEnabled = $Enabled; UserType = $Type; OnPremisesSyncEnabled = $false
        Mail = $(if ($Type -eq 'Member' -and $Licenses -gt 0) { $Upn } else { $null }); GivenName = $(if ($Dept) { $Name.Split(' ')[0] } else { $null }); Surname = $(if ($Dept) { $Name.Split(' ')[-1] } else { $null })
        CreatedDateTime = Get-DemoDate (200 + $rnd.Next(1800)); Department = $(if ($Dept) { $Dept } else { $null }); JobTitle = $(if ($Dept) { $titles[$Dept] } else { $null })
        CompanyName = $(if ($Type -eq 'Member') { 'Fernquill Engineering' } else { $null }); UsageLocation = 'US'; CreationType = $(if ($Type -eq 'Guest') { 'Invitation' } else { $null })
        ExternalUserState = $(if ($Type -eq 'Guest') { 'Accepted' } else { $null }); LicenseCount = $Licenses
        LastInteractiveSignIn = $(if ($LastDays -ge 0) { Get-DemoDate $LastDays } else { $null }); LastNonInteractiveSignIn = $(if ($LastDays -ge 0) { Get-DemoDate ([math]::Max(0, $LastDays - 1)) } else { $null })
        OnPremisesSecurityIdentifier = $null
    }
}
$users.Add((& $newUser '11111111-1111-1111-1111-111111111111' "breakglass01@$initial" 'BreakGlass-01' 'Member' 0 41 ''))
$users.Add((& $newUser '11111111-1111-1111-1111-111111111112' "breakglass02@$initial" 'BreakGlass-02' 'Member' 0 41 ''))
$admins = @(
    @{ Id = 'a0000000-0000-4000-8000-000000000001'; Upn = "avery.holloway@$domain"; Name = 'Avery Holloway'; Dept = 'IT' }
    @{ Id = 'a0000000-0000-4000-8000-000000000002'; Upn = "jordan.lindqvist@$domain"; Name = 'Jordan Lindqvist'; Dept = 'IT' }
    @{ Id = 'a0000000-0000-4000-8000-000000000003'; Upn = "riley.okonkwo@$domain"; Name = 'Riley Okonkwo'; Dept = 'IT' }
    @{ Id = 'a0000000-0000-4000-8000-000000000004'; Upn = "morgan.fairbanks@$domain"; Name = 'Morgan Fairbanks'; Dept = 'Finance' }
)
foreach ($a in $admins) { $users.Add((& $newUser $a.Id $a.Upn $a.Name 'Member' 2 0.2 $a.Dept)) }
# The named administrators' sign-in names are taken: a generated person of the same name gets a number.
$seen = @{}; foreach ($a in $admins) { $seen[$a.Upn] = $true }
for ($i = 1; $users.Count -lt 386; $i++) {
    $f = Get-DemoPick $first; $l = Get-DemoPick $last
    $upn = "$($f.ToLower()).$($l.ToLower())@$domain"
    if ($seen.ContainsKey($upn)) { $upn = "$($f.ToLower()).$($l.ToLower())$i@$domain" }
    $seen[$upn] = $true
    $lastDays = $(if (Test-DemoChance 0.04) { 120 + $rnd.Next(200) } elseif (Test-DemoChance 0.02) { -1 } else { $rnd.NextDouble() * 9 })
    $enabled = -not (Test-DemoChance 0.015)
    $users.Add((& $newUser (Get-DemoId 'b1000000' $i) $upn "$f $l" 'Member' $(if ($enabled) { 1 } elseif (Test-DemoChance 0.5) { 1 } else { 0 }) $lastDays (Get-DemoPick $departments) $enabled))
}
$guestDomains = 'brightline-partners.example', 'coldharbor-design.example', 'meridian-survey.example', 'gmail.example'
for ($i = 1; $i -le 26; $i++) {
    $f = Get-DemoPick $first; $l = Get-DemoPick $last; $d = Get-DemoPick $guestDomains
    $users.Add((& $newUser (Get-DemoId 'c2000000' $i) "$($f.ToLower()).$($l.ToLower())_$($d.Replace('.', '_'))#EXT#@$initial" "$f $l" 'Guest' 0 $(if ($i -le 7) { 100 + $rnd.Next(300) } elseif ($i -le 9) { -1 } else { $rnd.NextDouble() * 40 }) ''))
}
$members = @($users | Where-Object { $_.UserType -eq 'Member' })
$guests = @($users | Where-Object { $_.UserType -eq 'Guest' })
Write-Demo '06-users' @($users)
Write-Demo '06-users-guests' @($guests)
# Three people outside the named administrators hold a role all the same: one through the admin group, one as
# eligible only, one as someone PIM for Groups lets join the admin group. The collector's admin files include them.
$viaGroup = @($users | Where-Object { $_.Id -eq (Get-DemoId 'b1000000' 1) })[0]
$eligibleOnly = @($users | Where-Object { $_.Id -eq (Get-DemoId 'b1000000' 2) })[0]
$canJoin = @($users | Where-Object { $_.Id -eq (Get-DemoId 'b1000000' 4) })[0]
$alsoHoldRoles = @($viaGroup.Id, $eligibleOnly.Id, $canJoin.Id)
Write-Demo '06-users-admins' @($users | Where-Object { $_.Id -like 'a0000000-*' -or $_.Id -like '11111111-*' -or $_.Id -in $alsoHoldRoles })
Write-Demo '06-users-breakglass-candidates' @($users | Where-Object { $_.Id -like '11111111-*' })
Write-Demo '06-users-summary' @{
    Total = $users.Count; Members = $members.Count; Guests = $guests.Count; Synced = 0; CloudOnlyMembers = $members.Count
    Disabled = @($users | Where-Object { -not $_.AccountEnabled }).Count; DisabledWithLicenses = @($users | Where-Object { -not $_.AccountEnabled -and $_.LicenseCount -gt 0 }).Count
    EnabledInactiveMembers = @($members | Where-Object { $_.AccountEnabled -and $_.LastInteractiveSignIn -and [datetime]$_.LastInteractiveSignIn -lt $AsOf.AddDays(-90) }).Count
    EnabledNeverSignedIn = @($users | Where-Object { $_.AccountEnabled -and -not $_.LastInteractiveSignIn }).Count
    InactiveGuests = @($guests | Where-Object { -not $_.LastInteractiveSignIn -or [datetime]$_.LastInteractiveSignIn -lt $AsOf.AddDays(-90) }).Count
    PendingGuestInvites = 2; SignInActivityAvailable = $true; StaleDays = 90
}

# Roles: two break glass accounts and one standing Global Administrator, the rest eligible in PIM.
$role = { param([string] $Role, [string] $RoleId, [string] $Type, [hashtable] $Who, [string] $PrincipalType = 'user') [ordered]@{ Role = $Role; RoleDefinitionId = $RoleId; AssignmentType = $Type; MemberType = 'Direct'; DirectoryScopeId = '/'; StartDateTime = Get-DemoDate 300; EndDateTime = $null; PrincipalType = $PrincipalType; PrincipalName = $Who.Name; PrincipalUpn = $Who.Upn; PrincipalSynced = $false; PrincipalId = $Who.Id } }
$ga = '62e90394-69f5-4237-9190-012177145e10'
$bg1 = @{ Id = '11111111-1111-1111-1111-111111111111'; Name = 'BreakGlass-01'; Upn = "breakglass01@$initial" }
$bg2 = @{ Id = '11111111-1111-1111-1111-111111111112'; Name = 'BreakGlass-02'; Upn = "breakglass02@$initial" }
$active = @(
    (& $role 'Global Administrator' $ga 'Assigned' $bg1)
    (& $role 'Global Administrator' $ga 'Assigned' $bg2)
    (& $role 'Global Administrator' $ga 'Assigned' $admins[0])
    (& $role 'Exchange Administrator' '29232cdf-9323-42fd-ade2-1d097af3e4de' 'Assigned' $admins[1])
    (& $role 'Billing Administrator' 'b0f54661-2d74-4c50-afa3-1ec803f12efe' 'Assigned' $admins[3])
    (& $role 'Intune Administrator' '3a2c62db-5318-420d-8d74-23affee5d9d5' 'Activated' $admins[2])
    (& $role 'Application Administrator' '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' 'Assigned' @{ Id = 'd4000000-0000-4000-8000-000000000009'; Name = 'Drawing Vault Sync'; Upn = $null } 'servicePrincipal')
    # A role assigned to a group: whoever is in it holds the role, and the assignment names only the group.
    (& $role 'Helpdesk Administrator' '729827e3-9c14-49f7-bb1b-9608f156bbb8' 'Assigned' @{ Id = '22222222-2222-2222-2222-222222222202'; Name = 'Admins-Privileged'; Upn = $null } 'group')
)
Write-Demo '04-role-assignments-active' $active
$eligibleRoles = @(
    (& $role 'Global Administrator' $ga 'Eligible' $admins[1])
    (& $role 'Security Administrator' '194ae4cb-b126-40b2-bd5b-6091b380977d' 'Eligible' $admins[0])
    (& $role 'Security Administrator' '194ae4cb-b126-40b2-bd5b-6091b380977d' 'Eligible' $admins[2])
    (& $role 'Intune Administrator' '3a2c62db-5318-420d-8d74-23affee5d9d5' 'Eligible' $admins[2])
    (& $role 'Conditional Access Administrator' 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' 'Eligible' $admins[0])
    (& $role 'SharePoint Administrator' 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' 'Eligible' $admins[1])
    # Eligible for a role and nothing else: an administrator all the same.
    (& $role 'User Administrator' 'fe930be7-5e62-47db-91af-98c3a49a38b1' 'Eligible' @{ Id = $eligibleOnly.Id; Name = $eligibleOnly.DisplayName; Upn = $eligibleOnly.UserPrincipalName })
)
Write-Demo '04-role-assignments-pim-eligible' $eligibleRoles
Write-Demo '04-role-assignments-summary' @{ source = 'pim'; active = $active.Count; eligible = $eligibleRoles.Count; permanentGlobalAdmins = 3; roleDefinitions = 112 }
# Everyone who holds a role, one row per person and role, as the collector's role holders step writes it: the
# people the assignments name, the members of the group that holds a role, and the people PIM for Groups lets join it.
$asWho = { param($u) @{ Id = $u.Id; Name = $u.DisplayName; Upn = $u.UserPrincipalName } }
$groupPeople = @(
    @{ Who = $admins[2]; Membership = 'Member' }, @{ Who = (& $asWho $viaGroup); Membership = 'Member' }
    @{ Who = $admins[0]; Membership = 'EligibleMember' }, @{ Who = $admins[1]; Membership = 'EligibleMember' }, @{ Who = (& $asWho $canJoin); Membership = 'EligibleMember' }
)
$holderRow = {
    param($Assignment, [hashtable] $Who, [string] $Held, [string] $Membership = '')
    [ordered]@{
        UserId = $Who.Id; UserPrincipalName = $Who.Upn; DisplayName = $Who.Name; AccountEnabled = $true; Synced = $false
        Role = $Assignment.Role; RoleDefinitionId = $Assignment.RoleDefinitionId; DirectoryScopeId = '/'; AssignmentType = $Assignment.AssignmentType
        Held = $Held; GroupId = $(if ($Membership) { $Assignment.PrincipalId }); GroupName = $(if ($Membership) { $Assignment.PrincipalName }); Membership = $Membership
    }
}
$holders = @(foreach ($a in @($active) + @($eligibleRoles)) {
        if ($a.PrincipalType -eq 'user') { & $holderRow $a @{ Id = $a.PrincipalId; Name = $a.PrincipalName; Upn = $a.PrincipalUpn } $(if ($a.AssignmentType -eq 'Eligible') { 'Eligible' } else { 'Direct' }) }
        elseif ($a.PrincipalType -eq 'group') { foreach ($m in $groupPeople) { & $holderRow $a $m.Who $(if ($m.Membership -eq 'Member' -and $a.AssignmentType -ne 'Eligible') { 'Group' } else { 'EligibleGroup' }) $m.Membership } }
    })
Write-Demo '04-role-holders' $holders
$standing = @($holders | Where-Object { $_.Held -in 'Direct', 'Group' } | ForEach-Object { $_.UserPrincipalName } | Sort-Object -Unique)
Write-Demo '04-role-holders-summary' @{
    Holders = @($holders | ForEach-Object { $_.UserPrincipalName } | Sort-Object -Unique).Count
    Direct = @($holders | Where-Object { $_.Held -eq 'Direct' } | ForEach-Object { $_.UserPrincipalName } | Sort-Object -Unique).Count
    ThroughGroup = @($holders | Where-Object { $_.Held -eq 'Group' } | ForEach-Object { $_.UserPrincipalName } | Sort-Object -Unique).Count
    EligibleOnly = @($holders | Where-Object { $_.Held -in 'Eligible', 'EligibleGroup' } | ForEach-Object { $_.UserPrincipalName } | Sort-Object -Unique | Where-Object { $_ -notin $standing }).Count
    GroupsHoldingRoles = 1; GroupsRead = 1; GroupsNotRead = @(); EligibleMembersNotRead = @()
}
Write-Demo '04-pim-role-policies' @(
    @{ Role = 'Global Administrator'; RoleDefinitionId = $ga; PolicyId = 'p-ga'; MaxActivationHours = 4; ActivationExpirationRequired = $true; ActivationMfaRequired = $true; ActivationJustificationRequired = $true; ActivationTicketRequired = $false; ApprovalRequired = $true; EligibleAlertToAdmins = $true; EligibleAlertOtherRecipients = 0; ActiveAlertToAdmins = $true; ActiveAlertOtherRecipients = 0; ActivationAlertToAdmins = $true; ActivationAlertOtherRecipients = 1 }
    @{ Role = 'Privileged Role Administrator'; RoleDefinitionId = 'e8611ab8-c189-46e8-94e1-60213ab1f814'; PolicyId = 'p-pra'; MaxActivationHours = 4; ActivationExpirationRequired = $true; ActivationMfaRequired = $true; ActivationJustificationRequired = $true; ActivationTicketRequired = $false; ApprovalRequired = $true; EligibleAlertToAdmins = $true; EligibleAlertOtherRecipients = 0; ActiveAlertToAdmins = $true; ActiveAlertOtherRecipients = 0; ActivationAlertToAdmins = $true; ActivationAlertOtherRecipients = 1 }
    @{ Role = 'Security Administrator'; RoleDefinitionId = '194ae4cb-b126-40b2-bd5b-6091b380977d'; PolicyId = 'p-sec'; MaxActivationHours = 8; ActivationExpirationRequired = $true; ActivationMfaRequired = $true; ActivationJustificationRequired = $true; ActivationTicketRequired = $false; ApprovalRequired = $false; EligibleAlertToAdmins = $true; EligibleAlertOtherRecipients = 0; ActiveAlertToAdmins = $true; ActiveAlertOtherRecipients = 0; ActivationAlertToAdmins = $true; ActivationAlertOtherRecipients = 1 }
    @{ Role = 'Conditional Access Administrator'; RoleDefinitionId = 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'; PolicyId = 'p-caa'; MaxActivationHours = 8; ActivationExpirationRequired = $true; ActivationMfaRequired = $true; ActivationJustificationRequired = $true; ActivationTicketRequired = $false; ApprovalRequired = $false; EligibleAlertToAdmins = $true; EligibleAlertOtherRecipients = 0; ActiveAlertToAdmins = $true; ActiveAlertOtherRecipients = 0; ActivationAlertToAdmins = $true; ActivationAlertOtherRecipients = 1 }
    @{ Role = 'Intune Administrator'; RoleDefinitionId = '3a2c62db-5318-420d-8d74-23affee5d9d5'; PolicyId = 'p-int'; MaxActivationHours = 10; ActivationExpirationRequired = $true; ActivationMfaRequired = $false; ActivationJustificationRequired = $true; ActivationTicketRequired = $false; ApprovalRequired = $false; EligibleAlertToAdmins = $true; EligibleAlertOtherRecipients = 0; ActiveAlertToAdmins = $true; ActiveAlertOtherRecipients = 0; ActivationAlertToAdmins = $true; ActivationAlertOtherRecipients = 1 }
)

# --- Tenant-wide policies ------------------------------------------------------------------------------------------------
Write-Demo '02-authorization-policy' @{
    id = 'authorizationPolicy'; displayName = 'Authorization Policy'; allowInvitesFrom = 'adminsAndGuestInviters'; allowedToSignUpEmailBasedSubscriptions = $false; allowEmailVerifiedUsersToJoinOrganization = $false
    blockMsolPowerShell = $true; allowUserConsentForRiskyApps = $false; allowedToUseSSPR = $true; guestUserRoleId = '10dae51f-b6af-4016-8d66-8c2a99b929b3'
    defaultUserRolePermissions = @{ allowedToCreateApps = $false; allowedToCreateSecurityGroups = $false; allowedToCreateTenants = $false; allowedToReadOtherUsers = $true; allowedToReadBitlockerKeysForOwnedDevice = $true; permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-low') }
}
Write-Demo '02-security-defaults' @{ id = '00000000-0000-0000-0000-000000000000'; displayName = 'Security Defaults'; isEnabled = $false; controlTypes = @() }
Write-Demo '02-admin-consent-request-policy' @{ isEnabled = $true; notifyReviewers = $true; remindersEnabled = $true; requestDurationInDays = 14; reviewers = @(@{ query = "/users/$($admins[0].Id)"; queryType = 'MicrosoftGraph' }) }
Write-Demo '02-app-management-policy' @{ id = '00000000-0000-0000-0000-000000000000'; displayName = 'Default app management tenant policy'; isEnabled = $false; applicationRestrictions = @{ passwordCredentials = @(); keyCredentials = @() } }
Write-Demo '02-cross-tenant-access-defaults' @{
    id = 'default'; isServiceDefault = $false
    b2bCollaborationInbound = @{ usersAndGroups = @{ accessType = 'allowed'; targets = @(@{ target = 'AllUsers'; targetType = 'user' }) }; applications = @{ accessType = 'allowed'; targets = @(@{ target = 'AllApplications'; targetType = 'application' }) } }
    b2bCollaborationOutbound = @{ usersAndGroups = @{ accessType = 'allowed'; targets = @(@{ target = 'AllUsers'; targetType = 'user' }) }; applications = @{ accessType = 'allowed'; targets = @(@{ target = 'AllApplications'; targetType = 'application' }) } }
    b2bDirectConnectInbound = @{ usersAndGroups = @{ accessType = 'blocked'; targets = @(@{ target = 'AllUsers'; targetType = 'user' }) }; applications = @{ accessType = 'blocked'; targets = @(@{ target = 'AllApplications'; targetType = 'application' }) } }
    inboundTrust = @{ isMfaAccepted = $true; isCompliantDeviceAccepted = $false; isHybridAzureADJoinedDeviceAccepted = $false }
    tenantRestrictions = @{ usersAndGroups = @{ accessType = 'blocked'; targets = @(@{ target = 'AllUsers'; targetType = 'user' }) }; applications = @{ accessType = 'blocked'; targets = @(@{ target = 'AllApplications'; targetType = 'application' }) } }
}
Write-Demo '02-cross-tenant-access-partners' @(@{ tenantId = '7e1c0000-0000-4000-8000-00000000b001'; displayName = 'Brightline Partners'; inboundTrust = @{ isMfaAccepted = $true } })
Write-Demo '02-directory-settings' @(@{ DisplayName = 'Password Rule Settings'; TemplateId = '5cf42378-d67d-4f36-ba46-e8b86229381d'; Values = @{ EnableBannedPasswordCheck = 'True'; BannedPasswordCount = 7; EnableBannedPasswordCheckOnPremises = 'False'; BannedPasswordCheckOnPremisesMode = 'Audit'; LockoutThreshold = '10'; LockoutDurationInSeconds = '60' } },
    @{ DisplayName = 'Consent Policy Settings'; TemplateId = 'dffd5d46-495d-40a9-8e21-954ff55e198a'; Values = @{ EnableGroupSpecificConsent = 'false'; BlockUserConsentForRiskyApps = 'True'; EnableAdminConsentRequests = 'true' } })
Write-Demo '02-group-lifecycle-policy' @{ Present = $true; GroupLifetimeInDays = 365; ManagedGroupTypes = 'All'; AlternateNotificationEmails = "it-team@$domain" }
Write-Demo '02-auth-system-preferred' @{ State = 'enabled'; ReportSuspiciousActivityState = 'enabled'; ReportSuspiciousActivityTarget = 'all_users' }
Write-Demo '02-authentication-strengths' @()
Write-Demo '02-authentication-methods-policy' @{
    policyMigrationState = 'migrationComplete'
    registrationEnforcement = @{ authenticationMethodsRegistrationCampaign = @{ state = 'enabled'; snoozeDurationInDays = 1; includeTargets = @(@{ id = 'all_users'; targetType = 'group'; targetedAuthenticationMethod = 'microsoftAuthenticator' }) } }
    authenticationMethodConfigurations = @(
        @{ id = 'Sms'; state = 'enabled'; includeTargets = @(@{ id = 'all_users'; targetType = 'group' }) }
        @{ id = 'Voice'; state = 'disabled'; includeTargets = @() }
        @{ id = 'Email'; state = 'disabled'; includeTargets = @() }
        @{ id = 'MicrosoftAuthenticator'; state = 'enabled'; isSoftwareOathEnabled = $false; includeTargets = @(@{ id = 'all_users'; targetType = 'group'; authenticationMode = 'any' }); featureSettings = @{ displayAppInformationRequiredState = @{ state = 'enabled' }; displayLocationInformationRequiredState = @{ state = 'enabled' }; numberMatchingRequiredState = @{ state = 'enabled' } } }
        @{ id = 'Fido2'; state = 'enabled'; includeTargets = @(@{ id = 'all_users'; targetType = 'group' }); isAttestationEnforced = $true; isSelfServiceRegistrationAllowed = $true; keyRestrictions = @{ isEnforced = $false; enforcementType = 'block'; aaGuids = @() } }
        @{ id = 'TemporaryAccessPass'; state = 'enabled'; isUsableOnce = $true; defaultLifetimeInMinutes = 60; includeTargets = @(@{ id = 'all_users'; targetType = 'group' }) }
        @{ id = 'X509Certificate'; state = 'disabled'; includeTargets = @() }
        @{ id = 'SoftwareOath'; state = 'enabled'; includeTargets = @(@{ id = 'all_users'; targetType = 'group' }) }
    )
}

# --- Authentication ------------------------------------------------------------------------------------------------------
$registration = foreach ($u in $members) {
    $isAdmin = $u.Id -like 'a0000000-*' -or $u.Id -like '11111111-*'
    $methods = $(
        if ($u.Id -like '11111111-*') { 'fido2' }
        elseif ($isAdmin) { $(if ($u.Id -eq $admins[3].Id) { 'microsoftAuthenticatorPush;mobilePhone' } else { 'passKeyDeviceBound;microsoftAuthenticatorPush' }) }
        elseif (Test-DemoChance 0.03) { '' }
        elseif (Test-DemoChance 0.08) { 'mobilePhone' }
        elseif (Test-DemoChance 0.25) { 'microsoftAuthenticatorPasswordless;microsoftAuthenticatorPush;windowsHelloForBusiness' }
        elseif (Test-DemoChance 0.45) { 'microsoftAuthenticatorPush;softwareOneTimePasscode' }
        else { 'microsoftAuthenticatorPush;windowsHelloForBusiness' })
    [ordered]@{
        UserPrincipalName = $u.UserPrincipalName; UserDisplayName = $u.DisplayName; UserType = 'member'; IsAdmin = $isAdmin
        IsMfaRegistered = [bool]$methods; IsMfaCapable = [bool]$methods; IsPasswordlessCapable = $methods -match 'passKey|fido2|Passwordless|windowsHello'
        IsSsprRegistered = [bool]$methods; IsSsprEnabled = $true; IsSsprCapable = [bool]$methods
        IsSystemPreferredAuthenticationMethodEnabled = $true; SystemPreferredAuthenticationMethods = $(if ($methods -match 'passKey|fido2') { 'Fido2' } elseif ($methods) { 'PushNotification' } else { '' })
        UserPreferredMethodForSecondaryAuthentication = $(if ($methods -match 'microsoftAuthenticator') { 'push' } elseif ($methods) { 'sms' } else { 'none' })
        LastUpdatedDateTime = Get-DemoDate 1; MethodsRegistered = $methods
    }
}
$registration = @($registration)
Write-Demo '05-auth-registration' $registration
$holderUpns = @($holders | ForEach-Object { $_.UserPrincipalName } | Sort-Object -Unique)
Write-Demo '05-auth-registration-admins' @($registration | Where-Object { $_.IsAdmin -or $_.UserPrincipalName -in $holderUpns })
$pct = { param($Rows, [scriptblock] $Test) [math]::Round(100 * @($Rows | Where-Object $Test).Count / [math]::Max(1, @($Rows).Count), 1) }
# What the report reads from the registration list, counted as the collector counts it: no device-bound method is phishable.
$deviceBound = 'fido2', 'passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator', 'passKeyDeviceBoundWindowsHello', 'windowsHelloForBusiness', 'x509Certificate', 'x509CertificateMultiFactor'
$phishableRows = @($registration | Where-Object { @(([string]$_.MethodsRegistered).Split(';') | Where-Object { $_ -in $deviceBound }).Count -eq 0 })
Write-Demo '05-auth-registration-summary' @{
    Tally = [ordered]@{ Users = $registration.Count; SsprEnabled = @($registration | Where-Object IsSsprEnabled).Count; Phishable = $phishableRows.Count; PhishableAdmins = @($phishableRows | Where-Object { $_.IsAdmin -or $_.UserPrincipalName -in $holderUpns }).Count }
    TotalMembers = $registration.Count; Admins = @($registration | Where-Object IsAdmin).Count
    MfaRegisteredPct = & $pct $registration { $_.IsMfaRegistered }; PasswordlessCapablePct = & $pct $registration { $_.IsPasswordlessCapable }; SsprRegisteredPct = & $pct $registration { $_.IsSsprRegistered }
    AdminsNotPasswordless = @($registration | Where-Object { $_.IsAdmin -and -not $_.IsPasswordlessCapable }).Count; AdminsNoMfa = 0
    UsersWithSms = @($registration | Where-Object { $_.MethodsRegistered -match 'mobilePhone' }).Count
    UsersWithPasskeyOrFido = @($registration | Where-Object { $_.MethodsRegistered -match 'passKey|fido2' }).Count
    UsersWithWhfb = @($registration | Where-Object { $_.MethodsRegistered -match 'windowsHello' }).Count
    StrongestMethod = @{
        PhishingResistant = @($registration | Where-Object { $_.MethodsRegistered -match 'passKey|fido2|windowsHello' }).Count
        Passwordless = @($registration | Where-Object { $_.MethodsRegistered -match 'Passwordless' -and $_.MethodsRegistered -notmatch 'passKey|fido2|windowsHello' }).Count
        Authenticator = @($registration | Where-Object { $_.MethodsRegistered -match 'microsoftAuthenticatorPush' -and $_.MethodsRegistered -notmatch 'passKey|fido2|windowsHello|Passwordless' }).Count
        PhoneOnly = @($registration | Where-Object { $_.MethodsRegistered -eq 'mobilePhone' }).Count
        None = @($registration | Where-Object { -not $_.MethodsRegistered }).Count
    }
}
Write-Demo '05-per-user-mfa-summary' @{ Users = $members.Count; Members = $members.Count; Mode = 'all'; SampleSize = $members.Count; Enforced = 0; Enabled = 0; Disabled = $members.Count; Errors = 0; FirstError = $null }
Write-Demo '05-per-user-mfa' @($members | Select-Object -First 25 | ForEach-Object { @{ UserPrincipalName = $_.UserPrincipalName; Status = 200; PerUserMfaState = 'disabled' } })

# Sign-ins, last 7 days.
$byDay = [ordered]@{}; for ($d = 6; $d -ge 0; $d--) { $day = $AsOf.AddDays(-$d); $byDay[$day.ToString('MM/dd/yyyy')] = $(if ($day.DayOfWeek -in 'Saturday', 'Sunday') { 1400 + $rnd.Next(500) } else { 9800 + $rnd.Next(2200) }) }
$total = ($byDay.Values | Measure-Object -Sum).Sum
Write-Demo '06-signins-summary' @{
    WindowStartUtc = Get-DemoDate 7; WindowEndUtc = Get-DemoDate 0; Days = 7; SignIns = $total; Interactive = [int]($total * 0.18); Failures = [int]($total * 0.021); MfaRequired = [int]($total * 0.09); Risky = 6
    LegacySignIns = 0; LegacyUsers = 0; Pages = 12
    ByClientApp = [ordered]@{ Browser = [int]($total * 0.41); 'Mobile Apps and Desktop clients' = [int]($total * 0.59) }
    ByConditionalAccessStatus = [ordered]@{ success = [int]($total * 0.93); notApplied = [int]($total * 0.05); failure = [int]($total * 0.02) }
    ByDay = $byDay; ByCountry = [ordered]@{ US = [int]($total * 0.96); CA = [int]($total * 0.025); GB = [int]($total * 0.01); NG = 31; RU = 12 }
    FailuresByErrorCode = [ordered]@{ '50126' = 188; '50074' = 140; '53003' = 37; '50140' = 92; '50053' = 9 }
    ReportOnlyPolicies = @('CA-004-Guests-Require MFA and limit apps', 'Sign-in risk: require MFA (report-only pilot)')
    AdminSignIns = @($admins | ForEach-Object { @{ UserPrincipalName = $_.Upn; SignIns = 40 + $rnd.Next(60); SingleFactor = 0; Failures = $rnd.Next(3); LastSignIn = Get-DemoDate 0.3 } })
    SprayAddresses = @(); SprayTrackingCapped = $false
}
Write-Demo '06-signins-legacy-users' @()
Write-Demo '11-risky-users' @(
    @{ UserPrincipalName = $members[40].UserPrincipalName; RiskLevel = 'medium'; RiskState = 'atRisk'; RiskLastUpdatedDateTime = Get-DemoDate 3 }
    @{ UserPrincipalName = $members[95].UserPrincipalName; RiskLevel = 'low'; RiskState = 'remediated'; RiskLastUpdatedDateTime = Get-DemoDate 30 }
)
Write-Demo '11-risk-detections-30d' @(@{ RiskEventType = 'unfamiliarFeatures'; RiskLevel = 'medium'; DetectedDateTime = Get-DemoDate 3; UserPrincipalName = $members[40].UserPrincipalName })

# --- Groups and apps ---------------------------------------------------------------------------------------------------------
$groups = [System.Collections.Generic.List[object]]::new()
$group = { param([string] $Id, [string] $Name, [string] $Kind, [bool] $Dynamic = $false, [bool] $RoleAssignable = $false, [string] $Visibility = $null, [int] $Licensed = 0) [ordered]@{ Id = $Id; DisplayName = $Name; OnPremisesSyncEnabled = $false; CreatedDateTime = Get-DemoDate (100 + $rnd.Next(1200)); Visibility = $Visibility; IsAssignableToRole = $RoleAssignable; ExpirationDateTime = $null; MembershipRule = $(if ($Dynamic) { '(user.department -ne null)' } else { $null }); Kind = $Kind; Dynamic = $Dynamic; Licensed = $Licensed } }
$groups.Add((& $group '22222222-2222-2222-2222-222222222201' 'CA-Exclude-BreakGlass' 'Security' $false $true))
$groups.Add((& $group '22222222-2222-2222-2222-222222222202' 'Admins-Privileged' 'Security' $false $true))
$groups.Add((& $group '22222222-2222-2222-2222-222222222203' 'All Staff' 'Security' $true $false $null 1))
$groups.Add((& $group '22222222-2222-2222-2222-222222222299' 'Copilot Pilot' 'Security' $false $false $null 1))
$projects = 'Riverside Bridge', 'Harbor Terminal', 'North Campus', 'Water Treatment Upgrade', 'Transit Depot', 'Library Retrofit', 'Solar Field', 'Hospital Wing', 'Rail Crossing', 'Data Center'
$n = 0
foreach ($p in $projects) { $n++; $groups.Add((& $group (Get-DemoId 'e5000000' $n) "Project - $p" 'Microsoft 365' $false $false $(if ($n -le 8) { 'Private' } else { 'Public' }))) }
foreach ($d in 'Engineering', 'Projects', 'Field Services', 'Finance', 'Operations', 'Sales', 'People', 'IT') { $n++; $groups.Add((& $group (Get-DemoId 'e5000000' $n) $d 'Microsoft 365' $true $false 'Private')) }
foreach ($d in 'Intune - Windows', 'Intune - macOS', 'Intune - Phones', 'Printers', 'VPN Users') { $n++; $groups.Add((& $group (Get-DemoId 'e5000000' $n) $d 'Security' ($d -like 'Intune*'))) }
Write-Demo '07-groups' @($groups)
$byKind = [ordered]@{}; foreach ($x in $groups) { $byKind[[string]$x.Kind] = 1 + $(if ($byKind.Contains([string]$x.Kind)) { $byKind[[string]$x.Kind] } else { 0 }) }
Write-Demo '07-groups-summary' @{ Groups = $groups.Count; ByKind = $byKind; RoleAssignable = @($groups | Where-Object { $_.IsAssignableToRole }).Count; Synced = @($groups | Where-Object { $_.OnPremisesSyncEnabled }).Count; Licensed = @($groups | Where-Object { $_.Licensed }).Count; Dynamic = @($groups | Where-Object { $_.Dynamic }).Count }
Write-Demo '07-groups-ownerless' @(@{ Id = (Get-DemoId 'e5000000' 9); DisplayName = 'Project - Rail Crossing'; Kind = 'Microsoft 365'; CreatedDateTime = Get-DemoDate 640 }, @{ Id = (Get-DemoId 'e5000000' 10); DisplayName = 'Project - Data Center'; Kind = 'Microsoft 365'; CreatedDateTime = Get-DemoDate 410 })
Write-Demo '07-groups-ownerless-summary' @{ UnifiedGroups = 18; Ownerless = 2 }

Write-Demo '10-app-registrations' @(
    @{ Id = (Get-DemoId 'f6000000' 1); AppId = (Get-DemoId 'f7000000' 1); DisplayName = 'Drawing Vault Sync'; SignInAudience = 'AzureADMyOrg'; PublisherDomain = $domain; CreatedDateTime = Get-DemoDate 900; Secrets = 1; Certs = 0; EarliestExpiry = Get-DemoDate -19; ExpiredCredentials = 0 }
    @{ Id = (Get-DemoId 'f6000000' 2); AppId = (Get-DemoId 'f7000000' 2); DisplayName = 'Timesheet Export'; SignInAudience = 'AzureADMyOrg'; PublisherDomain = $domain; CreatedDateTime = Get-DemoDate 1200; Secrets = 2; Certs = 0; EarliestExpiry = Get-DemoDate 60; ExpiredCredentials = 1 }
    @{ Id = (Get-DemoId 'f6000000' 3); AppId = (Get-DemoId 'f7000000' 3); DisplayName = 'Intranet Search'; SignInAudience = 'AzureADMyOrg'; PublisherDomain = $domain; CreatedDateTime = Get-DemoDate 400; Secrets = 0; Certs = 1; EarliestExpiry = Get-DemoDate -280; ExpiredCredentials = 0 }
    @{ Id = (Get-DemoId 'f6000000' 4); AppId = (Get-DemoId 'f7000000' 4); DisplayName = 'Plotter Gateway'; SignInAudience = 'AzureADMyOrg'; PublisherDomain = $domain; CreatedDateTime = Get-DemoDate 600; Secrets = 0; Certs = 1; EarliestExpiry = Get-DemoDate -500; ExpiredCredentials = 0 }
)
# The id of a demo service principal, from its application id: the grants below and the service principal list agree on it.
$spId = { param([string] $AppId) [guid]::new(([System.Security.Cryptography.MD5]::HashData([System.Text.Encoding]::UTF8.GetBytes("sp$AppId")))).ToString() }
Write-Demo '10-graph-app-permissions' @(
    @{ PrincipalDisplayName = 'Drawing Vault Sync'; PrincipalId = (& $spId (Get-DemoId 'f7000000' 1)); PrincipalType = 'ServicePrincipal'; Permission = 'Sites.ReadWrite.All'; CreatedDateTime = Get-DemoDate 900 }
    @{ PrincipalDisplayName = 'Timesheet Export'; PrincipalId = (& $spId (Get-DemoId 'f7000000' 2)); PrincipalType = 'ServicePrincipal'; Permission = 'User.Read.All'; CreatedDateTime = Get-DemoDate 1200 }
    @{ PrincipalDisplayName = 'Mailbox Archiver'; PrincipalId = (& $spId (Get-DemoId 'f7000000' 5)); PrincipalType = 'ServicePrincipal'; Permission = 'Mail.ReadWrite'; CreatedDateTime = Get-DemoDate 700 }
)
# When each application last signed in. Timesheet Export stopped in the spring, and Mailbox Archiver has no sign-in
# on record at all: both still hold their Graph permissions (ID-024).
Write-Demo '10-app-signin-activity' @(
    @{ AppId = (Get-DemoId 'f7000000' 1); LastSignIn = Get-DemoDate 0.3 }
    @{ AppId = (Get-DemoId 'f7000000' 2); LastSignIn = Get-DemoDate 212 }
    @{ AppId = (Get-DemoId 'f7000000' 3); LastSignIn = Get-DemoDate 2 }
    @{ AppId = (Get-DemoId 'f7000000' 4); LastSignIn = Get-DemoDate 1 }
)
$sp = { param([string] $AppId, [string] $Name, [bool] $HomeApp = $false, [bool] $Assignment = $false, [bool] $Enabled = $true) [ordered]@{ Id = [guid]::new(([System.Security.Cryptography.MD5]::HashData([System.Text.Encoding]::UTF8.GetBytes("sp$AppId")))).ToString(); AppId = $AppId; DisplayName = $Name; AccountEnabled = $Enabled; ServicePrincipalType = 'Application'; AppOwnerOrganizationId = $(if ($HomeApp) { $tenantId } else { 'f8cdef31-a31e-4b4a-93e4-5f571e91255a' }); PreferredSingleSignOnMode = $null; SignInAudience = $(if ($HomeApp) { 'AzureADMyOrg' } else { 'AzureADMultipleOrgs' }); AppRoleAssignmentRequired = $Assignment; CreatedDateTime = Get-DemoDate 800; HomeTenantApp = $HomeApp; IsEnterpriseAppListed = $true; SamlCertExpiry = $null; HasExpiredCreds = $false; OwnerCount = $(if ($HomeApp) { 1 } else { 0 }) } }
Write-Demo '10-service-principals' @(
    (& $sp '14d82eec-204b-4c2f-b7e8-296a70dab67e' 'Microsoft Graph Command Line Tools' $false $true)
    (& $sp 'de8bc8b5-d9f9-48b1-a8ad-b748da725064' 'Graph Explorer' $false $true)
    (& $sp '04b07795-8ddb-461a-bbee-02f9e1bf7b46' 'Microsoft Azure CLI' $false $false)
    (& $sp '1950a258-227b-4e31-a9cf-717495945fc2' 'Microsoft Azure PowerShell' $false $false)
    (& $sp 'fb78d390-0c51-40cd-8e17-fdbfab77341b' 'Microsoft Exchange REST API Based Powershell' $false $true)
    (& $sp '9bc3ab49-b65d-410a-85ad-de819febfddc' 'Microsoft SharePoint Online Management Shell' $false $true)
    (& $sp '12128f48-ec9e-42f0-b203-ea49fb6af367' 'MS Teams Powershell Cmdlets' $false $true)
    (& $sp (Get-DemoId 'f7000000' 1) 'Drawing Vault Sync' $true $false)
    (& $sp (Get-DemoId 'f7000000' 2) 'Timesheet Export' $true $false)
    (& $sp (Get-DemoId 'f7000000' 3) 'Intranet Search' $true $true)
    (& $sp (Get-DemoId 'f7000000' 4) 'Plotter Gateway' $true $true)
    (& $sp (Get-DemoId 'f7000000' 5) 'Mailbox Archiver' $true $false)
)
Write-Demo '10-oauth2-delegated-grants' @(@{ ClientId = 'd4000000-0000-4000-8000-000000000020'; ConsentType = 'AllPrincipals'; PrincipalId = $null; ResourceId = 'd4000000-0000-4000-8000-000000000030'; Scope = 'User.Read offline_access openid profile' })

# --- Conditional Access: the anonymized sample, renamed to this tenant ------------------------------------------------------
$ca = Join-Path $PSScriptRoot '..' 'ca-snapshot'
foreach ($f in 'policies', 'named-locations', 'auth-strengths', 'auth-context', 'group-scope', 'resolved-names') {
    $text = (Get-Content -Raw -LiteralPath (Join-Path $ca "$f.json")).Replace('contoso.example', $domain)
    [System.IO.File]::WriteAllText((Join-Path $ev "$f.json"), $text, $utf8); $written.Add("$f.json")
}
$meta = Get-Content -Raw -LiteralPath (Join-Path $ca 'metadata.json') | ConvertFrom-Json -AsHashtable
$meta['tenantId'] = $tenantId; $meta['account'] = "posture-run@$domain"; $meta['timestampUtc'] = $AsOf.ToString('o')
Write-Demo 'metadata' $meta

# --- Devices -------------------------------------------------------------------------------------------------------------------
$fleet = [System.Collections.Generic.List[object]]::new()
$people = @($members | Where-Object { $_.AccountEnabled -and $_.Id -notlike '11111111-*' })
$build = @('10.0.26100.6899', '10.0.26100.6899', '10.0.26100.6899', '10.0.26100.6584', '10.0.22631.6060')
for ($i = 1; $i -le 296; $i++) {
    $os = $(if ($i -le 228) { 'Windows' } elseif ($i -le 252) { 'macOS' } elseif ($i -le 290) { 'iOS' } else { 'Android' })
    $owner = $people[$i % $people.Count]
    $compliant = $(if ($os -eq 'Windows') { -not (Test-DemoChance 0.06) } elseif ($os -eq 'macOS') { -not (Test-DemoChance 0.12) } else { -not (Test-DemoChance 0.04) })
    $name = $(switch ($os) { 'Windows' { 'FQ-{0}' -f ('{0:X6}' -f (1048576 + $i * 7919)) } 'macOS' { "FQ-MAC-$('{0:D3}' -f $i)" } 'iOS' { "iPhone-$('{0:D3}' -f $i)" } default { "Android-$('{0:D3}' -f $i)" } })
    $fleet.Add([ordered]@{
            Id = Get-DemoId '9a000000' $i; DeviceName = $name; UserPrincipalName = $owner.UserPrincipalName; OperatingSystem = $os
            OSVersion = $(switch ($os) { 'Windows' { Get-DemoPick $build } 'macOS' { Get-DemoPick @('26.1', '26.1', '15.7.2') } 'iOS' { Get-DemoPick @('26.1', '26.0.1', '18.7.2') } default { '16' } })
            SkuFamily = $(if ($os -eq 'Windows') { 'Enterprise' } else { '' }); ComplianceState = $(if ($compliant) { 'compliant' } elseif (Test-DemoChance 0.3) { 'inGracePeriod' } else { 'noncompliant' })
            ManagementAgent = 'mdm'; JoinType = $(if ($os -eq 'Windows') { 'azureADJoined' } else { '' }); DeviceEnrollmentType = $(switch ($os) { 'Windows' { 'windowsAzureADJoin' } 'macOS' { 'appleBulkWithUser' } 'iOS' { 'appleBulkWithUser' } default { 'androidEnterpriseFullyManaged' } })
            ManagedDeviceOwnerType = 'company'; AutopilotEnrolled = ($os -eq 'Windows' -and $i -gt 12); IsEncrypted = ($compliant -or $os -ne 'Windows'); IsSupervised = ($os -eq 'iOS')
            LastSyncDateTime = Get-DemoDate ($rnd.NextDouble() * $(if ($i % 41 -eq 0) { 60 } else { 3 })); EnrolledDateTime = Get-DemoDate (30 + $rnd.Next(900))
            Manufacturer = $(switch ($os) { 'Windows' { Get-DemoPick @('Dell Inc.', 'Dell Inc.', 'Lenovo', 'Microsoft Corporation') } 'Android' { 'Samsung' } default { 'Apple' } })
            Model = $(switch ($os) { 'Windows' { Get-DemoPick @('Precision 3591', 'Latitude 7450', 'ThinkPad P16s', 'Surface Laptop 7') } 'macOS' { 'MacBook Pro (14-inch, 2024)' } 'iOS' { 'iPhone 16' } default { 'Galaxy XCover7' } })
            SerialNumber = 'FQ{0:D8}' -f ($i * 104729 % 100000000); AzureAdDeviceId = Get-DemoId '9b000000' $i; IntuneWorkloads = ''
        })
}
Write-Demo '09-intune-managed-devices' @($fleet)
Write-Demo '09-intune-summary-compliance' @($fleet | Group-Object ComplianceState | ForEach-Object { @{ Name = $_.Name; Count = $_.Count } })
Write-Demo '09-intune-summary-windows-builds' @($fleet | Where-Object OperatingSystem -eq 'Windows' | Group-Object OSVersion | ForEach-Object { @{ Name = $_.Name; Count = $_.Count } })
Write-Demo '09-intune-summary-os-agent-join' @($fleet | Group-Object OperatingSystem | ForEach-Object { @{ Name = $_.Name; Count = $_.Count } })
$entraDevices = @($fleet | ForEach-Object {
        [ordered]@{ Id = Get-DemoId '9c000000' ([array]::IndexOf($fleet.ToArray(), $_) + 1); DeviceId = $_.AzureAdDeviceId; DisplayName = $_.DeviceName; OperatingSystem = $_.OperatingSystem; OperatingSystemVersion = $_.OSVersion; AccountEnabled = $true
            IsCompliant = ($_.ComplianceState -eq 'compliant'); IsManaged = $true; ApproximateLastSignInDateTime = $_.LastSyncDateTime; RegistrationDateTime = $_.EnrolledDateTime; ProfileType = 'RegisteredDevice'; ManagementType = 'MDM'
            EnrollmentType = $_.DeviceEnrollmentType; TrustType = $(if ($_.OperatingSystem -eq 'Windows') { 'AzureAd' } else { 'Workplace' }); JoinType = $(if ($_.OperatingSystem -eq 'Windows') { 'EntraJoined' } else { 'Registered' }); Stale = ([datetime]$_.LastSyncDateTime -lt $AsOf.AddDays(-45))
        }
    })
$entraDevices += @(1..9 | ForEach-Object { [ordered]@{ Id = Get-DemoId '9d000000' $_; DeviceId = Get-DemoId '9e000000' $_; DisplayName = "DESKTOP-$('{0:X5}' -f (40000 + $_ * 131))"; OperatingSystem = 'Windows'; OperatingSystemVersion = '10.0.19045.6456'; AccountEnabled = $true; IsCompliant = $null; IsManaged = $false; ApproximateLastSignInDateTime = Get-DemoDate (100 + $_ * 20); RegistrationDateTime = Get-DemoDate 900; ProfileType = 'RegisteredDevice'; ManagementType = $null; EnrollmentType = $null; TrustType = 'Workplace'; JoinType = 'Registered'; Stale = $true } })
Write-Demo '08-entra-devices' $entraDevices
Write-Demo '08-entra-devices-stale' @($entraDevices | Where-Object Stale)
Write-Demo '08-entra-devices-by-join-os' @($entraDevices | Group-Object { "$($_.JoinType) / $($_.OperatingSystem)" } | ForEach-Object { @{ Name = $_.Name; Count = $_.Count } })
Write-Demo '08-bitlocker-keys-by-device' @($fleet | Where-Object { $_.OperatingSystem -eq 'Windows' -and $_.IsEncrypted } | ForEach-Object { @{ DeviceId = $_.AzureAdDeviceId; DeviceName = $_.DeviceName; Keys = 1 } })
Write-Demo '08-bitlocker-keys-summary' @{ WindowsDevices = 228; WithKey = @($fleet | Where-Object { $_.OperatingSystem -eq 'Windows' -and $_.IsEncrypted }).Count }
Write-Demo '09-autopilot-devices' @($fleet | Where-Object AutopilotEnrolled | ForEach-Object { @{ SerialNumber = $_.SerialNumber; Manufacturer = $_.Manufacturer; Model = $_.Model; GroupTag = 'Standard'; EnrollmentState = 'enrolled'; LastContactedDateTime = $_.LastSyncDateTime; DeploymentProfileAssignmentStatus = 'assignedUnkownSyncState'; ManagedDeviceId = $_.Id; AzureActiveDirectoryDeviceId = $_.AzureAdDeviceId } })
Write-Demo '09-autopilot-profiles' @(@{ DisplayName = 'Fernquill Standard'; DeviceNameTemplate = 'FQ-%RAND:6%'; Assignments = 1 })
Write-Demo '09-apple-push-cert' @{ Present = $true; AppleIdentifier = "it-apple@$domain"; ExpirationDateTime = Get-DemoDate -24; LastModifiedDateTime = Get-DemoDate 341; TopicIdentifier = 'com.apple.mgmt.External.0d3e0f9a' }
Write-Demo '09-apple-vpp-tokens' @(@{ DisplayName = 'Fernquill Apps'; OrganizationName = 'Fernquill Engineering'; State = 'valid'; ExpirationDateTime = Get-DemoDate -190; LastSyncStatus = 'completed'; LastSyncDateTime = Get-DemoDate 0.5 })
Write-Demo '09-apple-ade-tokens' @(@{ TokenName = 'Fernquill Apple Business Manager'; AppleIdentifier = "it-apple@$domain"; TokenType = 'dep'; TokenExpirationDateTime = Get-DemoDate -75; LastSuccessfulSyncDateTime = Get-DemoDate 0.4; LastSyncErrorCode = 0 })
# Two certificate connectors: the second has not been heard from for twelve days (DEV-024).
Write-Demo '09-certificate-connectors' @(
    @{ DisplayName = 'Certificate Connector'; MachineName = 'FQ-PKI01'; State = 'active'; LastConnectionDateTime = Get-DemoDate 0.01; DaysSinceLastConnection = 0; EnrolledDateTime = Get-DemoDate 500; ConnectorVersion = '6.2406.0.1001' }
    @{ DisplayName = 'Certificate Connector'; MachineName = 'FQ-PKI02'; State = 'inactive'; LastConnectionDateTime = Get-DemoDate 12; DaysSinceLastConnection = 12; EnrolledDateTime = Get-DemoDate 500; ConnectorVersion = '6.2301.1.0' }
)
# Intune's own roles: the help desk has Help Desk Operator over every device and user (DEV-026), the Mac team is
# scoped to its group. No multi-admin approval policy yet (DEV-025).
Write-Demo '09-intune-role-assignments' @(
    @{ Id = 'ra-helpdesk'; DisplayName = 'Help desk'; RoleName = 'Help Desk Operator'; RoleBuiltIn = $true; ScopeType = 'allDevicesAndLicensedUsers'; MemberGroups = 1; ScopeGroups = 0 }
    @{ Id = 'ra-mac'; DisplayName = 'Mac team'; RoleName = 'Policy and Profile manager'; RoleBuiltIn = $true; ScopeType = 'resourceScope'; MemberGroups = 1; ScopeGroups = 1 }
    @{ Id = 'ra-audit'; DisplayName = 'Auditors'; RoleName = 'Read Only Operator'; RoleBuiltIn = $true; ScopeType = 'allDevicesAndLicensedUsers'; MemberGroups = 1; ScopeGroups = 0 }
)
Write-Demo '09-intune-scope-tags' @(@{ Id = '0'; DisplayName = 'Default'; IsBuiltIn = $true }, @{ Id = '1'; DisplayName = 'Mac'; IsBuiltIn = $false })
Write-Demo '09-intune-approval-policies' @()
Write-Demo '09-intune-mde-connector' @{ Id = 'fc780465-2017-40d4-a0c5-307022471b92'; PartnerState = 'enabled'; LastHeartbeatDateTime = Get-DemoDate 0.1; WindowsDeviceBlockedOnMissingPartnerData = $false; WindowsEnabled = $true; MacEnabled = $true; LinuxEnabled = $null; IosEnabled = $true; AndroidEnabled = $true; MicrosoftDefenderForEndpointAttachEnabled = $false }
Write-Demo '09-intune-device-cleanup' @{ Enabled = $true; DeviceInactivityBeforeRetirementInDays = 90; Rules = @(@{ Id = 'r1'; DisplayName = 'All platforms'; PlatformType = 'all'; DeviceInactivityBeforeRetirementInDays = 90 }) }
Write-Demo '09-intune-settings' @{ SecureByDefault = $true }
Write-Demo '09-intune-comanagement' @{ CoManagedDevices = 0; Workloads = @() }
Write-Demo '09-intune-compliance-partners' @()
Write-Demo '09-intune-device-management-partners' @()
Write-Demo '09-intune-gpo-analytics' @()
Write-Demo '09-intune-windows-hello' @{ Present = $true; State = 'enabled' }
$restriction = { param([string] $Name, [string] $Type, [int] $Priority, [bool] $PersonalBlocked) [ordered]@{ Id = $Name; DisplayName = $Name; Type = $Type; Priority = $Priority; Assignments = 1; windowsPlatformBlocked = $false; windowsPersonalBlocked = $PersonalBlocked; macOSPlatformBlocked = $false; macOSPersonalBlocked = $PersonalBlocked; iosPlatformBlocked = $false; iosPersonalBlocked = $false; androidPlatformBlocked = $true; androidPersonalBlocked = $true; androidForWorkPlatformBlocked = $false; androidForWorkPersonalBlocked = $true } }
Write-Demo '09-intune-enrollment-restrictions' @((& $restriction 'All users and all devices' 'deviceEnrollmentPlatformRestrictionsConfiguration' 0 $true), @{ Id = 'limit'; DisplayName = 'Device limit'; Type = 'deviceEnrollmentLimitConfiguration'; Priority = 0; Assignments = 1; Limit = 5 }, @{ Id = 'esp'; DisplayName = 'Enrollment Status Page'; Type = 'windows10EnrollmentCompletionPageConfiguration'; Priority = 1; Assignments = 1; ShowInstallationProgress = $true })
Write-Demo '09-intune-compliance-policies' @(
    @{ Id = 'cp-win'; DisplayName = 'Windows - Baseline compliance'; Type = 'windows10CompliancePolicy'; CreatedDateTime = Get-DemoDate 700; LastModifiedDateTime = Get-DemoDate 40; Version = 7; Assignments = 1; DeviceThreatProtectionEnabled = $true; DeviceThreatProtectionRequiredSecurityLevel = 'medium' }
    @{ Id = 'cp-mac'; DisplayName = 'macOS - Baseline compliance'; Type = 'macOSCompliancePolicy'; CreatedDateTime = Get-DemoDate 600; LastModifiedDateTime = Get-DemoDate 80; Version = 3; Assignments = 1; DeviceThreatProtectionEnabled = $true; DeviceThreatProtectionRequiredSecurityLevel = 'medium' }
    @{ Id = 'cp-ios'; DisplayName = 'iOS - Baseline compliance'; Type = 'iosCompliancePolicy'; CreatedDateTime = Get-DemoDate 600; LastModifiedDateTime = Get-DemoDate 80; Version = 4; Assignments = 1; DeviceThreatProtectionEnabled = $true; DeviceThreatProtectionRequiredSecurityLevel = 'low' }
    @{ Id = 'cp-and'; DisplayName = 'Android - Fully managed'; Type = 'androidDeviceOwnerCompliancePolicy'; CreatedDateTime = Get-DemoDate 500; LastModifiedDateTime = Get-DemoDate 120; Version = 2; Assignments = 1; DeviceThreatProtectionEnabled = $false; DeviceThreatProtectionRequiredSecurityLevel = 'unavailable' }
)
$cps = { param([string] $Id, [string] $Name, [string] $Type, [hashtable] $Settings) foreach ($k in $Settings.Keys) { [ordered]@{ PolicyId = $Id; PolicyName = $Name; Type = $Type; Setting = $k; Value = $Settings[$k] } } }
Write-Demo '09-intune-compliance-policy-settings' @(
    (& $cps 'cp-win' 'Windows - Baseline compliance' 'windows10CompliancePolicy' @{ bitLockerEnabled = $true; secureBootEnabled = $true; codeIntegrityEnabled = $true; tpmRequired = $true; defenderEnabled = $true; antivirusRequired = $true; deviceThreatProtectionEnabled = $true; deviceThreatProtectionRequiredSecurityLevel = 'medium'; osMinimumVersion = '10.0.22631' })
    (& $cps 'cp-mac' 'macOS - Baseline compliance' 'macOSCompliancePolicy' @{ systemIntegrityProtectionEnabled = $true; storageRequireEncryption = $true; firewallEnabled = $true; gatekeeperAllowedAppSource = 'macAppStoreAndIdentifiedDevelopers'; osMinimumVersion = '15.0' })
    (& $cps 'cp-ios' 'iOS - Baseline compliance' 'iosCompliancePolicy' @{ securityBlockJailbrokenDevices = $true; passcodeRequired = $true; osMinimumVersion = '18.0'; deviceThreatProtectionEnabled = $true })
    (& $cps 'cp-and' 'Android - Fully managed' 'androidDeviceOwnerCompliancePolicy' @{ securityBlockJailbrokenDevices = $true; passwordRequired = $true; storageRequireEncryption = $true })
)
Write-Demo '09-intune-config-profile-settings' @(
    @{ PolicyId = 'ring-broad'; PolicyName = 'Update ring - Broad'; Type = 'windowsUpdateForBusinessConfiguration'; Setting = 'deadlineForQualityUpdatesInDays'; Value = 3 }
    @{ PolicyId = 'ring-broad'; PolicyName = 'Update ring - Broad'; Type = 'windowsUpdateForBusinessConfiguration'; Setting = 'deadlineForFeatureUpdatesInDays'; Value = 7 }
    @{ PolicyId = 'ring-broad'; PolicyName = 'Update ring - Broad'; Type = 'windowsUpdateForBusinessConfiguration'; Setting = 'deadlineGracePeriodInDays'; Value = 1 }
    @{ PolicyId = 'ring-pilot'; PolicyName = 'Update ring - Pilot'; Type = 'windowsUpdateForBusinessConfiguration'; Setting = 'deadlineForQualityUpdatesInDays'; Value = 2 }
    @{ PolicyId = 'ring-pilot'; PolicyName = 'Update ring - Pilot'; Type = 'windowsUpdateForBusinessConfiguration'; Setting = 'deadlineGracePeriodInDays'; Value = 1 }
)
Write-Demo '09-intune-feature-update-profiles' @(@{ Id = 'fu-25h2'; DisplayName = 'Windows 11 25H2'; FeatureUpdateVersion = 'Windows 11, version 25H2'; EndOfSupportDate = '2028-10-10T00:00:00Z'; Assignments = 1 })
$profiles = @(
    @{ Id = 'sc-bl'; Name = 'Windows - BitLocker'; Platforms = 'windows10'; Technologies = 'mdm'; TemplateFamily = 'endpointSecurityDiskEncryption'; TemplateDisplayName = 'BitLocker' }
    @{ Id = 'sc-fw'; Name = 'Windows - Firewall'; Platforms = 'windows10'; Technologies = 'mdm,microsoftSense'; TemplateFamily = 'endpointSecurityFirewall'; TemplateDisplayName = 'Windows Firewall' }
    @{ Id = 'sc-av'; Name = 'Windows - Defender Antivirus'; Platforms = 'windows10'; Technologies = 'mdm,microsoftSense'; TemplateFamily = 'endpointSecurityAntivirus'; TemplateDisplayName = 'Microsoft Defender Antivirus' }
    @{ Id = 'sc-asr'; Name = 'Windows - Attack surface reduction'; Platforms = 'windows10'; Technologies = 'mdm,microsoftSense'; TemplateFamily = 'endpointSecurityAttackSurfaceReduction'; TemplateDisplayName = 'Attack Surface Reduction Rules' }
    @{ Id = 'sc-laps'; Name = 'Windows - LAPS'; Platforms = 'windows10'; Technologies = 'mdm'; TemplateFamily = 'endpointSecurityAccountProtection'; TemplateDisplayName = 'Local admin password solution (Windows LAPS)' }
    @{ Id = 'sc-base'; Name = 'Security baseline for Windows'; Platforms = 'windows10'; Technologies = 'mdm'; TemplateFamily = 'baseline'; TemplateDisplayName = 'Security Baseline for Windows 10 and later' }
    @{ Id = 'sc-mde'; Name = 'Defender for Endpoint baseline'; Platforms = 'windows10'; Technologies = 'mdm,microsoftSense'; TemplateFamily = 'baseline'; TemplateDisplayName = 'Microsoft Defender for Endpoint Security Baseline' }
    @{ Id = 'sc-office'; Name = 'Office - Macros from the internet'; Platforms = 'windows10'; Technologies = 'mdm'; TemplateFamily = 'none'; TemplateDisplayName = $null }
    @{ Id = 'sc-whfb'; Name = 'Windows - Hello for Business'; Platforms = 'windows10'; Technologies = 'mdm'; TemplateFamily = 'none'; TemplateDisplayName = $null }
    @{ Id = 'sc-mac-fv'; Name = 'macOS - FileVault'; Platforms = 'macOS'; Technologies = 'mdm,appleRemoteManagement'; TemplateFamily = 'none'; TemplateDisplayName = $null }
    @{ Id = 'sc-mac-sec'; Name = 'macOS - Gatekeeper and firewall'; Platforms = 'macOS'; Technologies = 'mdm,appleRemoteManagement'; TemplateFamily = 'none'; TemplateDisplayName = $null }
    @{ Id = 'sc-mac-sso'; Name = 'macOS - Enterprise SSO'; Platforms = 'macOS'; Technologies = 'mdm,appleRemoteManagement'; TemplateFamily = 'none'; TemplateDisplayName = $null }
    @{ Id = 'sc-ios-sso'; Name = 'iOS - Enterprise SSO'; Platforms = 'iOS'; Technologies = 'mdm,appleRemoteManagement'; TemplateFamily = 'none'; TemplateDisplayName = $null }
)
Write-Demo '09-intune-config-profiles-settings-catalog' @($profiles | ForEach-Object { $_ + @{ SettingCount = 4 + $rnd.Next(20); CreatedDateTime = Get-DemoDate 500; LastModifiedDateTime = Get-DemoDate (10 + $rnd.Next(200)); Assignments = 1 } })
Write-Demo '09-intune-config-profiles-templates' @()
$set = { param([string] $Policy, [string] $Id, [string] $Value) $p = @($profiles | Where-Object Id -eq $Policy)[0]; [ordered]@{ PolicyId = $p.Id; PolicyName = $p.Name; TemplateFamily = $p.TemplateFamily; TemplateDisplayName = $p.TemplateDisplayName; Platforms = $p.Platforms; SettingDefinitionId = $Id; Value = $Value } }
$asrIds = 'blockabuseofexploitedvulnerablesigneddrivers', 'blockadobereaderfromcreatingchildprocesses', 'blockallofficeapplicationsfromcreatingchildprocesses', 'blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem', 'blockexecutablecontentfromemailclientandwebmail', 'blockexecutionofpotentiallyobfuscatedscripts', 'blockjavascriptorvbscriptfromlaunchingdownloadedexecutablecontent', 'blockofficeapplicationsfromcreatingexecutablecontent', 'blockofficeapplicationsfrominjectingcodeintootherprocesses', 'blockofficecommunicationappfromcreatingchildprocesses', 'blockpersistencethroughwmieventsubscription', 'blockprocesscreationsfrompsexecandwmicommands', 'blockuntrustedunsignedprocessesthatrunfromusb', 'blockwin32apicallsfromofficemacros', 'useadvancedprotectionagainstransomware'
$settings = @(
    (& $set 'sc-bl' 'device_vendor_msft_bitlocker_requiredeviceencryption' 'device_vendor_msft_bitlocker_requiredeviceencryption_1')
    (& $set 'sc-bl' 'device_vendor_msft_bitlocker_encryptionmethodbydrivetype_encryptionmethodwithxtsosdropdown_name' 'device_vendor_msft_bitlocker_encryptionmethodbydrivetype_encryptionmethodwithxtsosdropdown_name_7')
    (& $set 'sc-bl' 'device_vendor_msft_bitlocker_allowwarningforotherdiskencryption' 'device_vendor_msft_bitlocker_allowwarningforotherdiskencryption_0')
    (& $set 'sc-bl' 'device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication' 'device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_1')
    (& $set 'sc-bl' 'device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configuretpmusagedropdown_name' 'device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configuretpmusagedropdown_name_1')
    (& $set 'sc-bl' 'device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osrequireactivedirectorybackup_name' 'device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osrequireactivedirectorybackup_name_1')
    (& $set 'sc-fw' 'vendor_msft_firewall_mdmstore_domainprofile_enablefirewall' 'vendor_msft_firewall_mdmstore_domainprofile_enablefirewall_true')
    (& $set 'sc-fw' 'vendor_msft_firewall_mdmstore_privateprofile_enablefirewall' 'vendor_msft_firewall_mdmstore_privateprofile_enablefirewall_true')
    (& $set 'sc-fw' 'vendor_msft_firewall_mdmstore_publicprofile_enablefirewall' 'vendor_msft_firewall_mdmstore_publicprofile_enablefirewall_true')
    (& $set 'sc-laps' 'device_vendor_msft_laps_policies_backupdirectory' 'device_vendor_msft_laps_policies_backupdirectory_1')
    (& $set 'sc-laps' 'device_vendor_msft_laps_policies_postauthenticationactions' 'device_vendor_msft_laps_policies_postauthenticationactions_3')
    (& $set 'sc-av' 'device_vendor_msft_policy_config_defender_allowrealtimemonitoring' 'device_vendor_msft_policy_config_defender_allowrealtimemonitoring_1')
    (& $set 'sc-av' 'device_vendor_msft_policy_config_defender_allowcloudprotection' 'device_vendor_msft_policy_config_defender_allowcloudprotection_1')
    (& $set 'sc-av' 'device_vendor_msft_policy_config_defender_puaprotection' 'device_vendor_msft_policy_config_defender_puaprotection_1')
    (& $set 'sc-av' 'device_vendor_msft_policy_config_defender_submitsamplesconsent' 'device_vendor_msft_policy_config_defender_submitsamplesconsent_3')
    (& $set 'sc-av' 'device_vendor_msft_policy_config_defender_schedulescanday' 'device_vendor_msft_policy_config_defender_schedulescanday_0')
    (& $set 'sc-av' 'device_vendor_msft_policy_config_defender_enablenetworkprotection' 'device_vendor_msft_policy_config_defender_enablenetworkprotection_1')
    # The rest of the antivirus policy, as an organisation half way through it: scanning and cloud protection are
    # set, removable drives and network files are not, and local administrators can still add exclusions.
    (& $set 'sc-av' 'device_vendor_msft_policy_config_defender_allowarchivescanning' 'device_vendor_msft_policy_config_defender_allowarchivescanning_1')
    (& $set 'sc-av' 'device_vendor_msft_policy_config_defender_allowemailscanning' 'device_vendor_msft_policy_config_defender_allowemailscanning_1')
    (& $set 'sc-av' 'device_vendor_msft_policy_config_defender_allowscriptscanning' 'device_vendor_msft_policy_config_defender_allowscriptscanning_1')
    (& $set 'sc-av' 'device_vendor_msft_policy_config_defender_allowbehaviormonitoring' 'device_vendor_msft_policy_config_defender_allowbehaviormonitoring_1')
    (& $set 'sc-av' 'device_vendor_msft_policy_config_defender_realtimescandirection' 'device_vendor_msft_policy_config_defender_realtimescandirection_0')
    (& $set 'sc-av' 'device_vendor_msft_policy_config_defender_cloudblocklevel' 'device_vendor_msft_policy_config_defender_cloudblocklevel_2')
    (& $set 'sc-av' 'device_vendor_msft_policy_config_defender_cloudextendedtimeout' '50')
    (& $set 'sc-av' 'device_vendor_msft_policy_config_defender_checkforsignaturesbeforerunningscan' 'device_vendor_msft_policy_config_defender_checkforsignaturesbeforerunningscan_1')
    (& $set 'sc-av' 'device_vendor_msft_policy_config_defender_signatureupdateinterval' '4')
    (& $set 'sc-av' 'device_vendor_msft_policy_config_defender_daystoretaincleanedmalware' '30')
    (& $set 'sc-av' 'vendor_msft_defender_configuration_tamperprotection_options' 'vendor_msft_defender_configuration_tamperprotection_options_0')
    (& $set 'sc-whfb' "device_vendor_msft_passportforwork_$($tenantId)_policies_usepassportforwork" "device_vendor_msft_passportforwork_$($tenantId)_policies_usepassportforwork_true")
    (& $set 'sc-office' 'user_vendor_msft_policy_config_word16v2~policy~l_microsoftofficeword~l_wordoptions~l_security~l_trustcenter_l_blockmacroexecutionfrominternet' 'user_vendor_msft_policy_config_word16v2~policy~l_microsoftofficeword~l_wordoptions~l_security~l_trustcenter_l_blockmacroexecutionfrominternet_1')
    (& $set 'sc-office' 'user_vendor_msft_policy_config_excel16v2~policy~l_microsoftofficeexcel~l_excelsoptions~l_security~l_trustcenter_l_blockmacroexecutionfrominternet' 'user_vendor_msft_policy_config_excel16v2~policy~l_microsoftofficeexcel~l_excelsoptions~l_security~l_trustcenter_l_blockmacroexecutionfrominternet_1')
    (& $set 'sc-mac-fv' 'com.apple.mcx.filevault2_enable' 'com.apple.mcx.filevault2_enable_0')
    (& $set 'sc-mac-fv' 'com.apple.security.fderecoverykeyescrow_location' 'Intune')
    (& $set 'sc-mac-sec' 'com.apple.systempolicy.control_enableassessment' 'com.apple.systempolicy.control_enableassessment_true')
    (& $set 'sc-mac-sec' 'com.apple.security.firewall_enablefirewall' 'com.apple.security.firewall_enablefirewall_true')
    (& $set 'sc-mac-sso' 'com.apple.extensiblesso_extensionidentifier' 'com.microsoft.CompanyPortalMac.ssoextension')
    (& $set 'sc-ios-sso' 'com.apple.extensiblesso_extensionidentifier' 'com.microsoft.azureauthenticator.ssoextension')
)
$asrMode = @{ blockwin32apicallsfromofficemacros = 'audit'; blockprocesscreationsfrompsexecandwmicommands = 'audit' }
$settings += @($asrIds | ForEach-Object { & $set 'sc-asr' "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_$_" "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_$($_)_$(if ($asrMode.ContainsKey($_)) { $asrMode[$_] } else { 'block' })" })
Write-Demo '09-intune-policy-settings' $settings
Write-Demo '09-intune-apps' @(@{ DisplayName = 'Microsoft 365 Apps for enterprise'; Type = 'officeSuiteApp'; Assignments = 1 }, @{ DisplayName = 'Company Portal'; Type = 'iosStoreApp'; Assignments = 1 }, @{ DisplayName = 'AutoCAD 2026'; Type = 'win32LobApp'; Assignments = 1 })
Write-Demo '09-intune-app-protection-policies' @(
    @{ Id = 'app-ios'; DisplayName = 'iOS - Protect work data'; Type = 'iosManagedAppProtection'; Assignments = 1; IsAssigned = $true; PinRequired = $true; FingerprintBlocked = $false; FaceIdBlocked = $false }
    @{ Id = 'app-and'; DisplayName = 'Android - Protect work data'; Type = 'androidManagedAppProtection'; Assignments = 1; IsAssigned = $true; PinRequired = $true; FingerprintBlocked = $false; FaceIdBlocked = $false }
)

# --- Defender ----------------------------------------------------------------------------------------------------------------
$windows = @($fleet | Where-Object OperatingSystem -eq 'Windows')
Write-Demo 'def-01-devices' @($fleet | Where-Object { $_.OperatingSystem -in 'Windows', 'macOS' } | ForEach-Object { [ordered]@{ DeviceId = $_.Id; DeviceName = $_.DeviceName; OSPlatform = $(if ($_.OperatingSystem -eq 'Windows') { 'Windows11' } else { 'macOS' }); OSVersionInfo = $_.OSVersion; OnboardingStatus = 'Onboarded'; SensorHealthState = $(if (Test-DemoChance 0.02) { 'Inactive' } else { 'Active' }); ExposureLevel = Get-DemoPick @('Low', 'Low', 'Medium', 'Medium', 'High'); MachineGroup = 'Fernquill'; JoinType = 'AzureADJoined'; AadDeviceId = $_.AzureAdDeviceId; IsAzureADJoined = 1; DeviceType = 'Workstation'; LastSeen = $_.LastSyncDateTime } })
Write-Demo 'def-01-devices-summary' @{ Devices = 252; RowsExpected = 252; RowsRead = 252; Truncated = $false; Onboarded = 252; Active = 248 }
Write-Demo 'def-02-av-state' @($windows | ForEach-Object { [ordered]@{ DeviceId = $_.Id; DeviceName = $_.DeviceName; OSPlatform = 'Windows11'; AvMode = 'Active'; AvIsSignatureUpToDate = $(if (Test-DemoChance 0.03) { 'False' } else { 'True' }); AvIsEngineUpToDate = 'True'; AvIsPlatformUpToDate = 'True'; AvSignatureVersion = '1.441.112.0'; LastSeen = $_.LastSyncDateTime } })
Write-Demo 'def-02-av-state-summary' @{ Devices = $windows.Count; RowsExpected = $windows.Count; RowsRead = $windows.Count; Truncated = $false; ByMode = @(@{ Name = 'Active'; Count = $windows.Count }); SignatureOutOfDate = 6 }
$config = { param([string] $Id, [string] $Name, [string] $Cat, [string] $Sub, [int] $Compliant) [ordered]@{ ConfigurationId = $Id; ConfigurationName = $Name; Category = $Cat; Subcategory = $Sub; Impact = 5; Devices = $windows.Count; Compliant = $Compliant; CompliantPct = [math]::Round(100 * $Compliant / $windows.Count, 1) } }
Write-Demo 'def-03-secure-config' @(
    (& $config 'scid-91' 'Turn on Tamper Protection' 'Security controls' 'Antivirus' 226)
    (& $config 'scid-2010' 'Turn on real-time protection' 'Security controls' 'Antivirus' 228)
    (& $config 'scid-2011' 'Turn on cloud-delivered protection' 'Security controls' 'Antivirus' 228)
    (& $config 'scid-96' 'Turn on network protection' 'Security controls' 'Network protection' 221)
    (& $config 'scid-2500' 'Block execution of potentially obfuscated scripts' 'Security controls' 'Attack Surface Reduction' 219)
    (& $config 'scid-2501' 'Block credential stealing from the Windows local security authority subsystem' 'Security controls' 'Attack Surface Reduction' 224)
    (& $config 'scid-2502' 'Block Win32 API calls from Office macros' 'Security controls' 'Attack Surface Reduction' 0)
    (& $config 'scid-2503' 'Block process creations originating from PSExec and WMI commands' 'Security controls' 'Attack Surface Reduction' 0)
    (& $config 'scid-2504' 'Block executable content from email client and webmail' 'Security controls' 'Attack Surface Reduction' 222)
)
Write-Demo 'def-04-vulnerabilities-summary' @{ CriticalCves = 4; DevicesWithCriticalCves = 9; CriticalCvesOver30d = 1; DevicesWithCriticalCvesOver30d = 2 }
Write-Demo 'def-05-incidents-summary' @{ Active = 3; OpenOver7Days = 1; OpenOver7DaysUnassigned = 0; BySeverity = @(@{ Name = 'Medium'; Count = 2 }, @{ Name = 'Low'; Count = 1 }) }
Write-Demo 'def-05-incidents-weekly' @{ Weeks = @(for ($w = 11; $w -ge 0; $w--) { @{ WeekStart = $AsOf.AddDays(-7 * $w - [int]$AsOf.DayOfWeek + 1).ToString('yyyy-MM-dd'); Total = 2 + $rnd.Next(7); High = $(if ($w -in 9, 4) { 1 } else { 0 }) } }) }
$controls = @(
    @('Ensure all users can complete multifactor authentication', 'Identity', 9, 9, 'Completed'), @('Require MFA for administrative roles', 'Identity', 10, 10, 'Completed'), @('Block legacy authentication', 'Identity', 8, 8, 'Completed')
    @('Enable Microsoft Entra ID Identity Protection sign-in risk policies', 'Identity', 7, 0, 'Default'), @('Enable Microsoft Entra ID Identity Protection user risk policies', 'Identity', 7, 0, 'Default'), @('Use least privileged administrative roles', 'Identity', 1, 1, 'Completed')
    @('Ensure Administrative accounts are separate and cloud-only', 'Identity', 1, 0.5, 'Default'), @('Turn on Microsoft Defender for Cloud Apps app governance', 'Apps', 3, 0, 'Default'), @('Create Safe Links policies for email messages', 'Apps', 9, 9, 'Completed')
    @('Create zero-hour auto purge policies for malware', 'Apps', 5, 5, 'Completed'), @('Set the email bulk complaint level threshold to be 6 or lower', 'Apps', 1, 0, 'Default'), @('Enable impersonated user protection', 'Apps', 3, 3, 'Completed')
    @('Block Win32 API calls from Office macros', 'Device', 9, 0, 'Default'), @('Block process creations originating from PSExec and WMI commands', 'Device', 9, 0, 'Default'), @('Turn on Tamper Protection', 'Device', 9, 8.9, 'Completed')
    @('Update Microsoft Edge to the latest version', 'Device', 7, 6.2, 'Default'), @('Disable SMBv1', 'Device', 9, 9, 'Completed'), @('Set Account lockout threshold to 1-10 invalid login attempts', 'Device', 7, 7, 'Completed')
    @('Ensure DLP policies are enabled for Microsoft Teams', 'Data', 4, 0, 'Default'), @('Apply sensitivity labels automatically', 'Data', 4, 0, 'Default'), @('Restrict anonymous users from joining meetings', 'Apps', 1, 0, 'Default')
)
$rank = 0
Write-Demo 'def-06-secure-score-controls' @($controls | ForEach-Object { $rank++; [ordered]@{ Id = "control-$rank"; Title = $_[0]; Category = $_[1]; MaxScore = $_[2]; Score = $_[3]; ImplementationCost = Get-DemoPick @('Low', 'Moderate'); UserImpact = 'Low'; ActionType = 'Config'; Tier = 'Core'; Rank = $rank; State = $_[4]; Remediation = 'See the action in Microsoft Defender.'; ActionUrl = 'https://security.microsoft.com/securescore?viewid=actions' } })
# Ninety days of daily scores: a slow climb, with the last fortnight flat. Nothing was undone (OP-009 passes).
Write-Demo 'def-06-secure-score-history' @(0..89 | ForEach-Object { [ordered]@{ Date = Get-DemoDate ($_ + 0.5); CurrentScore = [Math]::Round(612.4 - [Math]::Max(0, $_ - 14) * 0.62, 1); MaxScore = 878 } })
Write-Demo 'def-06-secure-score' @{ Present = $true; CreatedDateTime = Get-DemoDate 0.5; CurrentScore = 612.4; MaxScore = 878; LicensedUserCount = 384; ActiveUserCount = 371; ByCategory = @{ Identity = 74.2; Device = 69.8; Apps = 66.1; Data = 31.0 }; AverageComparativeScores = @(@{ Basis = 'AllTenants'; AverageScore = 48.3 }, @{ Basis = 'TotalSeats'; AverageScore = 52.9 }) }

# --- Exchange Online, mail DNS, Defender for Office 365 ----------------------------------------------------------------------------
Write-Demo 'dns-01-mail-records' @(
    @{ Domain = $domain; MX = 'fernquill-example.mail.protection.outlook.com'; SPF = 'v=spf1 include:spf.protection.outlook.com -all'; DMARC = "v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@$domain"; MTASTS = ''; TLSRPT = '' }
)
Write-Demo 'exo-01-audit-config' @{ UnifiedAuditLogIngestionEnabled = $true; UnifiedAuditLogFirstOptInDate = '2019-03-05T00:00:00Z'; AdminAuditLogEnabled = $true }
Write-Demo 'exo-01-orgconfig' @{ Name = $initial; RejectDirectSend = $false; OAuth2ClientProfileEnabled = $true; DefaultAuthenticationPolicy = 'Block Basic Auth'; AuditDisabled = $false; IsDehydrated = $false; SendFromAliasEnabled = $true; MailTipsAllTipsEnabled = $true; MailTipsExternalRecipientsTipsEnabled = $true; MailTipsLargeAudienceThreshold = 25; AutoExpandingArchiveEnabled = $true; EwsEnabled = $null; ActivityBasedAuthenticationTimeoutEnabled = $true; ActivityBasedAuthenticationTimeoutInterval = '06:00:00'; ArcTrustedSealers = $null; SmtpClientAuthenticationDisabled = $null; CustomerLockboxEnabled = $true }
Write-Demo 'exo-01-transport-config' @{ SmtpClientAuthenticationDisabled = $true; ExternalPostmasterAddress = $null; MaxRecipientEnvelopeLimit = '500'; DSNConversionMode = 'UseExchangeDSNs' }
Write-Demo 'exo-01-auth-policies' @(@{ Name = 'Block Basic Auth'; AllowBasicAuthSmtp = $false; AllowBasicAuthPop = $false; AllowBasicAuthImap = $false })
Write-Demo 'exo-02-accepted-domains' @(@{ DomainName = $domain; DomainType = 'Authoritative'; Default = $true; AuthenticationType = 'Managed'; InitialDomain = $false }, @{ DomainName = $initial; DomainType = 'Authoritative'; Default = $false; AuthenticationType = 'Managed'; InitialDomain = $true })
Write-Demo 'exo-02-dkim' @(@{ Domain = $domain; Enabled = $true; Status = 'Valid'; Selector1CNAME = "selector1-fernquill-example._domainkey.$initial"; Selector2CNAME = "selector2-fernquill-example._domainkey.$initial"; LastChecked = Get-DemoDate 1; RotateOnDate = Get-DemoDate 120 }, @{ Domain = $initial; Enabled = $true; Status = 'Valid'; Selector1CNAME = ''; Selector2CNAME = ''; LastChecked = Get-DemoDate 1; RotateOnDate = Get-DemoDate 400 })
Write-Demo 'exo-03-inbound-connectors' @()
Write-Demo 'exo-03-outbound-connectors' @()
Write-Demo 'exo-03-transport-rules' @(@{ Name = 'Disclaimer - outbound'; State = 'Enabled'; Mode = 'Enforce'; Priority = 0; SetSCL = $null; SetHeaderName = $null; SetHeaderValue = $null; FromScope = 'InOrganization'; SentToScope = 'NotInOrganization'; HeaderContainsMessageHeader = $null; SenderDomainIs = @(); SenderIpRanges = @(); RedirectMessageTo = @(); BlindCopyTo = @() })
$base = @{ IsDefault = $true; Identity = 'Default'; RecommendedPolicyType = 'Custom' }
Write-Demo 'exo-04-antiphish' @($base + @{ Name = 'Office365 AntiPhish Default'; Enabled = $true; PhishThresholdLevel = 2; EnableTargetedUserProtection = $true; TargetedUsersToProtect = @("Avery Holloway;avery.holloway@$domain", "Morgan Fairbanks;morgan.fairbanks@$domain"); EnableOrganizationDomainsProtection = $true; EnableTargetedDomainsProtection = $false; EnableMailboxIntelligence = $true; EnableMailboxIntelligenceProtection = $true; MailboxIntelligenceProtectionAction = 'MoveToJmf'; TargetedUserProtectionAction = 'Quarantine'; TargetedDomainProtectionAction = 'Quarantine'; EnableFirstContactSafetyTips = $true; EnableSimilarUsersSafetyTips = $true; EnableSimilarDomainsSafetyTips = $true; EnableUnusualCharactersSafetyTips = $true; EnableSpoofIntelligence = $true; EnableViaTag = $true; EnableUnauthenticatedSender = $true; HonorDmarcPolicy = $true; DmarcRejectAction = 'Reject'; DmarcQuarantineAction = 'Quarantine'; AuthenticationFailAction = 'MoveToJmf'; ImpersonationProtectionState = 'Automatic' })
Write-Demo 'exo-04-eop-connection-filter' @($base + @{ IPAllowList = @(); IPBlockList = @(); EnableSafeList = $false })
Write-Demo 'exo-04-eop-content-filter' @($base + @{ BulkThreshold = 7; SpamAction = 'MoveToJmf'; HighConfidenceSpamAction = 'Quarantine'; PhishSpamAction = 'Quarantine'; HighConfidencePhishAction = 'Quarantine'; BulkSpamAction = 'MoveToJmf'; ZapEnabled = $true; SpamZapEnabled = $true; PhishZapEnabled = $true; AllowedSenders = @(); AllowedSenderDomains = @(); BlockedSenders = @(); BlockedSenderDomains = @(); QuarantineRetentionPeriod = 30; InlineSafetyTipsEnabled = $true; MarkAsSpamBulkMail = 'On'; SpamQuarantineTag = 'DefaultFullAccessPolicy'; HighConfidenceSpamQuarantineTag = 'DefaultFullAccessPolicy'; PhishQuarantineTag = 'DefaultFullAccessWithNotificationPolicy'; HighConfidencePhishQuarantineTag = 'AdminOnlyAccessPolicy'; BulkQuarantineTag = 'DefaultFullAccessPolicy' })
Write-Demo 'exo-04-eop-malware' @($base + @{ EnableFileFilter = $true; FileTypeAction = 'Reject'; ZapEnabled = $true; EnableInternalSenderAdminNotifications = $true; InternalSenderAdminAddress = "security@$domain"; QuarantineTag = 'AdminOnlyAccessPolicy' })
Write-Demo 'exo-04-outbound-spam' @($base + @{ Enabled = $true; AutoForwardingMode = 'Off'; RecipientLimitExternalPerHour = '500'; RecipientLimitInternalPerHour = '1000'; RecipientLimitPerDay = '1000'; ActionWhenThresholdReached = 'BlockUser'; NotifyOutboundSpam = $true; NotifyOutboundSpamRecipients = @("security@$domain"); BccSuspiciousOutboundMail = $false })
Write-Demo 'exo-04-preset-rules-eop' @(@{ Name = 'Standard Preset Security Policy'; State = 'Enabled'; Priority = 1; SentTo = @(); SentToMemberOf = @(); RecipientDomainIs = @($domain) })
Write-Demo 'exo-04-preset-rules-mdo' @(@{ Name = 'Standard Preset Security Policy'; State = 'Enabled'; Priority = 1; SentTo = @(); SentToMemberOf = @(); RecipientDomainIs = @($domain) })
Write-Demo 'exo-05-mdo-global' @{ EnableATPForSPOTeamsODB = $true; EnableSafeDocs = $true; AllowSafeDocsOpen = $false }
Write-Demo 'exo-05-mdo-safeattachments' @(@{ Name = 'Standard Preset Security Policy'; Enable = $true; Action = 'Block'; Redirect = $false; IsBuiltInProtection = $false; IsDefault = $false; QuarantineTag = 'AdminOnlyAccessPolicy' }, @{ Name = 'Built-In Protection Policy'; Enable = $true; Action = 'Block'; Redirect = $false; IsBuiltInProtection = $true; IsDefault = $false; QuarantineTag = 'AdminOnlyAccessPolicy' })
Write-Demo 'exo-05-mdo-safelinks' @(@{ Name = 'Standard Preset Security Policy'; EnableSafeLinksForEmail = $true; EnableSafeLinksForTeams = $true; EnableSafeLinksForOffice = $true; TrackClicks = $true; AllowClickThrough = $false; ScanUrls = $true; EnableForInternalSenders = $true; DeliverMessageAfterScan = $true; DisableUrlRewrite = $false; IsBuiltInProtection = $false }, @{ Name = 'Built-In Protection Policy'; EnableSafeLinksForEmail = $true; EnableSafeLinksForTeams = $true; EnableSafeLinksForOffice = $true; TrackClicks = $true; AllowClickThrough = $true; ScanUrls = $true; EnableForInternalSenders = $false; DeliverMessageAfterScan = $true; DisableUrlRewrite = $false; IsBuiltInProtection = $true })
Write-Demo 'exo-05-quarantine-policies' @(@{ Name = 'AdminOnlyAccessPolicy'; EndUserQuarantinePermissions = 'None'; ESNEnabled = $false; QuarantinePolicyType = 'QuarantinePolicy' }, @{ Name = 'DefaultFullAccessWithNotificationPolicy'; EndUserQuarantinePermissions = 'Full'; ESNEnabled = $true; QuarantinePolicyType = 'QuarantinePolicy' })
Write-Demo 'exo-06-remote-domains' @(@{ DomainName = '*'; AutoForwardEnabled = $false; AllowedOOFType = 'External' })
Write-Demo 'exo-06-sharing-policies' @(@{ Name = 'Default Sharing Policy'; Enabled = $true; Default = $true; Domains = @('Anonymous:CalendarSharingFreeBusySimple', '*:CalendarSharingFreeBusySimple') })
Write-Demo 'exo-06-owa-policies' @(@{ Name = 'OwaMailboxPolicy-Default'; AdditionalStorageProvidersAvailable = $false; ThirdPartyFileProvidersEnabled = $false })
$mailboxes = @($members | Where-Object { $_.LicenseCount -gt 0 } | ForEach-Object { [ordered]@{ UserPrincipalName = $_.UserPrincipalName; DisplayName = $_.DisplayName; RecipientTypeDetails = 'UserMailbox'; LitigationHoldEnabled = $false; InPlaceHoldCount = 1; ArchiveStatus = 'Active'; ForwardingSmtpAddress = ''; ForwardingAddress = ''; DeliverToMailboxAndForward = $false; AuditEnabled = $true; WhenMailboxCreated = $_.CreatedDateTime; ExternalDirectoryObjectId = $_.Id } })
$mailboxes += @(@('Reception', 'reception'), @('Accounts Payable', 'ap'), @('Plotter Room', 'plotter-room'), @('Board Room', 'boardroom')) | ForEach-Object { [ordered]@{ UserPrincipalName = "$($_[1])@$domain"; DisplayName = $_[0]; RecipientTypeDetails = $(if ($_[1] -match 'room') { 'RoomMailbox' } else { 'SharedMailbox' }); LitigationHoldEnabled = $false; InPlaceHoldCount = 1; ArchiveStatus = 'None'; ForwardingSmtpAddress = $(if ($_[1] -eq 'ap') { 'smtp:invoices@ledgerbox.example' } else { '' }); ForwardingAddress = ''; DeliverToMailboxAndForward = $($_[1] -eq 'ap'); AuditEnabled = $true; WhenMailboxCreated = Get-DemoDate 1000; ExternalDirectoryObjectId = (Get-DemoId 'ab000000' $_[1].Length) } }
Write-Demo 'exo-09-mailboxes' $mailboxes
Write-Demo 'exo-09-mailboxes-with-forwarding' @($mailboxes | Where-Object { $_.ForwardingSmtpAddress })
Write-Demo 'exo-09-mailboxes-by-type' @($mailboxes | Group-Object RecipientTypeDetails | ForEach-Object { @{ Name = $_.Name; Count = $_.Count } })
Write-Demo 'exo-10-cas-mailboxes' @($mailboxes | ForEach-Object { [ordered]@{ PrimarySmtpAddress = $_.UserPrincipalName; ActiveSyncEnabled = $true; ImapEnabled = $false; PopEnabled = $false; SmtpClientAuthenticationDisabled = $null; OWAEnabled = $true; MAPIEnabled = $true; EwsEnabled = $true } })
Write-Demo 'exo-10-cas-summary' @{ Total = $mailboxes.Count; ImapEnabled = 0; PopEnabled = 0; ActiveSyncEnabled = $mailboxes.Count; SmtpAuthExplicitlyEnabled = 0 }
Write-Demo 'exo-11-attack-simulations' @(@{ DisplayName = 'Q3 credential harvest'; Status = 'succeeded'; LaunchDateTime = Get-DemoDate 70; CompletionDateTime = Get-DemoDate 56; AttackTechnique = 'credentialHarvesting'; Report = @{ Simulated = 371; Compromised = 14; Reported = 122 } })
# Exchange PowerShell left on for everyone: the admins, and the rest of the staff the check counts.
# Counted as the collector counts it: everyone with the setting on, then the people among them who hold no role, of whom the first 500 are listed.
$psPeople = @($mailboxes | Where-Object { $_.RecipientTypeDetails -notmatch '^(SharedMailbox|RoomMailbox|EquipmentMailbox|SchedulingMailbox)$' -and $_.UserPrincipalName -notin $holderUpns })
Write-Demo 'exo-12-remote-powershell-users' @($psPeople | Select-Object -First 500 | ForEach-Object { @{ UserPrincipalName = $_.UserPrincipalName; RecipientTypeDetails = $_.RecipientTypeDetails } })
Write-Demo 'exo-12-remote-powershell-summary' @{ RemotePowerShellEnabled = $mailboxes.Count; NonAdmin = $psPeople.Count; Listed = [Math]::Min(500, $psPeople.Count); AdminsExcluded = $true }
Write-Demo 'exo-13-external-in-outlook' @(@{ Enabled = $true; AllowList = @() })
Write-Demo 'exo-13-report-submission' @(@{ EnableReportToMicrosoft = $true; ReportJunkToCustomizedAddress = $true; ReportPhishToCustomizedAddress = $true })
Write-Demo 'exo-07-eas-org-settings' @{ DefaultAccessLevel = 'Allow' }
Write-Demo 'exo-07-mobile-device-policies' @()
Write-Demo 'exo-08-role-groups' @(@{ Name = 'Organization Management'; Members = @('Avery Holloway', 'Jordan Lindqvist') })

# --- SharePoint, OneDrive, Teams ---------------------------------------------------------------------------------------------------
$sites = [System.Collections.Generic.List[object]]::new()
$site = { param([string] $Url, [string] $Title, [string] $Template, [string] $Sharing, [string] $Label, [bool] $Ownerless = $false, [bool] $OneDrive = $false) [ordered]@{ Url = $Url; Title = $Title; Template = $Template; SharingCapability = $Sharing; StorageUsageCurrent = 200 + $rnd.Next(90000); LastContentModifiedDate = Get-DemoDate ($rnd.NextDouble() * 60); Owner = ''; OwnerEmail = $(if ($Ownerless) { '' } else { "avery.holloway@$domain" }); OwnerLoginName = ''; OwnerName = $(if ($Ownerless) { '' } else { 'Avery Holloway' }); GroupId = $(if ($Template -like 'GROUP*') { Get-DemoId 'e5000000' ($sites.Count + 1) } else { '00000000-0000-0000-0000-000000000000' }); SensitivityLabel = $Label; LockState = 'Unlock'; RestrictedAccessControl = $false; RestrictContentOrgWideSearch = $false; DenyAddAndCustomizePages = 'Enabled'; IsOneDrive = $OneDrive; IsSystem = $false; Ownerless = $Ownerless } }
$labelGeneral = 'b7a3c0de-0000-4000-8000-000000000001'; $labelConfidential = 'b7a3c0de-0000-4000-8000-000000000003'
$spoBase = 'https://fernquilldemo.sharepoint.com/sites'
$sites.Add((& $site "$spoBase/intranet" 'Fernquill Intranet' 'SITEPAGEPUBLISHING#0' 'Disabled' $labelGeneral))
$n = 0; foreach ($p in $projects) { $n++; $sites.Add((& $site "$spoBase/project-$($p.ToLower().Replace(' ', '-'))" "Project - $p" 'GROUP#0' $(if ($n -in 3, 7) { 'ExternalUserAndGuestSharing' } else { 'ExistingExternalUserSharingOnly' }) $(if ($n -le 7) { $labelConfidential } else { '' }) ($n -ge 9))) }
foreach ($d in 'Engineering', 'Projects', 'Field Services', 'Finance', 'Operations', 'Sales', 'People', 'IT') { $sites.Add((& $site "$spoBase/$($d.ToLower().Replace(' ', '-'))" $d 'GROUP#0' 'Disabled' $(if ($d -in 'Finance', 'People') { $labelConfidential } else { $labelGeneral }))) }
foreach ($u in ($members | Select-Object -First 300)) { $sites.Add((& $site "https://fernquilldemo-my.sharepoint.com/personal/$($u.UserPrincipalName.Replace('@', '_').Replace('.', '_'))" $u.DisplayName 'SPSPERS#10' 'ExistingExternalUserSharingOnly' '' $false $true)) }
Write-Demo 'spo-sites' @($sites)
Write-Demo 'spo-sites-summary' @{ Total = $sites.Count; OneDrives = 300; Sites = $sites.Count - 300; AnonymousSharingAllowed = 2; Ownerless = 2; Labeled = @($sites | Where-Object { $_.SensitivityLabel -and -not $_.IsOneDrive }).Count; RestrictedAccessControl = 0; ByTemplate = @($sites | Group-Object Template | ForEach-Object { @{ Name = $_.Name; Count = $_.Count } }) }
Write-Demo 'spo-tenant-settings' @{
    SharingCapability = 'ExternalUserAndGuestSharing'; DefaultSharingLinkType = 'Internal'; DefaultLinkPermission = 'View'; RequireAnonymousLinksExpireInDays = 14; FileAnonymousLinkType = 'View'; FolderAnonymousLinkType = 'View'
    OneDriveSharingCapability = 'ExistingExternalUserSharingOnly'; SharingDomainRestrictionMode = 'None'; SharingAllowedDomainList = $null; SharingBlockedDomainList = $null; ExternalUserExpirationRequired = $true; ExternalUserExpireInDays = 90
    ShowEveryoneClaim = $false; ShowEveryoneExceptExternalUsersClaim = $false; ShowAllUsersClaim = $false; LegacyAuthProtocolsEnabled = $false; ConditionalAccessPolicy = 'AllowLimitedAccess'; EnableRestrictedAccessControl = $false
    EnableAzureADB2BIntegration = $true; EmailAttestationRequired = $true; EmailAttestationReAuthDays = 30; PreventExternalUsersFromResharing = $true; NotifyOwnersWhenItemsReshared = $true; RequireAcceptingAccountMatchInvitedAccount = $true; DisallowInfectedFileDownload = $true
    ShowPeoplePickerSuggestionsForGuestUsers = $false; EnableAIPIntegration = $true; BlockUserInfoVisibilityInOneDrive = 'ApplyToNoUsers'; OneDriveLoopSharingCapability = 'ExistingExternalUserSharingOnly'; CoreSharingCapability = 'ExternalUserAndGuestSharing'
}
Write-Demo 'spo-tenant-settings-graph' @{ sharingCapability = 'externalUserAndGuestSharing'; sharingDomainRestrictionMode = 'none'; isLegacyAuthProtocolsEnabled = $false; isResharingByExternalUsersEnabled = $false; idleSessionSignOut = @{ isEnabled = $true; signOutAfterInSeconds = 28800; warnAfterInSeconds = 27900 }; sharingAllowedDomainList = @(); sharingBlockedDomainList = @(); isUnmanagedSyncAppForTenantRestricted = $true; isMacSyncAppEnabled = $true; isLoopEnabled = $true; isSiteCreationEnabled = $false; deletedUserPersonalSiteRetentionPeriodInDays = 365 }
Write-Demo 'spo-restricted-search' @{ Mode = 'Disabled'; AllowedSites = 0 }
Write-Demo 'spo-dag-site-permissions' @{ Sites = @($sites | Where-Object { -not $_.IsOneDrive } | Select-Object -First 8 | ForEach-Object { @{ Url = $_.Url; Title = $_.Title; EveryoneExceptExternalUsers = $(if ($_.Title -in 'Fernquill Intranet', 'Project - Harbor Terminal') { $true } else { $false }); ExternalUsers = $(if ($_.SharingCapability -eq 'ExternalUserAndGuestSharing') { 3 } else { 0 }); AnyoneLinks = $(if ($_.SharingCapability -eq 'ExternalUserAndGuestSharing') { 4 } else { 0 }) } }) }
Write-Demo 'teams-federation' @{ Identity = 'Global'; AllowFederatedUsers = $true; AllowPublicUsers = $false; AllowedDomains = 'AllowAllKnownDomains'; BlockedDomains = @(); AllowTeamsConsumer = $false; AllowTeamsConsumerInbound = $false; AllowTeamsSms = $false; ExternalAccessWithTrialTenants = 'Blocked'; TreatDiscoveredPartnersAsUnverified = $true; BlockAllSubdomains = $false }
Write-Demo 'teams-external-access' @(@{ Identity = 'Global'; EnableFederationAccess = $true; EnableTeamsConsumerAccess = $false; EnableTeamsConsumerInbound = $false; EnablePublicCloudAudioVideoAccess = $true; EnableOutsideAccess = $true })
Write-Demo 'teams-client-config' @{ Identity = 'Global'; AllowEmailIntoChannel = $false; AllowDropBox = $false; AllowBox = $false; AllowGoogleDrive = $false; AllowShareFile = $false; AllowEgnyte = $false; AllowGuestUser = $true; AllowSkypeBusinessInterop = $false }
Write-Demo 'teams-meeting-policy-global' @{ Identity = 'Global'; AllowAnonymousUsersToJoinMeeting = $true; AllowAnonymousUsersToStartMeeting = $false; AllowAnonymousUsersToDialOut = $false; AutoAdmittedUsers = 'EveryoneInCompanyExcludingGuests'; AllowExternalParticipantGiveRequestControl = $false; DesignatedPresenterRoleMode = 'EveryoneInCompanyUserOverride'; AllowCloudRecording = $true; AllowTranscription = $true; MeetingChatEnabledType = 'Enabled'; AllowExternalNonTrustedMeetingChat = $false; ExplicitRecordingConsent = 'Disabled'; AllowPSTNUsersToBypassLobby = $false }
Write-Demo 'teams-live-event-policy-global' @{ Identity = 'Global'; AllowBroadcastScheduling = $true; AllowBroadcastTranscription = $false; BroadcastAttendeeVisibilityMode = 'EveryoneInCompany'; BroadcastRecordingMode = 'UserOverride' }
# The older permission policy says what the org-wide app settings below say, kind by kind: third-party apps limited,
# custom apps open. The two are sources for the same answers (CL-014, CL-029), so they must not disagree.
Write-Demo 'teams-app-permission-policies' @{ Identity = 'Global'; DefaultCatalogAppsType = 'AllowedAppList'; GlobalCatalogAppsType = 'AllowedAppList'; PrivateCatalogAppsType = 'BlockedAppList'; DefaultCatalogApps = @(); GlobalCatalogApps = @(@{ Id = 'app-1' }, @{ Id = 'app-2' }); PrivateCatalogApps = @() }
# App centric management: third-party apps off by default, a handful opened one by one.
Write-Demo 'teams-app-settings' @(@{ SettingName = 'DefaultApp'; SettingValue = 'All'; Users = ''; Groups = '' }, @{ SettingName = 'GlobalApp'; SettingValue = 'None'; Users = ''; Groups = '' }, @{ SettingName = 'PrivateApp'; SettingValue = 'All'; Users = ''; Groups = '' }, @{ SettingName = 'EnableCopilotExtensibility'; SettingValue = 'Some'; Users = ''; Groups = 'Copilot Pilot' })
$teamsApps = @(@('Planner', 'Everyone', 'Unblocked'), @('Approvals', 'Everyone', 'Unblocked'), @('Lists', 'Everyone', 'Unblocked'), @('Viva Learning', 'Everyone', 'Unblocked'), @('Drawing Vault', 'Everyone', 'Unblocked'), @('Site Diary', 'UsersandGroups', 'Unblocked'), @('Survey Pro', 'UsersandGroups', 'Unblocked'), @('Arcade Break', 'Noone', 'Blocked'))
$n = 0
Write-Demo 'teams-app-availability' @($teamsApps | ForEach-Object { $n++; [ordered]@{ Id = Get-DemoId 'a7000000' $n; AppName = $_[0]; IsBlocked = $_[2]; AvailableTo = $_[1]; AvailableToChangedUtc = Get-DemoDate (20 + $n * 9); InstalledFor = 'Noone' } })
Write-Demo 'teams-guest-messaging' @{ Identity = 'Global'; AllowUserChat = $true; AllowUserEditMessage = $true; AllowUserDeleteMessage = $false; AllowGiphy = $true; GiphyRatingType = 'Strict' }
Write-Demo 'teams-messaging-policies' @(@{ Identity = 'Global'; AllowUrlPreviews = $true; AllowUserChat = $true; AllowGiphy = $true; GiphyRatingType = 'Moderate'; AllowSecurityEndUserReporting = $true; AllowCommunicationComplianceEndUserReporting = $true })

# --- Purview, governance ---------------------------------------------------------------------------------------------------------
Write-Demo 'pv-01-sensitivity-labels' @(
    @{ Name = 'Public'; DisplayName = 'Public'; Guid = 'b7a3c0de-0000-4000-8000-000000000000'; Priority = 0; Disabled = $false; ContentType = 'File, Email'; EncryptionEnabled = $false; ParentId = $null; SiteAndGroupProtectionEnabled = $false }
    @{ Name = 'General'; DisplayName = 'General'; Guid = $labelGeneral; Priority = 1; Disabled = $false; ContentType = 'File, Email, Site, UnifiedGroup'; EncryptionEnabled = $false; ParentId = $null; SiteAndGroupProtectionEnabled = $true }
    @{ Name = 'Confidential'; DisplayName = 'Confidential'; Guid = 'b7a3c0de-0000-4000-8000-000000000002'; Priority = 2; Disabled = $false; ContentType = 'File, Email'; EncryptionEnabled = $false; ParentId = $null; SiteAndGroupProtectionEnabled = $false }
    @{ Name = 'Confidential-Project'; DisplayName = 'Confidential \ Project team'; Guid = $labelConfidential; Priority = 3; Disabled = $false; ContentType = 'File, Email, Site, UnifiedGroup'; EncryptionEnabled = $true; ParentId = 'b7a3c0de-0000-4000-8000-000000000002'; SiteAndGroupProtectionEnabled = $true }
    @{ Name = 'Highly-Confidential'; DisplayName = 'Highly Confidential'; Guid = 'b7a3c0de-0000-4000-8000-000000000004'; Priority = 4; Disabled = $false; ContentType = 'File, Email'; EncryptionEnabled = $true; ParentId = $null; SiteAndGroupProtectionEnabled = $false }
)
Write-Demo 'pv-01-label-policies' @(@{ Name = 'Fernquill labels - everyone'; Enabled = $true; Mode = 'Enforce'; Labels = @('Public', 'General', 'Confidential', 'Confidential-Project', 'Highly-Confidential'); ExchangeLocation = @('All'); Settings = @('[mandatory, true]', '[defaultlabelid, b7a3c0de-0000-4000-8000-000000000001]', '[requiredowngradejustification, true]') })
Write-Demo 'pv-01-autolabel-policies' @()
Write-Demo 'pv-02-dlp-policies' @(
    @{ Name = 'U.S. Financial Data'; Enabled = $true; Mode = 'Enable'; Priority = 0; Workload = 'Exchange, SharePoint, OneDriveForBusiness'; ExchangeLocation = @('All'); SharePointLocation = @('All'); OneDriveLocation = @('All'); TeamsLocation = @(); EndpointDlpLocation = @(); WhenCreated = Get-DemoDate 400; WhenChanged = Get-DemoDate 90 }
    @{ Name = 'Project drawings leaving the company'; Enabled = $true; Mode = 'TestWithNotifications'; Priority = 1; Workload = 'Exchange, SharePoint, OneDriveForBusiness, EndpointDevices'; ExchangeLocation = @('All'); SharePointLocation = @('All'); OneDriveLocation = @('All'); TeamsLocation = @(); EndpointDlpLocation = @('All'); WhenCreated = Get-DemoDate 60; WhenChanged = Get-DemoDate 12 }
)
Write-Demo 'pv-02-dlp-rules' @(
    @{ Name = 'High volume of financial data'; ParentPolicyName = 'U.S. Financial Data'; Disabled = $false; Priority = 0; ReportSeverityLevel = 'High'; BlockAccess = $true; BlockAccessScope = 'PerUser'; NotifyUser = @('LastModifier', 'Owner'); Mode = 'Enable' }
    @{ Name = 'Low volume of financial data'; ParentPolicyName = 'U.S. Financial Data'; Disabled = $false; Priority = 1; ReportSeverityLevel = 'Low'; BlockAccess = $false; BlockAccessScope = $null; NotifyUser = @('LastModifier'); Mode = 'Enable' }
    @{ Name = 'Drawings shared outside'; ParentPolicyName = 'Project drawings leaving the company'; Disabled = $false; Priority = 0; ReportSeverityLevel = 'Medium'; BlockAccess = $false; BlockAccessScope = $null; NotifyUser = @('LastModifier'); Mode = 'TestWithNotifications' }
)
Write-Demo 'pv-07-alert-policies' @(
    'Suspicious email sending patterns detected', 'Suspicious connector activity', 'Suspicious email forwarding activity', 'Messages have been delayed',
    'Tenant restricted from sending unprovisioned email', 'Tenant restricted from sending email', 'Elevation of Exchange admin privilege' | ForEach-Object {
        @{ Name = $_; Disabled = $false; Severity = 'High'; Category = 'ThreatManagement'; ThreatType = 'Activity'; IsSystemRule = $true; NotifyUser = @('TenantAdmins'); NotificationEnabled = $true }
    }
)
Write-Demo 'pv-03-retention-policies' @(
    @{ Name = 'Mail - 7 years'; Enabled = $true; Mode = 'Enforce'; Workload = 'Exchange'; DistributionStatus = 'Success'; RestrictiveRetention = $false; ExchangeLocation = @('All'); SharePointLocation = @(); OneDriveLocation = @(); TeamsChatLocation = @(); TeamsChannelLocation = @(); ModernGroupLocation = @(); WhenChanged = Get-DemoDate 300 }
    @{ Name = 'Project sites - 10 years'; Enabled = $true; Mode = 'Enforce'; Workload = 'SharePoint, OneDriveForBusiness'; DistributionStatus = 'Success'; RestrictiveRetention = $false; ExchangeLocation = @(); SharePointLocation = @('All'); OneDriveLocation = @('All'); TeamsChatLocation = @(); TeamsChannelLocation = @(); ModernGroupLocation = @(); WhenChanged = Get-DemoDate 300 }
)
Write-Demo 'pv-04-insider-risk-policies' @()
Write-Demo 'pv-04-communication-compliance' @()
Write-Demo 'pv-05-audit-retention-policies' @(@{ Name = 'Sign-ins and admin actions - 1 year'; RetentionDuration = 'OneYear'; Priority = 1; RecordTypes = @('AzureActiveDirectory', 'ExchangeAdmin') })
Write-Demo 'pv-08-role-groups' @(@{ Name = 'ComplianceAdministrator'; Members = @('Riley Okonkwo'); Roles = @('Case Management', 'Compliance Administrator') }, @{ Name = 'eDiscoveryManager'; Members = @('Morgan Fairbanks'); Roles = @('Case Management', 'Review') })
Write-Demo 'gov-01-access-reviews' @(
    @{ DisplayName = 'Quarterly - guests in project teams'; Status = 'InProgress'; Recurring = $true; ScopeQuery = "/groups?`$filter=(groupTypes/any(c:c+eq+'Unified'))/members/microsoft.graph.user/?`$filter=(userType eq 'Guest')"; AutoApply = $true }
    @{ DisplayName = 'Quarterly - privileged roles'; Status = 'NotStarted'; Recurring = $true; ScopeQuery = '/roleManagement/directory/roleAssignmentScheduleInstances'; AutoApply = $true }
)
Write-Demo 'gov-02-access-packages-summary' @{ Packages = 2; Catalogs = 1; ConnectedOrganizations = 1 }
Write-Demo 'gov-03-lifecycle-workflows' @(@{ DisplayName = 'Joiner - first day'; Category = 'joiner'; IsEnabled = $true }, @{ DisplayName = 'Leaver - last day'; Category = 'leaver'; IsEnabled = $true })
$pimGroupRows = @($groupPeople | Where-Object { $_.Membership -eq 'EligibleMember' } | ForEach-Object { [ordered]@{ Id = "pg-$($_.Who.Id)"; GroupId = '22222222-2222-2222-2222-222222222202'; AccessId = 'member'; PrincipalId = $_.Who.Id; Status = 'Provisioned'; MemberType = 'Direct' } })
Write-Demo 'gov-04-pim-groups' $pimGroupRows
Write-Demo 'gov-04-pim-groups-summary' @{ EligibleAssignments = $pimGroupRows.Count; Groups = 1; RoleAssignableGroups = 2; GroupsRead = 2 }
Write-Demo 'gov-05-administrative-units' @()
Write-Demo 'az-11-m365-backup' @{ ServiceStatus = 'enabled'; SharePointPolicies = 1; OneDrivePolicies = 1; ExchangePolicies = 1 }

# --- The run's own files -------------------------------------------------------------------------------------------------------------
# Power BI and Power Platform: a tenant that approved the optional reads. Mostly sound, with the gaps most tenants have:
# guests open shared Power BI content everywhere, trial environments are open to anyone, only the default environment
# has a DLP policy, and tenant isolation is off.
$setting = { param([string] $Name, [string] $Title, [string] $Group, [bool] $Enabled, [string[]] $Groups = @()) @{ SettingName = $Name; Title = $Title; Group = $Group; Enabled = $Enabled; CanSpecifySecurityGroups = $true; EnabledSecurityGroups = @($Groups); ExcludedSecurityGroups = @() } }
Write-Demo 'pbi-01-tenant-settings' @(
    (& $setting 'PublishToWeb' 'Publish to web' 'Export and sharing settings' $false)
    (& $setting 'AllowGuestUserToAccessSharedContent' 'Guest users can access Microsoft Fabric' 'Export and sharing settings' $true)
    (& $setting 'ExternalSharingV2' 'Users can invite guest users to collaborate through item sharing and permissions' 'Export and sharing settings' $true @('SG-PowerBI-ExternalSharing'))
    (& $setting 'ServicePrincipalAccessPermissionAPIs' 'Service principals can call Fabric public APIs' 'Developer settings' $false)
    (& $setting 'AllowServicePrincipalsCreateAndUseProfiles' 'Allow service principals to create and use profiles' 'Developer settings' $false)
    (& $setting 'BlockResourceKeyAuthentication' 'Block ResourceKey Authentication' 'Developer settings' $false)
    (& $setting 'RScriptVisual' 'Interact with and share R and Python visuals' 'R and Python visuals settings' $true)
    (& $setting 'EimInformationProtectionEdit' 'Allow users to apply sensitivity labels for content' 'Information protection' $true)
    (& $setting 'ExportToExcelSetting' 'Export to Excel' 'Export and sharing settings' $true)
)
Write-Demo 'pp-01-tenant-settings' @{
    walkMeOptOut = $false; disableNPSCommentsReachout = $false; disableNewsletterSendout = $false; disableEnvironmentCreationByNonAdminUsers = $true; disablePortalsCreationByNonAdminUsers = $true
    disableSurveyFeedback = $false; disableTrialEnvironmentCreationByNonAdminUsers = $false; disableCapacityAllocationByEnvironmentAdmins = $false; disableSupportTicketsVisibleByAllUsers = $false
    powerPlatform = @{ powerApps = @{ disableShareWithEveryone = $true; enableGuestsToMake = $false }; search = @{ disableDocsSearch = $false } }
}
$defaultEnvironment = "Default-$tenantId"
Write-Demo 'pp-02-environments' @(
    @{ Name = $defaultEnvironment; DisplayName = 'Fernquill Engineering (default)'; IsDefault = $true; Sku = 'Default'; Location = 'unitedstates'; CreatedTime = Get-DemoDate 900 }
    @{ Name = '5c1a0f6e-7d2b-4c3a-9e41-2b7f0a6d1c01'; DisplayName = 'Field apps'; IsDefault = $false; Sku = 'Production'; Location = 'unitedstates'; CreatedTime = Get-DemoDate 420 }
    @{ Name = '5c1a0f6e-7d2b-4c3a-9e41-2b7f0a6d1c02'; DisplayName = 'Sandbox - finance'; IsDefault = $false; Sku = 'Sandbox'; Location = 'unitedstates'; CreatedTime = Get-DemoDate 75 }
)
Write-Demo 'pp-03-dlp-policies' @(@{ Name = 'd0b6a1e2-3f44-4a55-8c66-7d8e9f0a1b2c'; DisplayName = 'Default environment guardrail'; EnvironmentType = 'OnlyEnvironments'; Environments = @($defaultEnvironment) })
Write-Demo 'pp-04-tenant-isolation' @{ IsDisabled = $true; AllowedTenants = 0 }

$collectors = @('Entra', 'SignIns', 'Intune', 'Defender', 'Exchange', 'Purview', 'SharePoint', 'Teams', 'PowerBI', 'PowerPlatform')
$started = $AsOf.AddMinutes(-23)
Write-Demo 'collection' @{
    product = 'TenantKeep Posture'; moduleVersion = '0.9.0'; collectors = $collectors; tenantId = $tenantId; account = "posture-run@$domain"; authType = 'Delegated'
    timestampUtc = $started.ToString('o'); completedUtc = $AsOf.ToString('o'); graphApiVersions = @('v1.0', 'beta'); staleDays = 90; errorCount = 0; errors = @(); files = @($written)
    modules = @{ 'Microsoft.Graph.Authentication' = '2.36.1'; ExchangeOnlineManagement = '3.9.2'; 'PnP.PowerShell' = '3.1.0'; MicrosoftTeams = '7.5.0' }
    powerShell = '7.5.4'; os = 'Demo'; timings = [ordered]@{ Entra = @{ seconds = 312; steps = 41 }; SignIns = @{ seconds = 95; steps = 1 }; Intune = @{ seconds = 248; steps = 33 }; Defender = @{ seconds = 61; steps = 7 }; Exchange = @{ seconds = 304; steps = 38 }; Purview = @{ seconds = 133; steps = 10 }; SharePoint = @{ seconds = 120; steps = 6 }; Teams = @{ seconds = 44; steps = 8 } }
}
# The client folder: the profile the wizard would write after discovery and its questions, and one accepted risk.
$profileDoc = [ordered]@{
    version = 1; tenantId = $tenantId; clientName = 'Fernquill Engineering'
    licenses = @('E5', 'P1', 'P2', 'Intune', 'MDO1', 'MDO2', 'MDE1', 'MDE2', 'MDI', 'MDCA', 'IP1', 'Purview', 'Copilot', 'SAM')
    platforms = @('windows', 'macOS', 'iOS', 'android'); identityModel = 'cloud-only'; byod = 'mam'; externalCollaboration = 'governed'; copilot = 'pilot'; azure = 'none'
    thirdParty = [ordered]@{ email = 'none'; edr = 'none'; mfa = 'none'; mdm = 'none'; macMdm = 'none'; siem = 'Microsoft Sentinel'; backup = 'Microsoft 365 Backup'; swg = 'none'; ztna = 'none'; training = 'none' }
    frameworks = @('nist-csf-2', 'cisa-scuba'); audience = 'technical'; cadence = 'quarterly'
    thresholds = [ordered]@{ maxPermanentGlobalAdmins = 2; staleDeviceDays = 90; inactiveGuestDays = 90; namePattern = '^CA-\d{3}-' }
    breakGlass = @("breakglass01@$initial", "breakglass02@$initial")
    operations = [ordered]@{ breakGlassTestedUtc = $AsOf.AddDays(-52).ToString('o'); messageCenterOwner = 'IT team (Avery Holloway)'; siemConnected = $true; backupTestedUtc = $AsOf.AddDays(-30).ToString('o') }
    attestations = [ordered]@{ copilotSettingsReviewedUtc = $AsOf.AddDays(-20).ToString('o') }
    createdUtc = $AsOf.AddDays(-90).ToString('o'); updatedUtc = $started.ToString('o')
}
[System.IO.File]::WriteAllText((Join-Path $clientPath 'profile.json'), (ConvertTo-Json -InputObject $profileDoc -Depth 6), $utf8)
$exceptionsDoc = @{ exceptions = @([ordered]@{ check = 'EM-015'; object = $null; justification = 'MTA-STS waits for the DNS provider move in the first quarter.'; owner = 'Jordan Lindqvist'; approver = 'Avery Holloway'; expires = $AsOf.AddDays(120).ToString('yyyy-MM-dd'); recordedUtc = $AsOf.AddDays(-14).ToString('o') }) }
[System.IO.File]::WriteAllText((Join-Path $clientPath 'exceptions.json'), (ConvertTo-Json -InputObject $exceptionsDoc -Depth 6), $utf8)
$runJson = @{ tenantId = $tenantId; client = $clientPath; startedUtc = $started.ToString('o'); planned = $collectors; skipped = @{ Azure = 'not part of the demo tenant'; ActiveDirectory = 'cloud-only tenant' }; runAs = @{ account = "posture-run@$domain"; roles = @('Global Reader', 'SharePoint Administrator'); checkedUtc = $started.ToString('o'); coverage = @($collectors | ForEach-Object { @{ collector = $_; status = 'full'; detail = 'every step this account can read' } }) } }
[System.IO.File]::WriteAllText((Join-Path $root 'logs' 'run.json'), (ConvertTo-Json -InputObject $runJson -Depth 6), $utf8)
[System.IO.File]::WriteAllText((Join-Path $root 'errors' 'errors.jsonl'), '', $utf8)
[pscustomobject]@{ Path = $root; Evidence = $ev; Client = $clientPath; Files = $written.Count; Users = $users.Count; Devices = $fleet.Count }
