# Evidence collection

`Start-PostureRun` signs in once and runs everything on this page, in the right processes, from that sign-in
(docs/guide.md section 1). What follows is what each collector writes and what it needs, for reading a run folder and
for the manual path, where you open each session yourself.

`Invoke-PostureCollection` writes one run folder, `<OutRoot>/<yyyyMMdd-HHmm>/`, with the audit plan's file names
(Appendix A) so findings and checks reference the same evidence whether it came from the module or from the
original scripts. Read-only. Every step is independent: a permission failure is one line in `errors.txt` and the
run continues.

A list marked (+csv) is written twice, as a JSON array and as a CSV with the same rows. Everything that runs
after collection reads the lists with a row per user, device, group, mailbox or site from the CSV, a row at a
time, or reads a summary the collector counted while writing the list; none of them is loaded whole, which keeps
the report's memory about the same on a tenant of 300 users and one of 300,000. Dates in the CSV are ISO
8601 in UTC (`2026-11-15T02:03:22Z`), the same instant the JSON carries. CSV files written before 2026-11-21 carry
dates with no zone (`11/15/2026 02:03:22`); those are UTC too, and are read as UTC.

A list is written to `<name>.json.part` and `<name>.csv.part` and takes its name when it is finished, so nothing
ever reads half a list. Collected again into the same run folder (`Resume-PostureRun`, or `-OutputFolder`), a long
list that finished there less than a day ago is kept, and a Graph list that stopped part way carries on from its
cursor in `logs/`. The run's journal, `logs/journal.jsonl`, records every step, file and domain as it happens; it is
what says a list finished, and what says a file is left from an earlier attempt and must not be read.

## What the Entra collector writes

| File | Source | Notes |
|---|---|---|
| `01-organization`, `01-subscribed-skus` (+csv), `01-onprem-sync-features` | organization, subscribedSkus, directory sync | SKUs feed `New-PostureProfile -Evidence`; sync features need OnPremDirectorySynchronization.Read.All |
| `02-*` tenant policies | authorization, security defaults, authentication methods, strengths, admin consent, cross-tenant access | |
| `04-role-definitions`, `04-role-assignments-active` (+csv), `04-role-assignments-pim-eligible` (+csv), `04-role-assignments-summary` | PIM schedule instances; plain role assignments when PIM is unavailable | Needs RoleManagement.Read.Directory for PIM |
| `04-role-holders` (+csv), `04-role-holders-summary` | groups/{id}/transitiveMembers for each group that holds a role; PIM for Groups eligibilitySchedules for the same groups where the tenant has PIM | One row per person and role: `Held` is Direct, Eligible, Group or EligibleGroup, with the group and the kind of membership. Every admin set (registration, users, sign-in tallies, the checks, the admins table) reads it. A group that could not be opened is named in the summary (`GroupsNotRead`, `EligibleMembersNotRead`), the step is logged as failed, and the checks that count administrators say what they did not see. Needs Group.Read.All and, for who can join, PrivilegedEligibilitySchedule.Read.AzureADGroup (verify: a Global Reader can read the members of a role-assignable group) |
| `04-pim-role-policies` (+csv) | roleManagementPolicyAssignments with rules | Activation MFA, justification, max duration, approval per role; feeds ID-006 |
| `05-auth-registration` (+csv), `05-auth-registration-summary` | userRegistrationDetails report | Needs AuditLog.Read.All and UserAuthenticationMethod.Read.All. The summary carries `Tally` (users, self-service reset enabled, phishable, phishable administrators), counted in the same pass, so the report reads the counts and never the list |
| `05-per-user-mfa` (+csv), `05-per-user-mfa-summary` | users/{id}/authentication/requirements, batched 20 per request | Legacy per-user MFA state; feeds AU-009. Every member up to 5,000. Above that a sample: every administrator and 1,000 other members at random, and the summary (`Mode`, `SampledAdmins`, `SampledMembers`) and the check say so. `-FullPerUserMfa` reads everyone, a request per account; `-SkipPerUserMfa` leaves it out |
| `08-entra-devices` (+csv), `08-entra-devices-by-join-os`, `08-entra-devices-stale` | devices | Join type and staleness against StaleDays; feeds the devices domain |
| `06-users` (+csv), `06-users-summary` | users with signInActivity; retried without it when AuditLog.Read.All is missing | `SignInActivityAvailable` in the summary says which |
| `07-groups` (+csv), `07-groups-summary` | groups with Kind and Dynamic | The summary is counted as the list is written: groups, by kind, role-assignable, synced, licensed, dynamic |
| `10-app-registrations`, `10-service-principals`, `10-graph-app-permissions`, `10-oauth2-delegated-grants` (+csv) | applications, servicePrincipals, Graph appRoleAssignedTo, oauth2PermissionGrants | Credential expiry and SAML certificate expiry computed |
| `11-risky-users`, `11-risk-detections-30d` (+csv) | Identity Protection | P2; denied without it and logged. Risky users are the ones at risk now (`riskState` atRisk or confirmedCompromised), not everyone who ever had a risk |
| `gov-01-access-reviews` (+csv) | identityGovernance/accessReviews/definitions | Scope queries joined, recurrence; needs AccessReview.Read.All |
| `gov-02-access-packages` (+csv), `gov-02-access-packages-summary` | entitlementManagement packages, catalogs, connected organizations | EntitlementManagement.Read.All |
| `gov-03-lifecycle-workflows` (+csv) | lifecycleWorkflows/workflows | LifecycleWorkflows.Read.All |
| `gov-04-pim-groups` (+csv), `gov-04-pim-groups-summary` | privilegedAccess/group/eligibilitySchedules | PrivilegedEligibilitySchedule.Read.AzureADGroup (verify). Read once per role-assignable group, every one of them; the summary records `RoleAssignableGroups` and `GroupsRead`, and GV-006 has no answer when fewer were read and none of those is under PIM |
| `gov-05-administrative-units` (+csv) | directory/administrativeUnits | AdministrativeUnit.Read.All |
| `01-domains` (+csv) | domains with authentication type and password expiry | Federated domains feed the identity model discovery; expiry feeds ID-017 |
| `01-company-branding` | organization/{id}/branding | Presence only (logo, background, sign-in text); a 404 means no branding |
| `02-directory-settings` | groupSettings | Tenant directory settings; Password Rule Settings feed ID-018 and ID-019. The banned password list is kept as a count, never its words |
| `gsa-01-forwarding-profiles`, `gsa-02-filtering-profiles`, `gsa-03-settings` | networkAccess (beta) | Read only where the tenant holds Internet Access or Private Access; NetworkAccess.Read.All |
| `policies`, `named-locations`, `auth-strengths`, `auth-context`, `resolved-names`, `group-scope`, `metadata` | Export-PostureCaSnapshot into the same folder | The CA checks and documents read these |
| `collection` | run manifest: tenant, account, scopes, API versions, files, errors | `metadata.json` stays the CA snapshot's own |

Users and groups carry `Source`: ActiveDirectory (synced), EntraFromAD (came from AD, source of authority switched to
Entra) or Cloud. Microsoft's own flag for the switch (onPremisesSyncBehavior isCloudManaged) needs a write permission
even to read, so the collector infers it: after the switch onPremisesSyncEnabled is empty, as for a cloud object, and
the object keeps its AD security identifier (verify on a tenant that has switched a group). Groups also carry
`Licensed`. 06-users-summary counts `EntraManagedFromAd`. HY-032 and HY-033 read them with the Conditional Access
snapshot.

## What the Intune collector writes

| File | Source | Notes |
|---|---|---|
| `09-intune-managed-devices` (+csv), `09-intune-summary-os-agent-join`, `09-intune-summary-compliance`, `09-intune-summary-windows-builds` | managedDevices (beta, for joinType and autopilotEnrolled) | |
| `09-autopilot-devices` (+csv) | windowsAutopilotDeviceIdentities | |
| `09-intune-compliance-policies`, `09-intune-config-profiles-templates`, `09-intune-config-profiles-settings-catalog`, `09-intune-apps` (+csv) | compliance policies, device configurations, configurationPolicies (beta) with template family and assignment counts, mobile apps | Endpoint security policies are settings catalog policies with a `TemplateFamily` |
| `09-apple-push-cert`, `09-apple-vpp-tokens` (+csv) | APNs certificate, VPP tokens | Expiry feeds DEV-008 |
| `09-intune-enrollment-restrictions` (+csv) | deviceEnrollmentConfigurations (beta) | Per-platform personal enrollment blocked (verify the newer per-platform shape) |
| `09-intune-mde-connector` (+csv) | mobileThreatDefenseConnectors (beta) | (verify) partner identification |
| `09-intune-device-cleanup` | managedDeviceCleanupSettings (beta) | (verify) endpoint |
| `08-bitlocker-keys-by-device` (+csv), `08-bitlocker-keys-summary` | informationProtection/bitlocker/recoveryKeys, ids only | Key presence per device; the key material is never read |
| `09-intune-policy-settings` (+csv) | configurationPolicies/{id}/settings (beta) for every assigned settings catalog policy | One row per setting instance, recursed through choice children and groups; the endpoint facts match on the definition ids |
| `09-intune-config-profile-settings` (+csv), `09-intune-compliance-policy-settings` (+csv) | scalar properties of assigned template profiles and compliance policies | Update ring deadlines, jailbreak detection, SIP, SmartScreen in classic profiles |
| `09-intune-windows-hello` | the tenant-wide windowsHelloForBusinessConfiguration | |
| `09-intune-app-protection-policies` (+csv) | managedAppPolicies | iOS and Android, with IsAssigned |
| `09-intune-feature-update-profiles` (+csv) | windowsFeatureUpdateProfiles (beta) | |

Scopes: DeviceManagementManagedDevices.Read.All, DeviceManagementConfiguration.Read.All,
DeviceManagementServiceConfig.Read.All, DeviceManagementApps.Read.All, BitLockerKey.ReadBasic.All.

The managed device list (`09-intune-managed-devices`) carries `IntuneWorkloads` for co-managed Windows devices: the
co-management workloads Intune holds (compliance policies, device configuration, Windows Update policies, endpoint
protection, resource access, client apps, Office Click-to-Run, inventory), from Graph's
configurationManagerClientEnabledFeatures (verify on a co-managed tenant). `09-intune-comanagement` counts them across
the co-managed devices. With the Entra device list, the devices checks tell Intune alone, co-managed, Configuration
Manager alone (tenant attach) and hybrid-joined devices that nothing in the cloud manages (DEV-019 to DEV-021). With
the AD collector's `ad-06-computers`, DEV-020 also counts workstations in use in AD (not servers or domain controllers)
whose names Entra does not know at all; the collector's summary now carries `ActiveWindowsWorkstations`.

`09-intune-compliance-partners` (beta) and `09-intune-device-management-partners` (v1.0) list the MDMs connected to
Intune, Jamf for Macs being the usual one: the platforms each is onboarded for, its state and its last heartbeat
(DeviceManagementServiceConfig.Read.All). DEV-022 asks that a Mac MDM report compliance to Intune, DEV-023 that its Macs
come through as compliant in Entra; the profile's `thirdParty.macMdm` is filled from a connected partner while it says
none, and covers the macOS checks Intune would otherwise judge.

## What the Exchange collector writes

Needs a connected Exchange Online PowerShell session (ExchangeOnlineManagement 3.x, `Connect-ExchangeOnline`), with
Global Reader, View-Only Organization Management or an equivalent read-only role. The module never connects; with no session the
collector is skipped with a warning, or refused when `-Collector Exchange` was asked for by name. Every cmdlet goes
through one `Get-` only entry point, so a write is impossible by construction. Rich cmdlet objects are projected to
scalars and string lists before they are written.

| File | Source | Notes |
|---|---|---|
| `exo-01-orgconfig`, `exo-01-transport-config`, `exo-01-auth-policies`, `exo-01-audit-config` | organization, transport and audit config, authentication policies | SMTP AUTH, ARC sealers, mailbox audit default, unified audit log |
| `exo-02-accepted-domains`, `exo-02-dkim` | accepted domains, DKIM signing config | |
| `exo-03-inbound-connectors`, `exo-03-outbound-connectors`, `exo-03-transport-rules` | connectors, mail flow rules | Enhanced Filtering fields, SCL -1 rules with their scope |
| `exo-04-eop-content-filter`, `exo-04-eop-connection-filter`, `exo-04-eop-malware`, `exo-04-antiphish`, `exo-04-outbound-spam` | EOP policies | Full property set |
| `exo-04-preset-rules-eop`, `exo-04-preset-rules-mdo` | preset security policy rules | The scope columns say whether Standard or Strict reaches everyone |
| `exo-05-mdo-safelinks`, `exo-05-mdo-safeattachments`, `exo-05-mdo-global`, `exo-05-quarantine-policies` | Defender for Office 365 policies | Absent or denied without MDO; logged |
| `exo-06-remote-domains`, `exo-06-sharing-policies`, `exo-06-owa-policies` | remote domains, sharing, OWA policies | |
| `exo-07-eas-org-settings`, `exo-07-mobile-device-policies` | ActiveSync | |
| `exo-08-role-groups` | role groups with members | |
| `exo-09-mailboxes` (+csv), `exo-09-mailboxes-by-type`, `exo-09-mailboxes-with-forwarding` | Get-EXOMailbox, unlimited | Forwarding, holds, audit flag, the Entra object id for the shared mailbox join. `-SkipMailboxEnumeration` at very large sizes |
| `exo-10-cas-mailboxes` (+csv), `exo-10-cas-summary` | Get-EXOCASMailbox, unlimited | POP, IMAP, ActiveSync, SMTP AUTH override per mailbox |
| `exo-11-attack-simulations` (+csv) | Graph security/attackSimulation/simulations | Only with AttackSimulation.Read.All; skipped quietly otherwise |
| `dns-01-mail-records` (+csv) | public DNS through dig (Resolve-DnsName on Windows) | MX, SPF, DMARC, MTA-STS and TLS-RPT per custom authoritative domain; the initial onmicrosoft.com domain is left out. `LookupFailed` lists the records whose lookup got no answer (a timeout, a server failure); the checks read those as unknown, never as not published |

```powershell
Connect-ExchangeOnline -UserPrincipalName reader@contoso.example -ShowBanner:$false
Invoke-PostureCollection -OutRoot ~/tenantkeep/evidence        # Entra, Intune and Exchange into one folder
```

Not yet collected: inbox rules forwarding externally (spec 4.10, needs an audit search at scale) and Maester (A.4).

## What the sign-in read writes

The `SignIns` collector reads the Entra sign-in log for the last 7 days (`-SignInDays`, up to 30) a page at a time
and keeps counts, never the records. It needs AuditLog.Read.All and Entra ID P1.

| File | Notes |
|---|---|
| `06-signins-summary` | Totals, by client app, by Conditional Access status, by day and country, failures by error code, what each report-only policy would have done, administrators' sign-ins, and the addresses many accounts failed from (`SprayAddresses`). `Scope` says what is counted: interactive user sign-ins |
| `06-signins-legacy-users` (+csv) | The accounts that signed in with a legacy client app, most active first (500 at most; the summary's `LegacyUsers` is the number of different accounts) |

While the read is under way a checkpoint, `.signins-checkpoint.json`, is saved every ten pages so a failure or a
restart carries on from where it stopped; it is removed when the read ends. Where the question is only how many
different accounts (per address, per report-only policy, legacy in all), an account is remembered by a keyed hash
made for that read, so neither the counts nor the checkpoint hold a list of who failed to sign in from where. An
address keeps 200 accounts at most, and `AccountsFailedOrMore` says when it met that.

`exo-12-remote-powershell-users` (+summary) is about the accounts with Exchange Online PowerShell on (Get-User filtered
on RemotePowerShellEnabled; left out with -SkipMailboxEnumeration). The setting is on for everyone by default, so the
collector counts them all and lists the first 500 that are people and, when the Entra evidence is in the same run
folder, not administrators; the summary carries `RemotePowerShellEnabled`, `NonAdmin`, `Listed` and `AdminsExcluded`.
When the Exchange Online PowerShell app is closed to everyone but assigned people the read is skipped (`Skipped` says
so), and EM-025 passes on the app alone.

For the user experience checks, the Exchange collector also writes `exo-13-external-in-outlook` (the built-in External
tag), `exo-13-report-submission` (user reported settings, the Report button), and `exo-01-orgconfig` carries the MailTips
for outside recipients and large audiences and auto-expanding archiving. The Entra collector writes
`02-auth-system-preferred` (beta: system-preferred MFA); the Intune collector's app protection policies carry the PIN,
fingerprint and Face ID settings.

## What the Defender collector writes

Graph only, on the same session as the Entra collector: advanced hunting is a query-style POST that changes nothing.
Scopes: ThreatHunting.Read.All (hunting), SecurityIncident.Read.All (incidents), SecurityEvents.Read.All (Secure
Score). Skipped with a warning when ThreatHunting.Read.All is missing. The device tables are read in 16 shards by
the first character of the device id, to stay under the row cap of one query (10,000 rows when this was written
(verify); the cap is the service's to change). One query per table first asks how many rows each shard has, and
the summary records `RowsExpected`, `RowsRead` and `Truncated`. A shard that returns fewer rows than it has is read
again in sixteen parts, by the second character of the id. When it is still short after that, the list is cut
short and the checks that count devices over it (EP-019, EP-020, EP-021) have no answer, with the two numbers as
the reason. Needs Defender for Endpoint P2 for the configuration and vulnerability tables (verify: P1
answers DeviceInfo only).

| File | Source | Notes |
|---|---|---|
| `def-01-devices` (+csv), `def-01-devices-summary` | DeviceInfo, last 7 days, latest row per device | Onboarding, sensor health, exposure; joined to Intune on the Entra device id for coverage |
| `def-02-av-state` (+csv), `def-02-av-state-summary` | DeviceTvmInfoGathering | Antivirus mode and signature state (verify field names and mode values) |
| `def-03-secure-config` (+csv) | DeviceTvmSecureConfigurationAssessment joined to its KB | Compliant and applicable device counts per configuration; the facts match on names and subcategory (verify) |
| `def-04-vulnerabilities-summary`, `def-04-vulnerabilities-top` (+csv) | DeviceTvmSoftwareVulnerabilities joined to its KB | Critical CVEs, over 30 days since publication, top 50 by device count |
| `def-05-incidents` (+csv), `def-05-incidents-summary` | security/incidents, active | Open over 7 days, unassigned |
| `def-06-secure-score`, `def-06-secure-score-controls` (+csv) | security/secureScores, secureScoreControlProfiles | Spec 4.12: reported beside the posture score, never the grade |

## What the Azure collector writes

On a `Connect-AzAccount` session with Reader on the subscriptions (or the management group) and Security Reader.
Resource Graph at tenant scope carries the fleet-wide reads; Resource Manager GET calls go to every enabled
subscription for six things: Defender plans, security contacts, activity log export, classic administrators,
budgets and pay-as-you-go spend. A subscription that refuses one of them costs its own rows and nothing else: the
others are read and written, the step is logged once with how many refused, and `az-01-subscriptions` says per
subscription whether every read went through (`DetailRead`, and `DetailError` with the refusal). The checks on
those files judge the subscriptions that were read and no others: a gap among them is a finding whose reason says
"Judged on N of M subscriptions", and with no gap among them the check has no answer for the tenant. Throttling
(429) and a busy service are waited out, after Retry-After when Azure sends one. Resource Graph is paged by its
skip token, and by position when a full page comes with none ((verify) live). Both go through Get-only entry
points. Sign in to Graph before importing Az.Accounts in the same
process: imported first, Az breaks `Connect-MgGraph` with "Entry point was not found" (observed 2026-10-15 on macOS). On macOS the Az browser sign-in can hit the same MSAL
conflicts as the others. What works (confirmed 2026-10-15): a token from the Azure CLI with the classic Resource
Manager audience, handed to Az.Accounts:

```powershell
az login --tenant <tenant id>
$arm = az account get-access-token --tenant <tenant id> --resource https://management.core.windows.net/ --query accessToken -o tsv
Connect-AzAccount -AccessToken $arm -AccountId <upn> -Tenant <tenant id> -SkipContextPopulation
```

With the `https://management.azure.com` audience the context is created but every call fails as expired. The token
lasts about an hour; the collector finishes well inside that on a few hundred subscriptions.

| File | Source | Notes |
|---|---|---|
| `az-01-subscriptions` (+csv), `az-01-management-groups` (+csv) | resourcecontainers | Management group chain; subscriptions at the tenant root |
| `az-02-defender-pricings` (+csv), `az-02-security-contacts` (+csv) | Microsoft.Security pricings and securityContacts per subscription | (verify) contact shape |
| `az-02-secure-scores` (+csv), `az-02-assessments-summary` (+csv), `az-02-assessments-top` (+csv) | securityresources | Microsoft's numbers, reported beside the posture score |
| `az-03-policy-assignments` (+csv) | policyresources | Benchmark assignments flagged |
| `az-04-activity-log-exports` (+csv) | Microsoft.Insights diagnosticSettings per subscription | |
| `az-05-role-assignments` (+csv), `az-05-role-definitions-custom` (+csv), `az-05-classic-administrators` (+csv) | authorizationresources, classicAdministrators | Role names resolved, scope level and subscription parsed; joined to 06-users, 07-groups and 10-service-principals by the facts |
| `az-06-resources-by-type` (+csv), `az-06-resources-summary`, `az-06-locks` (+csv), `az-06-vaults` (+csv) | resources | Tags, orphans, delete locks on Key Vaults and Recovery Services vaults |
| `az-07-keyvaults` (+csv), `az-07-storage` (+csv), `az-07-sql-servers` (+csv) | resources | Access model, purge protection, shared keys, anonymous blobs, TLS, Entra-only SQL |
| `az-08-entra-connect-health` (+csv) | Microsoft.ADHybridHealthService (verify) | Feeds OP-007 |
| `az-09-entra-diagnostic-settings` (+csv) | microsoft.aadiam diagnosticSettings | Feeds ID-014: sign-in and audit logs to a workspace or event hub |

Also from the Azure collector: `az-12-open-management-ports` (inbound allow rules from anywhere for SSH, RDP and WinRM on
network security groups in use), `az-13-budgets` (budgets per subscription), `az-14-backup-vaults` (soft delete and
immutability on Recovery Services and Backup vaults), `az-15-sentinel` (Sentinel workspaces and their data connector
kinds) and `az-16-entra-domain-services` (the managed domain's security settings), read through Resource Graph and ARM
GETs (verify the vault, Sentinel and Entra Domain Services property paths on a tenant that has them). The Defender
collector's Secure Score controls carry each control's points and Microsoft's action link.

## What the Windows collector writes (hybrid)

collectors/windows/Get-ADBaseline.ps1 is Windows-only and runs outside the module: once, on any domain-joined machine
with RSAT (ActiveDirectory; GroupPolicy for the GPO inventory), as a domain user. It writes ad-01 to ad-10 (forest and
domain, trusts, domain controllers, privileged groups and admin accounts, krbtgt and built-in accounts, delegation,
Kerberoastable and AS-REP roastable accounts, LAPS coverage and computers, users, GPOs with a cpassword scan, AD CS
templates with ESC1 candidates, the seamless SSO and cloud Kerberos accounts) plus errors.txt, a transcript and
bundle.json (every file with its SHA-256, and the forest's domains and UPN suffixes). `Export-PostureCollector -Kind
ActiveDirectory -Run <run folder>` writes the script and a RUN-ME.txt to carry to that machine. Bring the folder it
writes into the run with `Import-PostureEvidence -Path <folder> -Run <run folder>`; the hybrid checks evaluate from it
next to the Entra-side facts (sync features, federation, Connect Health) the cloud collectors already wrote. Nothing is
installed or scheduled.

On a large domain: users and computers are read through the pipeline and counted as they arrive, never held as a
list. GPO links come from one directory query for `gPLink`, and passwords stored in Group Policy Preferences from one
pass over the preference files in SYSVOL (`ad-08-gpos-summary` says whether SYSVOL could be read; when it could not,
HY-030 has no answer instead of "none"). The collector reads one domain for each run. `ad-01-forest-domain` records
the forest's domains and the one that was read, and on a forest with more than one the checks on accounts, groups,
policies and computers say which domain they judged: a finding stands with that note, and where nothing was found
there is no answer for the forest. bundle.json carries the forest name, its domains and its UPN suffixes.

## What the Windows SharePoint collector writes

collectors/windows/Get-SpoBaseline.ps1 is the SharePoint admin read without any third-party app: Windows-only, outside
the module, on Microsoft's SharePoint Online Management Shell (Microsoft.Online.SharePoint.PowerShell), run by an
account holding SharePoint Administrator (activate it in PIM for the run). Before reading it looks up the tenant id
behind `-Tenant` in Microsoft's public sign-in metadata and refuses anything but `-TenantId`. Only Get-SPO commands run.
It writes the files the module's SharePoint collector writes, with the same names and properties:
`spo-tenant-settings.json`, `spo-restricted-search.json`, `spo-sites.csv` and `spo-sites-summary.json` (the site list
is left out with `-SkipSiteEnumeration`, and lists the OneDrives only with `-IncludeOneDriveSites`), plus errors.txt, a
transcript and bundle.json.

Split collection, for example most of a run on a Mac and SharePoint on a Windows cloud PC:

```powershell
# On the cloud PC, as the SharePoint admin
.\Get-SpoBaseline.ps1 -Tenant contoso -TenantId <tenant id> -OutputPath C:\audit\spo
# Where the run lives, after copying the folder (or a .zip of it) across
Import-PostureEvidence -Path ./spo -Run ~/tenantkeep/evidence/<stamp>
New-PostureReport -Evidence ~/tenantkeep/evidence/<stamp>
```

Import-PostureEvidence is the one way Windows-collected evidence enters a run. It checks every file against
bundle.json, refuses SharePoint evidence from another tenant, copies only the evidence files the checks read, refuses
to overwrite a different file already in the run unless `-Force`, adds the collector's errors.txt to the run's errors
and records the import, which Run Health lists, then rebuilds the run's report when it has one (`-NoReport` leaves
it). It also takes the evidence folder of a SharePoint-only run made with the module on another machine (the tenant
comes from that run).

Active Directory evidence has no tenant id in it, so it is tied to the tenant by name: one of the forest's UPN
suffixes (or its domains) must be a domain the run's tenant has verified, or sit under or over one. A forest that
shares none is refused, which is what keeps one client's domain controllers out of another client's report; `-Force`
accepts it, for a forest whose people sign in to Microsoft 365 with another name than their AD one. A collector
folder from before the suffixes were recorded, or a run without the tenant's domain list, is accepted with a warning
that says the check could not be made. `-Client <client folder>` also files the read in the client's `hybrid/`, and
`Start-PostureRun` brings that folder into each later run through the same checks; a folder that fails one is not
used and Run Health says why.

## What the Purview collector writes

Through Security and Compliance PowerShell (`Connect-IPPSSession`, ExchangeOnlineManagement 3.x; Compliance
Administrator, or Global Reader for most reads, verify). The A.2 pv-* files: `pv-01-sensitivity-labels` (+csv),
`pv-01-label-policies`, `pv-01-autolabel-policies`, `pv-02-dlp-policies` (+csv), `pv-02-dlp-rules` (+csv),
`pv-03-retention-policies`, `pv-03-retention-rules` (+csv), `pv-03-retention-labels` (+csv),
`pv-04-insider-risk-policies`, `pv-04-communication-compliance`, `pv-04-information-barriers`,
`pv-05-audit-retention-policies`, `pv-06-ediscovery-cases` (+csv), `pv-07-alert-policies` (+csv), `pv-08-role-groups`.
Purview and Exchange share cmdlet names (Get-RoleGroup is one), so run `-Collector Purview` in a process of its own
after `Connect-IPPSSession`, into the run folder the other collectors filled. The same Get-only entry point as
Exchange carries every call.

## What the SharePoint and Teams collectors write

| File | Source | Notes |
|---|---|---|
| `spo-tenant-settings` | Get-PnPTenant, the audit plan's property list plus a few | Sharing level, link defaults, anonymous link expiry, domain restrictions, Everyone claims, guest expiration, restricted access control, legacy auth |
| `spo-restricted-search` | Get-PnPTenantRestrictedSearchMode and its allow list | Copilot readiness C9 |
| `spo-sites` (+csv), `spo-sites-summary` | Get-PnPTenantSite -Detailed | Ownerless, anonymous-capable, labeled and restricted counts. The sites, not the OneDrives: there is one OneDrive per user and no check reads them. `-IncludeOneDriveSites` lists them as well (the summary then counts them apart; without it `OneDrives` is empty, which means not listed). `-SkipSiteEnumeration` leaves the list out |
| `teams-federation`, `teams-client-config`, `teams-meeting-policy-global`, `teams-guest-messaging` | the Teams tenant configurations and the Global meeting policy | Single objects |
| `teams-external-access` (+csv), `teams-app-permission-policies` (+csv), `teams-messaging-policies` (+csv) | the policy collections | App permission policies only decide CL-014 on a tenant not yet moved to app centric management |
| `teams-app-settings`, `teams-app-availability` (+csv) | Get-M365UnifiedTenantSettings and Get-AllM365TeamsApps | App centric management (tenants moved since April 2025): the org-wide default per kind of app, and each app's availability (everyone, named users and groups, no one) and whether it is blocked. CL-014 reads the third-party default (`GlobalApp`) |

The Entra collector adds `02-group-lifecycle-policy` and `07-groups-ownerless` (+summary) for the collaboration checks. The
oversharing views that need SharePoint Advanced Management reports (sites shared with Everyone except external users,
active anonymous links, inactive sites) are not collected yet.

## SharePoint and Teams setup

Without any SharePoint setup the SharePoint checks read Graph's SharePoint settings (the Entra collector, read-only
SharePointTenantSettings.Read.All): the tenant sharing level, domain restrictions, legacy authentication, and Anyone
links and OneDrive when the tenant rules Anyone out. The rest (default links, Anyone link expiry, guest expiry, the
Everyone claims, restricted access control, the site list, restricted search) needs the SharePoint admin read, which
needs SharePoint Administrator and one of:

- **TenantKeep Posture for SharePoint**, Kainor's second app, the only one asking for SharePoint full control. It is
  never consented for the organisation. A Global Administrator grants it to named admins and requires assignment:

  ```powershell
  Connect-MgGraph -TenantId <tenant id> -Scopes Application.ReadWrite.All, DelegatedPermissionGrant.ReadWrite.All, AppRoleAssignment.ReadWrite.All, User.Read.All -NoWelcome
  ./deploy/setup/Grant-PostureSharePointAccess.ps1 -TenantId <tenant id> -Admin spadmin@contoso.com
  ./deploy/setup/Grant-PostureSharePointAccess.ps1 -TenantId <tenant id> -Disable   # between runs; -Enable before the next
  ```

  Start-PostureRun asks Graph whether the app is granted to the account signed in; only then does a second browser
  window open (it goes straight through when that account is already signed in), and the SharePoint collector runs
  with that sign-in. Otherwise the run notes why in run health and carries on with Graph. By hand:
  `Connect-PostureSession -SharePoint` after `Connect-PostureSession`.
- **The Windows collector** (`collectors/windows/Get-SpoBaseline.ps1`) on Microsoft's SharePoint Online Management
  Shell, run by a SharePoint admin on Windows, with no third-party app at all; bring its folder into the run with
  `Import-PostureEvidence`.
- **An app registration of your own**, below.

PnP.PowerShell 3.x can also sign in through an Entra app registration of your own. `deploy/setup/New-PostureSharePointApp.ps1`
creates it with delegated permissions only (SharePoint AllSites.FullControl, which the tenant admin reads need and
which delegated means bound by the reader's own rights; Graph User.Read, Sites.Read.All, Group.Read.All), asks for admin consent, writes `sharePointClientId` into profile.json and prints the steps that
stay manual: consent if it was declined, the SharePoint Administrator role for the reading account, Conditional
Access on the new app, and the connect commands. It is a tenant write and lives outside the module for that reason;
run it once per tenant as an admin who can register apps. Delete the registration to revoke everything. With `-ClientId` and a Graph session holding Application.ReadWrite.All it
adds the SharePoint permission to an existing registration instead of creating one, and with
DelegatedPermissionGrant.ReadWrite.All grants the admin consent through Graph; the adminconsent web page does not work
for this app (AADSTS500113, its only reply address is localhost).

```powershell
./deploy/setup/New-PostureSharePointApp.ps1 -Tenant contoso.onmicrosoft.com -ProfilePath ~/tenantkeep/clients/contoso/profile.json
Connect-PnPOnline -Url https://contoso-admin.sharepoint.com -ClientId <sharePointClientId> -Interactive
Connect-MicrosoftTeams
```

On macOS, `Connect-MicrosoftTeams` with a browser fails with a kernel32.dll load error (MicrosoftTeams 7.9.0 on
PowerShell 7.6, confirmed 2026-10-14). Two ways around it, both outside the module: `Connect-MicrosoftTeams
-UseDeviceAuthentication`, or tokens from the Azure CLI:

```powershell
az login --tenant <tenant id> --allow-no-subscriptions
$graph = az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv
$teams = az account get-access-token --resource 48ac35b8-9aa8-4d74-927d-1f4a14a0b239 --query accessToken -o tsv
Connect-MicrosoftTeams -AccessTokens @($graph, $teams)
```

The same Azure CLI session can sign Exchange Online in without a browser, which also avoids a second macOS problem:
once PnP.PowerShell and MicrosoftTeams are loaded in a session, `Connect-ExchangeOnline` with a browser throws
PlatformNotSupportedException (observed 2026-10-14 on macOS 27 with ExchangeOnlineManagement 3.10). Connect Exchange
first in that session, or:

```powershell
$exo = az account get-access-token --resource https://outlook.office365.com --query accessToken -o tsv
Connect-ExchangeOnline -AccessToken $exo -Organization contoso.onmicrosoft.com -ShowBanner:$false
```

Order matters in the first process too: once PnP.PowerShell is imported, an interactive `Connect-MgGraph` in the same
session fails with the same macOS error, so sign in to Graph first and import PnP afterwards.

That token path hit a further assembly conflict on the same machine (Microsoft.IdentityModel.Tokens versions). The
dependable arrangement on macOS is two processes: one with Graph, PnP and Teams running `-Collector Entra, Intune,
SharePoint, Teams`, then a fresh process with Exchange Online alone running `-Collector Exchange -SkipCaSnapshot
-OutputFolder <the same folder>`. The manifest keeps the collectors and start time of the first run, so the folder
reads as one collection.

## Scopes

Required: Policy.Read.All, Directory.Read.All, Group.Read.All. Optional, each unlocking the steps named above:
User.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All, RoleManagement.Read.Directory,
OnPremDirectorySynchronization.Read.All, IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All. All delegated, all read-only.

```powershell
Connect-MgGraph -Scopes Policy.Read.All, Directory.Read.All, Group.Read.All, User.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All, RoleManagement.Read.Directory, OnPremDirectorySynchronization.Read.All, IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All, AccessReview.Read.All, EntitlementManagement.Read.All, LifecycleWorkflows.Read.All, PrivilegedEligibilitySchedule.Read.AzureADGroup, AdministrativeUnit.Read.All, ThreatHunting.Read.All, SecurityIncident.Read.All, SecurityEvents.Read.All -NoWelcome, NetworkAccess.Read.All, BackupRestore-Configuration.Read.All
Invoke-PostureCollection -OutRoot ~/tenantkeep/evidence
```

At 20k users the users and registration pulls dominate; expect 20 to 40 minutes, as the audit plan says.
