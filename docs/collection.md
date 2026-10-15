# Evidence collection

`Invoke-PostureCollection` writes one run folder, `<OutRoot>/<yyyyMMdd-HHmm>/`, with the audit plan's file names
(Appendix A) so findings and checks reference the same evidence whether it came from the module or from the
original scripts. Read-only. Every step is independent: a permission failure is one line in `errors.txt` and the
run continues.

## What the Entra collector writes

| File | Source | Notes |
|---|---|---|
| `01-organization`, `01-subscribed-skus` (+csv), `01-onprem-sync-features` | organization, subscribedSkus, directory sync | SKUs feed `New-PostureProfile -Evidence`; sync features need OnPremDirectorySynchronization.Read.All |
| `02-*` tenant policies | authorization, security defaults, authentication methods, strengths, admin consent, cross-tenant access | |
| `04-role-definitions`, `04-role-assignments-active` (+csv), `04-role-assignments-pim-eligible` (+csv), `04-role-assignments-summary` | PIM schedule instances; plain role assignments when PIM is unavailable | Needs RoleManagement.Read.Directory for PIM |
| `04-pim-role-policies` (+csv) | roleManagementPolicyAssignments with rules | Activation MFA, justification, max duration, approval per role; feeds ID-006 |
| `05-auth-registration` (+csv), `05-auth-registration-summary` | userRegistrationDetails report | Needs AuditLog.Read.All and UserAuthenticationMethod.Read.All |
| `05-per-user-mfa` (+csv), `05-per-user-mfa-summary` | users/{id}/authentication/requirements, batched 20 per request | Legacy per-user MFA state; feeds AU-009. `-SkipPerUserMfa` on very large tenants |
| `08-entra-devices` (+csv), `08-entra-devices-by-join-os`, `08-entra-devices-stale` | devices | Join type and staleness against StaleDays; feeds the devices domain |
| `06-users` (+csv), `06-users-summary` | users with signInActivity; retried without it when AuditLog.Read.All is missing | `SignInActivityAvailable` in the summary says which |
| `07-groups` (+csv) | groups with Kind and Dynamic | |
| `10-app-registrations`, `10-service-principals`, `10-graph-app-permissions`, `10-oauth2-delegated-grants` (+csv) | applications, servicePrincipals, Graph appRoleAssignedTo, oauth2PermissionGrants | Credential expiry and SAML certificate expiry computed |
| `11-risky-users`, `11-risk-detections-30d` (+csv) | Identity Protection | P2; denied without it and logged |
| `gov-01-access-reviews` (+csv) | identityGovernance/accessReviews/definitions | Scope queries joined, recurrence; needs AccessReview.Read.All |
| `gov-02-access-packages` (+csv), `gov-02-access-packages-summary` | entitlementManagement packages, catalogs, connected organizations | EntitlementManagement.Read.All |
| `gov-03-lifecycle-workflows` (+csv) | lifecycleWorkflows/workflows | LifecycleWorkflows.Read.All |
| `gov-04-pim-groups` (+csv), `gov-04-pim-groups-summary` | privilegedAccess/group/eligibilitySchedules | PrivilegedEligibilitySchedule.Read.AzureADGroup (verify) |
| `gov-05-administrative-units` (+csv) | directory/administrativeUnits | AdministrativeUnit.Read.All |
| `01-domains` (+csv) | domains with authentication type | Federated domains feed the identity model discovery |
| `policies`, `named-locations`, `auth-strengths`, `auth-context`, `resolved-names`, `group-scope`, `metadata` | Export-PostureCaSnapshot into the same folder | The CA checks and documents read these |
| `collection` | run manifest: tenant, account, scopes, API versions, files, errors | `metadata.json` stays the CA snapshot's own |

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

## What the Exchange collector writes

Needs a connected Exchange Online PowerShell session (ExchangeOnlineManagement 3.x, `Connect-ExchangeOnline`), with
View-Only Organization Management or an equivalent read-only role. The module never connects; with no session the
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
| `dns-01-mail-records` (+csv) | public DNS through dig (Resolve-DnsName on Windows) | MX, SPF, DMARC, MTA-STS and TLS-RPT per custom authoritative domain; the initial onmicrosoft.com domain is left out |

```powershell
Connect-ExchangeOnline -UserPrincipalName reader@contoso.example -ShowBanner:$false
Invoke-PostureCollection -OutRoot ~/audit/evidence        # Entra, Intune and Exchange into one folder
```

Not yet collected: legacy sign-ins (section 12), inbox rules forwarding externally (spec 4.10, needs an audit search
at scale), Purview (A.2), SharePoint and Teams (A.3), Maester (A.4), Defender effective state (spec 4.11).

## What the Defender collector writes

Graph only, on the same session as the Entra collector: advanced hunting is a query-style POST that changes nothing.
Scopes: ThreatHunting.Read.All (hunting), SecurityIncident.Read.All (incidents), SecurityEvents.Read.All (Secure
Score). Skipped with a warning when ThreatHunting.Read.All is missing. The device tables are read in 16 shards by
the first character of the device id, under the 10,000-row cap per query. Needs Defender for Endpoint P2 for the
configuration and vulnerability tables (verify: P1 answers DeviceInfo only).

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
Resource Graph at tenant scope carries the fleet-wide reads; Resource Manager GET calls per subscription are capped at
200 subscriptions. Both go through Get-only entry points. Sign in to Graph before importing Az.Accounts in the same
process: imported first, Az breaks `Connect-MgGraph` with "Entry point was not found" (observed 2026-10-15 on macOS). On macOS the Az browser sign-in can hit the same MSAL
conflicts as the others; `Connect-AzAccount -UseDeviceAuthentication` or a token from the Azure CLI
(`Connect-AzAccount -AccessToken (az account get-access-token --resource https://management.azure.com --query accessToken -o tsv) -AccountId <upn>`) work.

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
| `spo-sites` (+csv), `spo-sites-summary` | Get-PnPTenantSite -IncludeOneDriveSites -Detailed | Ownerless, anonymous-capable, labeled and restricted counts; OneDrives apart. `-SkipSiteEnumeration` at 20k OneDrives |
| `teams-federation`, `teams-client-config`, `teams-meeting-policy-global`, `teams-guest-messaging` | the Teams tenant configurations and the Global meeting policy | Single objects |
| `teams-external-access` (+csv), `teams-app-permission-policies` (+csv), `teams-messaging-policies` (+csv) | the policy collections | (verify) app permission policies on tenants moved to app centric management |

The Entra collector adds `02-group-lifecycle-policy` and `07-groups-ownerless` (+summary) for the collaboration checks. The
oversharing views that need SharePoint Advanced Management reports (sites shared with Everyone except external users,
active anonymous links, inactive sites) are not collected yet.

## SharePoint and Teams setup

PnP.PowerShell 3.x signs in through an Entra app registration of your own. `deploy/setup/New-PostureSharePointApp.ps1`
creates it with delegated permissions only (SharePoint AllSites.FullControl, which the tenant admin reads need and
which delegated means bound by the reader's own rights; Graph User.Read, Sites.Read.All, Group.Read.All), asks for admin consent, writes `sharePointClientId` into profile.json and prints the steps that
stay manual: consent if it was declined, the SharePoint Administrator role for the reading account, Conditional
Access on the new app, and the connect commands. It is a tenant write and lives outside the module for that reason;
run it once per tenant as an admin who can register apps. Delete the registration to revoke everything. With `-ClientId` and a Graph session holding Application.ReadWrite.All it
adds the SharePoint permission to an existing registration instead of creating one, and with
DelegatedPermissionGrant.ReadWrite.All grants the admin consent through Graph; the adminconsent web page does not work
for this app (AADSTS500113, its only reply address is localhost).

```powershell
./deploy/setup/New-PostureSharePointApp.ps1 -Tenant contoso.onmicrosoft.com -ProfilePath ./clients/contoso/profile.json
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
Connect-MgGraph -Scopes Policy.Read.All, Directory.Read.All, Group.Read.All, User.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All, RoleManagement.Read.Directory, OnPremDirectorySynchronization.Read.All, IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All, AccessReview.Read.All, EntitlementManagement.Read.All, LifecycleWorkflows.Read.All, PrivilegedEligibilitySchedule.Read.AzureADGroup, AdministrativeUnit.Read.All, ThreatHunting.Read.All, SecurityIncident.Read.All, SecurityEvents.Read.All -NoWelcome
Invoke-PostureCollection -OutRoot ~/audit/evidence
```

At 20k users the users and registration pulls dominate; expect 20 to 40 minutes, as the audit plan says.
