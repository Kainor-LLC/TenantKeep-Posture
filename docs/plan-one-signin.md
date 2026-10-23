# Plan: one sign-in, one command

Decided to plan 2026-10-22 after Connor's review: the report works, getting to it does not. Six sign-ins across five
auth mechanisms, a per-customer app registration and a wizard stand between an admin and the HTML. This plan takes
that down to two lines, without touching what the product promises: read-only, nothing leaves, source published.

```powershell
Install-Module Tenantkeep.Posture
Start-PostureRun
```

One browser sign-in. The module gets a token for each service from that sign-in, runs every collector, handles its
own process juggling, discovers the profile, evaluates, renders the report and opens it. The admin types nothing else.

## 1. What changes, what does not

| Stays exactly as it is | Changes |
|---|---|
| Collectors, engine, catalog, report, licence, integrity | How sessions are made: one sign-in brokers every token |
| Automation deployment (managed identity, certificate for Purview) | Becomes the advanced option; a Marketplace wizard later, not in this plan |
| `Invoke-PostureCollection`, `New-PostureProfile`, `New-PostureReport` | Still there for people who want the steps; `Start-PostureRun` calls them |
| The licence model | Nothing |
| Nothing leaves the tenant | Nothing |

## 2. The pieces

### 2.1 One multi-tenant app, owned by Kainor, delegated permissions only

A public client (no credentials, ever) named **Tenantkeep Posture**, registered once in the Kainor tenant, multi-tenant,
publisher-verified through Partner Center. Customers consent once through an admin consent link; after that any admin
in that tenant signs in to it like any other Microsoft app. The app has no permissions of its own: every token it
gets is the signed-in admin's, limited to what that admin can already read.

Delegated permissions it requests (all read):

| Resource | Permissions |
|---|---|
| Microsoft Graph | the collectors' scopes as today: Policy.Read.All, Directory.Read.All, Group.Read.All, User.Read.All, OnPremDirectorySynchronization.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All, RoleManagement.Read.Directory, IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All, DeviceManagementManagedDevices.Read.All, DeviceManagementConfiguration.Read.All, DeviceManagementServiceConfig.Read.All, DeviceManagementApps.Read.All, BitLockerKey.ReadBasic.All, AttackSimulation.Read.All, AccessReview.Read.All, EntitlementManagement.Read.All, LifecycleWorkflows.Read.All, PrivilegedEligibilitySchedule.Read.AzureADGroup, AdministrativeUnit.Read.All, ThreatHunting.Read.All, SecurityIncident.Read.All, SecurityEvents.Read.All, Sites.Read.All, Organization.Read.All, Application.Read.All, Reports.Read.All |
| Office 365 Exchange Online | Exchange.Manage (the delegated scope Exchange Online PowerShell uses) |
| Microsoft Exchange Online Protection | Exchange.Manage, for Security & Compliance PowerShell (verify the delegated scope name) |
| Office 365 SharePoint Online | AllSites.FullControl, which PnP's tenant reads require even for reading (proven on the per-customer app) |
| Skype and Teams Tenant Admin API | user_impersonation (proven through the Azure CLI route) |
| Azure Service Management | user_impersonation, used only when the profile says Azure is in scope |

Redirect URIs: `http://localhost` (the loopback the module listens on) and `https://tenantkeep.app/consent` (where
the admin consent link lands). Nothing else.

### 2.2 The token broker, in the module, in plain PowerShell

`Private/Connect-PostureSession.ps1`: the OAuth 2.0 authorization code flow with PKCE against
`login.microsoftonline.com`, no MSAL, no new dependency, every request readable in the source:

1. Open the browser to the authorize endpoint for the app with `offline_access` and the Graph scopes; listen on a
   loopback port for the redirect; exchange the code for tokens.
2. Keep the refresh token in memory for the session only (an opt-in encrypted cache on disk is a later feature; the
   default is nothing written anywhere).
3. `Get-PostureToken -Resource <graph|exchange|purview|sharepoint|teams|azure>` returns an access token for that
   resource through the refresh token grant, cached until five minutes before expiry. Microsoft issues a token per
   resource from the one refresh token; this is exactly what MSAL does underneath every Microsoft module.
4. A device-code variant for a box without a browser (`-DeviceCode`), same broker.

Every SDK we use accepts a caller-supplied token: `Connect-MgGraph -AccessToken`, `Connect-ExchangeOnline -AccessToken`
(3.1+), `Connect-IPPSSession -AccessToken` (3.8+), `Connect-PnPOnline -Url -AccessToken`,
`Connect-MicrosoftTeams -AccessTokens`, `Connect-AzAccount -AccessToken`. Whether Exchange and Purview take a
delegated token with `-UserPrincipalName` the way their docs imply is the first spike (verify); PnP's note that it
cannot refresh its own token is handled by the broker refreshing before each collector starts.

The module's existing read-only guard is unchanged: these connect calls live where the session hints live today, in
the one public cmdlet that orchestrates, never inside a collector.

### 2.3 `Start-PostureRun`

```
Start-PostureRun [-TenantId <guid>] [-Client <folder>] [-Collector <names>] [-DeviceCode] [-NoBrowser] [-SkipReport]
```

1. Sign in once (2.2). Resolve the tenant from the token; refuse if `-TenantId` was given and differs.
2. Client folder: `-Client`, else `~/tenantkeep/clients/<tenant name>/`, created on first run. The licence file, if
   present, is read from there as today.
3. Collect. Graph-based collectors, Defender and Azure in this process. Exchange and Purview in one child `pwsh`,
   SharePoint and Teams in another, each handed its tokens over standard input (never an argument, never an
   environment variable, never a file), all writing into the same run folder through `-OutputFolder` as the
   Automation runbook already does. The admin sees one progress line per collector.
4. Profile: discovery runs from the evidence (today's `New-PostureProfile -Evidence` without the questions);
   anything the wizard would ask is left to the report's Settings view. An existing profile.json is kept and only
   the discovered keys are refreshed.
5. Evaluate and render as today, with `-Previous` set to the newest earlier run under the evidence root, so the trend
   appears from the second run with nothing typed.
6. Open the report in the default browser.
7. Hybrid tenants: if `imports/hybrid/ad-*` or the newest `ad-baseline-*` folder is beside the evidence, it is copied
   in; else the hybrid checks say to run the Windows collector, as today.

Exit cleanly on any collector failure: the run folder keeps what was collected and the report says what was not.

### 2.4 Consent and first run

- The admin consent link is on tenantkeep.app (`/consent/`), and `Start-PostureRun` prints and offers to open it when
  the sign-in fails with "consent required" (AADSTS65001). Consent is per tenant, once.
- The first run with no licence file produces the Conditional Access domain and says what the full tier adds, as today.
- Conditional Access in the customer tenant that blocks unapproved apps: the error is reported with the app id so the
  admin can allow it; nothing we can or should work around.

### 2.5 What this retires or demotes

- `deploy/setup/New-PostureSharePointApp.ps1`: no longer needed for new customers. Kept for one release as the way
  to run with a customer-owned app (`-SharePointClientId` in the profile still honoured), then removed.
- The six-sign-in recipe in docs/collection.md becomes a troubleshooting appendix; the guide starts with two lines.
- The macOS process workarounds become internal to `Start-PostureRun`.
- Purview app-only, the certificate vault and the role group stay for the scheduled run only; the local path reads
  Purview as the admin, which already covers everything including the three reads app-only cannot.

## 3. Security, said plainly

- Kainor owns the app object. The risk that adds: someone with control of Kainor's tenant could change the app's
  redirect URIs or scopes. They could not read any customer data: the app has no credentials and every token is a
  signed-in admin's, bounded by that admin's roles and visible to that tenant's audit log. Mitigations: publisher
  verification (customers see "verified publisher"), the app's settings reviewed in the open (its manifest is
  published in this repo), Kainor's own tenant held to the same posture report.
- The refresh token never touches disk by default. Tokens cross to child processes over standard input and are not in
  the process list or the environment.
- Scopes are delegated and read-only; the consent screen shows every one. A tenant that wants fewer can consent
  partially; the collectors that lose a scope report it, as they do today.

## 4. Spikes before the build (one day)

1. Connect-ExchangeOnline and Connect-IPPSSession with a delegated token from the broker, on macOS and Windows
   (verify: the companion parameter and the audience each wants).
2. Connect-PnPOnline -AccessToken against an admin site with a multi-tenant app's token (verify audience:
   `https://<tenant>-admin.sharepoint.com`).
3. `Get-MgContext` after `Connect-MgGraph -AccessToken`: does it carry the scopes our scope assertion reads, or do we
   decode the token's `scp` claim ourselves (verify; the fallback is small).
4. Child process token hand-off over standard input on both platforms.

## 5. Checkpoints

| | Deliverable | Needs |
|---|---|---|
| P0 | The four spikes, results written here | Connor's sign-ins on the Mac and a Windows box |
| P1 | The app registration in the Kainor tenant, manifest committed under deploy/app/, publisher verification | Connor: the Partner Center MPN id, a go on creating the app |
| P2 | `Connect-PostureSession` and `Get-PostureToken` with tests against a stubbed token endpoint | nothing |
| P3 | `Start-PostureRun` end to end on Kainor, then the first customer | consent once per tenant |
| P4 | Guide, site and collection docs rewritten around the two lines; consent page on tenantkeep.app | nothing |
| P5 | Retire the per-customer SharePoint app path after one release | nothing |

Rough size: P0 one day, P1 half a day, P2 two days, P3 two days, P4 one day.

## 6. Decisions for Connor

1. Go on the multi-tenant app, named **Tenantkeep Posture**, owned by the Kainor tenant.
2. Publisher verification: needs the Partner Center MPN id and a verified kainor.com domain on the account.
3. Default client folder naming by tenant display name (`~/tenantkeep/clients/<name>/`) or by tenant id.
4. Whether the first run should also offer to issue a 30-day trial licence by email (ties into the licensing
   function; not required for this plan).
