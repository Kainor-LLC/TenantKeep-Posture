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
| Microsoft Exchange Online Protection | none. The principal exposes no delegated scopes at all (live, Kainor, 2026-10-23), so no third-party app can get a Security & Compliance PowerShell token. Purview signs the same admin in through the Exchange module's own app: a second window, for that one service |
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

Desk research done 2026-10-22 (sources: the module docs, pnp/powershell and msgraph-sdk-powershell source, Michev,
Rakhesh and Maester); what is left is the live run, marked (verify):

1. Connect-ExchangeOnline -AccessToken: delegated token for `https://outlook.office365.com/.default` with the
   delegated scope Exchange.Manage on Office 365 Exchange Online, paired with -UserPrincipalName. Documented
   companions; audience from three independent write-ups. (verify live on macOS and Windows)
2. Connect-IPPSSession -AccessToken: audience `https://ps.compliance.protection.outlook.com`, owned by the Microsoft
   Exchange Online Protection principal, -Organization takes the onmicrosoft.com name. No published report of a
   custom app's delegated token here; the setup script lists what delegated scopes that principal exposes. (verify)
   Live, 2026-10-23 (Connor, Kainor): the Exchange Online Protection principal exposes no delegated scope named
   Exchange.Manage; the rerun showed it exposes no delegated scopes at all. Settled: Purview keeps its own sign-in
   through Connect-IPPSSession (the Exchange module's first-party app, -Device when the run has no browser) and the
   one sign-in covers every other service. The purview resource is out of app.json.
3. Connect-PnPOnline -Url -AccessToken: the token's audience must match the host in -Url (pnp/powershell #305), so
   the broker asks for `https://<tenant>-admin.sharepoint.com/.default` and connects to the admin site. (verify)
4. Get-MgContext after Connect-MgGraph -AccessToken: the SDK fills Scopes from the token's scp claim
   (JwtHelpers.cs), so the scope assertion works unchanged; the module still falls back to reading the claim itself.
5. Connect-MicrosoftTeams -AccessTokens: Graph `/.default` plus `48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default`,
   custom apps documented as supported. Microsoft's list of Graph delegated permissions for it includes write
   scopes the read-only app does not ask for. (verify a read-only set is enough for Get-Cs* and Get-Team*)
6. Connect-AzAccount -AccessToken: no audience check in Az; `https://management.core.windows.net//.default` is what
   Az itself uses and what the earlier CLI route proved.
7. Child process token hand-off over standard input on both platforms. (verify)

## 5. Checkpoints

| | Deliverable | Needs |
|---|---|---|
| P0 | The four spikes, results written here | Connor's sign-ins on the Mac and a Windows box |
| P1 | The app registration in the Kainor tenant, manifest committed as Tenantkeep.Posture/app.json (decision 1), publisher verification. Registered 2026-10-23, client id e5b148e7-9689-40b2-9b09-9d0bef133049; verification retried on the next run | Connor: the Partner Center MPN id, a go on creating the app |
| P2 | `Connect-PostureSession` and `Get-PostureToken` with tests against a stubbed token endpoint | nothing |
| P3 | `Start-PostureRun` end to end on Kainor, then the first customer | consent once per tenant |
| P4 | Guide, site and collection docs rewritten around the two lines; consent page on tenantkeep.app | nothing |
| P5 | Retire the per-customer SharePoint app path after one release | nothing |

Rough size: P0 one day, P1 half a day, P2 two days, P3 two days, P4 one day.

## 6. Decisions (Connor, 2026-10-22)

1. Go on the multi-tenant app, named **Tenantkeep Posture**, owned by the Kainor tenant. Registered by
   `deploy/setup/New-PostureClientApp.ps1` from `Tenantkeep.Posture/app.json`, which is also what the broker reads.
2. Publisher verification with the Partner Global Account id (Microsoft refuses the Location id:
   MPNGlobalAccountNotFound). kainor.com is verified. The user running it needs Application Administrator in Entra,
   Account Admin in Partner Center, and MFA in the same session.
3. Default client folder: `~/tenantkeep/clients/<tenant display name, lower case, spaces to dashes>/`, with the
   tenant id in profile.json as the thing that is actually checked. Readable for people, exact for the module.
4. First run with no licence offers a 30-day trial by email, through the licensing function (an `Issue` call with a
   trial plan; built after P3).
