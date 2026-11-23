# What gets installed, and where

The complete inventory of what TenantKeep Posture puts in a customer's environment, per way of running it, and how to
remove every piece. Nothing on this page phones home, and nothing leaves a tenant.

## Running it locally (no Azure needed)

An admin runs the module on their own machine with their own sign-in. Nothing is installed in the tenant except the
consent record for the one app the sign-in goes through.

| Where | What | Why | Remove |
|---|---|---|---|
| The admin's machine | The `TenantKeep.Posture` PowerShell module, an evidence folder per run, a client folder per tenant (profile.json, brand.json, exceptions.json, tenantkeep.lic, imports/) | Everything the report needs stays here | Delete the folders |
| Entra ID, enterprise applications | **TenantKeep**: the consent record (service principal) for Kainor's multi-tenant public client, which this report and the TenantKeep On-Call app both sign in to for what they read. It holds what an administrator approved and nothing else. The link Posture gives names Posture's permissions only, the ones under `resources` in the module's app.json: the Graph read scopes the collectors use (SharePoint tenant settings through Graph's read-only SharePointTenantSettings.Read.All). Every permission on this app is read-only by its name, on every API. No SharePoint, Azure, Teams or Power Platform permission: those are on the apps below. A customer who also uses On-Call approves its reads from On-Call's own link, by name (`sharedWith` in app.json lists them; two reveal a LAPS password or a BitLocker key to an administrator who already holds the role for it). In such a tenant a token for either product carries what was approved for both, because Microsoft issues one set of permissions per app. Nothing on this app can write, and a test in the repository fails if a scope that is not read-only by name is added, on any API. No credentials exist for it anywhere | The sign-in for everything read through Microsoft Graph; the app acts as the admin, never on its own | Delete the enterprise application; the next run says consent is needed. That also signs On-Call out of this tenant |
| Entra ID, the same enterprise application, optional | One more permission on **TenantKeep**, approved from a link of its own and only by a customer who wants the Power BI checks: Tenant.Read.All on the Power BI Service, read-only by name | The Power BI checks | Revoke the permission on the enterprise application, or never open the link |
| Entra ID, enterprise applications, only where Azure, Teams or Power Platform is read | **TenantKeep Posture for Azure, Teams and Power Platform**: Kainor's second public client (`app-services.json` in the module), which Posture alone signs in to. Three APIs offer no read-only permission, only one to act as the signed-in administrator, and this app holds those: user_impersonation on Azure Service Management and on the Teams tenant admin API, and, from a link of its own for a customer who wants the Power Platform checks, User on the PowerApps Service. Beside them, the Graph scopes for signing in and no Graph read. They are kept off **TenantKeep** so that app holds read-only permissions only: a refresh token for an app can be redeemed for any API the organisation granted that app, so one broader permission there would reach every tenant that approved it. The module reads each of the three through one entry point that refuses anything but a read (docs/security-review.md). No credentials exist for it anywhere | The Azure and Teams collectors and the Power Platform checks | Delete the enterprise application; the next run skips those three and gives the link. An organisation that approved **TenantKeep** before 2026-11-23, when it still named Azure and Teams, removes those older grants with `deploy/setup/Remove-PostureStaleGrant.ps1` |
| Entra ID, enterprise applications, optional | **TenantKeep Posture for SharePoint**: Kainor's second public client, the only one that asks for SharePoint full control (AllSites.FullControl, delegated, plus the Graph sign-in scopes). Never consented for the organisation: `deploy/setup/Grant-PostureSharePointAccess.ps1` adds it, requires assignment and grants it to named admins one at a time, and can turn sign-in to it off between runs. No credentials exist for it anywhere | The SharePoint admin read (default links, Anyone link expiry, guest expiry, sites, restricted search), which Graph does not return | The same script with `-Remove`, or delete the enterprise application |
| Entra ID, app registrations, optional | **TenantKeep Posture (SharePoint)**: a customer-owned public client for the manual path without the Kainor app (Graph User.Read, Sites.Read.All, Group.Read.All; SharePoint AllSites.FullControl) | PnP.PowerShell needs an app id to sign the admin in | Delete the app registration |
| Entra ID, roles on the admin | Global Reader covers Entra, Intune and Defender reads; SharePoint Administrator for the SharePoint collector; Global Reader also covers Exchange and most Purview reads, with Purview role groups for Insider Risk, Communication Compliance, audit retention and eDiscovery; Reader and Security Reader on Azure subscriptions only if the Azure domain is wanted; Fabric Administrator (on an account with a Power BI or Fabric licence, the free one counts) and Power Platform Administrator only if the Power Platform and Power BI domain is wanted, since neither product has a read-only role for these settings | The module reads as the signed-in admin | Standard role removal |
| A domain-joined Windows machine, hybrid tenants only | Nothing installed: `Get-ADBaseline.ps1` runs once as a domain user with RSAT and writes a folder | The AD facts for the hybrid domain | Delete the folder |

Azure is optional here. With `azure: none` in the profile, the Azure collector is skipped and the Azure domain reads
as not applicable; no Azure role is needed.

What is on the admin's machine is the tenant's whole directory in files: every user, device, group, mailbox and site,
the report, and for a hybrid tenant the domain's accounts. The run and client folders the module creates are the
owner's alone on macOS and Linux (mode 700, so no other account on the machine can list or read them). On Windows the
module changes no permissions: a folder under your profile (the default, `~/tenantkeep`) is already limited to you,
SYSTEM and Administrators by the profile's own permissions, and a folder you choose elsewhere keeps what its parent
grants, so choose one that is yours. While a list is being read there are also `.part` files and, in `logs/`, a
cursor for a list that stopped part way; both hold rows of that list and go when it finishes. The sign-in read's
checkpoint holds no account names, only keyed hashes. Nothing is encrypted at rest by the module: use the disk's own
encryption (FileVault, BitLocker), and delete a run folder when its report has been delivered.

## Running it on a schedule (the customer's own Azure subscription)

The deployment puts one small resource group in the customer's subscription. It is the only Azure footprint, and it
exists because the schedule needs somewhere to run as a managed identity instead of as a person.

| Where | What | Why | Remove |
|---|---|---|---|
| Azure, resource group `rg-tenantkeep` | Automation account `aa-tenantkeep-<env>` with a system-assigned managed identity, a PowerShell 7.6 runtime environment holding the module and its dependencies, two runbooks (`Invoke-CaSnapshotCycle` nightly, `Invoke-PostureCycle` monthly), schedules, variables (container URLs, organisation, SharePoint admin URL, Purview app id and certificate URL, optional Teams webhook and email settings) | Runs the cycles | Delete the resource group |
| Azure, same resource group | Storage account with containers `ca-snapshots`, `posture-runs`, `client`, `modules`; shared-key access disabled, RBAC only | Evidence, reports, the findings lists, the client files, the module zips | Same |
| Azure, same resource group | Key Vault `kv-<name>` (RBAC, soft delete) holding one certificate, `tenantkeep-purview`, generated inside the vault | Purview has no managed identity sign-in; the identity reads this certificate at run time | Same; the app registration stops working the moment the vault is gone |
| Azure RBAC | On the storage account: Storage Blob Data Contributor to the identity (and to the deployer, for uploads). On the vault: Key Vault Secrets User to the identity, Certificates Officer to the deployer. On each subscription the Azure domain should cover: Reader and Security Reader to the identity | Read access and nothing more | Role assignment removal, or deleting the resource group for the first two |
| Entra ID, the managed identity | Graph application roles, all read: Policy, Directory, Group, User, AuditLog, authentication methods, role management, risk, device management, BitLocker key basics, attack simulation, access reviews, entitlement management, lifecycle workflows, PIM for Groups, administrative units, threat hunting, security incidents and events, SharePoint tenant settings, Intune roles, Defender for Identity health, service health and Message Center, federation settings, Organization, Application. Exchange.ManageAsApp on Office 365 Exchange Online. application_access on the Teams tenant admin API. The Global Reader directory role. Only when the admin asks for it with `-IncludeSharePointAdminRead`, for the site list in the scheduled run: Sites.FullControl.All on SharePoint Online, a standing permission over every site's content that the module only reads with | Each collector's reads as the identity | Deleting the Automation account deletes the identity and every assignment with it |
| Entra ID, app registrations | **TenantKeep Posture (Purview)**: single-tenant, trusts the vault certificate, Exchange.ManageAsApp on Office 365 Exchange Online and on Microsoft Exchange Online Protection, Global Reader, and a Purview role group **TenantKeep Posture (view only)** with View-Only Audit Logs, Insider Risk Management Audit and the view-only retention, DLP and information barrier roles | App-only Purview reads | Delete the app registration and the role group |
| Entra ID, enterprise applications | **TenantKeep** and **TenantKeep Posture for Azure, Teams and Power Platform**, as in the local table, if the same customer also runs it locally. The scheduled run signs in to neither: it reads as the managed identity | The sign-ins for local runs | Delete them |
| Optional, Power BI in the scheduled run | A security group, **TenantKeep Posture (Power BI read)**, with the identity as its one member, named by a Fabric administrator in the Fabric tenant setting "Service principals can access read-only admin APIs". No role and no API permission on the identity. Power Platform is never read on a schedule | The Power BI checks in the scheduled report | Remove the group from the tenant setting and delete the group |
| Optional, email alerts | Mail.Send on the identity, restricted by an Exchange application access policy to one sender mailbox the customer names | Change alerts and the monthly report by email | Remove the role and the policy |
| Retired, relayed alerts | The Automation variables `RELAY_SENDER_KEY` and `RELAY_PAIRING_CODES`, if set up before 2026-11-15 | Nothing reads them now; phone alerts are TenantKeep On-Call's Instant alerts | Delete the two variables |
| Optional, hybrid tenants | The AD collector's files uploaded to `client/hybrid/` in the storage account; a Hybrid Runbook Worker on the AD box is the planned automation | The hybrid domain in the scheduled report | Delete the files |

Not in the customer's environment, ever: the licence signing key (Kainor's Key Vault), the Stripe webhook function
(Kainor's tenant), the websites. The customer's deployment never contacts any of them.

## Removing everything

1. Delete the resource group: the Automation account, its identity and every role assignment to it, the storage
   account with every run, the vault and the certificate.
2. Delete the Purview app registration and role group, and the TenantKeep enterprise application (keep it if the
   organisation uses TenantKeep On-Call, which signs in to the same one).
3. Delete the client and evidence folders on the admin's machine.

No residue remains: no agents, no scheduled tasks, no browser extensions, no DNS records, no mailboxes.
