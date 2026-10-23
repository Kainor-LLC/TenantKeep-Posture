# What gets installed, and where

The complete inventory of what Tenantkeep Posture puts in a customer's environment, per way of running it, and how to
remove every piece. Nothing on this page phones home; the only thing that ever leaves a tenant is nothing.

## Running it locally (no Azure needed)

An admin runs the module on their own machine with their own sign-in. Nothing is installed in the tenant except the
consent record for the one app the sign-in goes through.

| Where | What | Why | Remove |
|---|---|---|---|
| The admin's machine | The `Tenantkeep.Posture` PowerShell module, an evidence folder per run, a client folder per tenant (profile.json, brand.json, exceptions.json, findings.csv, tenantkeep.lic, imports/) | Everything the report needs stays here | Delete the folders |
| Entra ID, enterprise applications | **Tenantkeep Posture**: the consent record (service principal) for Kainor's multi-tenant public client. Delegated, read-only permissions only, listed in the module's app.json and on the consent screen: the Graph read scopes the collectors use, Exchange.Manage on Exchange Online and on Exchange Online Protection (Purview), AllSites.FullControl on SharePoint Online (what PnP's tenant reads require; it still acts as the admin), user_impersonation on the Teams tenant admin API and on Azure Service Management. No credentials exist for it anywhere | One sign-in for every service; the app acts as the admin, never on its own | Delete the enterprise application; the next run says consent is needed |
| Entra ID, app registrations, optional | **Tenantkeep Posture (SharePoint)**: a customer-owned public client for the manual path without the Kainor app (Graph User.Read, Sites.Read.All, Group.Read.All; SharePoint AllSites.FullControl) | PnP.PowerShell needs an app id to sign the admin in | Delete the app registration |
| Entra ID, roles on the admin | Global Reader covers Entra, Intune and Defender reads; SharePoint Administrator for the SharePoint collector; View-Only Organization Management for Exchange; a Purview read role group for Purview; Reader and Security Reader on Azure subscriptions only if the Azure domain is wanted | The module reads as the signed-in admin | Standard role removal |
| A domain-joined Windows machine, hybrid tenants only | Nothing installed: `Get-ADBaseline.ps1` runs once as a domain user with RSAT and writes a folder | The AD facts for the hybrid domain | Delete the folder |

Azure is optional here. With `azure: none` in the profile, the Azure collector is skipped and the Azure domain reads
as not applicable; no Azure role is needed.

## Running it on a schedule (the customer's own Azure subscription)

The deployment puts one small resource group in the customer's subscription. It is the only Azure footprint, and it
exists because the schedule needs somewhere to run as a managed identity instead of as a person.

| Where | What | Why | Remove |
|---|---|---|---|
| Azure, resource group `rg-tenantkeep` | Automation account `aa-tenantkeep-<env>` with a system-assigned managed identity, a PowerShell 7.4 runtime environment holding the module and its dependencies, two runbooks (`Invoke-CaSnapshotCycle` nightly, `Invoke-PostureCycle` monthly), schedules, variables (container URLs, organisation, SharePoint admin URL, Purview app id and certificate URL, optional Teams webhook and email settings) | Runs the cycles | Delete the resource group |
| Azure, same resource group | Storage account with containers `ca-snapshots`, `posture-runs`, `client`, `modules`; shared-key access disabled, RBAC only | Evidence, reports, the register, the client files, the module zips | Same |
| Azure, same resource group | Key Vault `kv-<name>` (RBAC, soft delete) holding one certificate, `tenantkeep-purview`, generated inside the vault | Purview has no managed identity sign-in; the identity reads this certificate at run time | Same; the app registration stops working the moment the vault is gone |
| Azure RBAC | On the storage account: Storage Blob Data Contributor to the identity (and to the deployer, for uploads). On the vault: Key Vault Secrets User to the identity, Certificates Officer to the deployer. On each subscription the Azure domain should cover: Reader and Security Reader to the identity | Read access and nothing more | Role assignment removal, or deleting the resource group for the first two |
| Entra ID, the managed identity | Graph application roles, all read: Policy, Directory, Group, User, AuditLog, authentication methods, role management, risk, device management, BitLocker key basics, attack simulation, access reviews, entitlement management, lifecycle workflows, PIM for Groups, administrative units, threat hunting, security incidents and events, Sites, Organization, Application, Reports. Exchange.ManageAsApp on Office 365 Exchange Online. Sites.FullControl.All on SharePoint Online. application_access on the Teams tenant admin API. The Global Reader directory role | Each collector's reads as the identity | Deleting the Automation account deletes the identity and every assignment with it |
| Entra ID, app registrations | **Tenantkeep Posture (Purview)**: single-tenant, trusts the vault certificate, Exchange.ManageAsApp on Office 365 Exchange Online and on Microsoft Exchange Online Protection, Global Reader, and a Purview role group **Tenantkeep Posture (view only)** with View-Only Audit Logs, Insider Risk Management Audit and the view-only retention, DLP and information barrier roles | App-only Purview reads | Delete the app registration and the role group |
| Entra ID, enterprise applications | **Tenantkeep Posture**, as in the local table, if the same customer also runs it locally | The one sign-in for local runs | Delete it |
| Optional, email alerts | Mail.Send on the identity, restricted by an Exchange application access policy to one sender mailbox the customer names | Change alerts and the monthly report by email | Remove the role and the policy |
| Optional, hybrid tenants | The AD collector's files uploaded to `client/hybrid/` in the storage account; a Hybrid Runbook Worker on the AD box is the planned automation | The hybrid domain in the scheduled report | Delete the files |

Not in the customer's environment, ever: the licence signing key (Kainor's Key Vault), the Stripe webhook function
(Kainor's tenant), the websites. The customer's deployment never contacts any of them.

## Removing everything

1. Delete the resource group: the Automation account, its identity and every role assignment to it, the storage
   account with every run, the vault and the certificate.
2. Delete the Purview app registration and role group, and the Tenantkeep Posture enterprise application.
3. Delete the client and evidence folders on the admin's machine.

No residue remains: no agents, no scheduled tasks, no browser extensions, no DNS records, no mailboxes.
