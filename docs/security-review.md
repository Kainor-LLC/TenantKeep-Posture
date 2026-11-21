# TenantKeep Posture: security review

For the security team deciding whether an administrator may run TenantKeep Posture against your Microsoft 365
tenant. It says what the tool reads, as whom, where the results go, how read-only is enforced, and how you can check a
run afterwards in your own logs. Everything here can be confirmed in the source, which is public.

## The short answers

| Question | Answer |
|---|---|
| Does it change anything in the tenant? | No. Every request is a read. The module has no code path that writes, and its tests fail the build if one appears. |
| Does any data leave your environment? | No. The report and the evidence are files on the machine that runs it. There is no telemetry, no analytics and no licence server: the licence is a signed file checked offline. |
| Does it store credentials? | No. It signs in as the administrator running it, with delegated permissions, and keeps the tokens in memory for the run. The apps it signs in to have no secrets or certificates. |
| Can it act on its own? | No. Every token belongs to the signed-in administrator and is bounded by that person's own roles. The optional Azure Automation deployment runs as a managed identity in your subscription. |
| Can we read the code? | Yes. The repository is public under PolyForm Shield 1.0.0: read it, run it, change it. |
| Is the release what Kainor published? | Every release carries an integrity manifest signed with Kainor's key, listing every file with its hash; the module checks it when it loads, and the report header says whether the running copy is a release, a development copy or a modified one. Authenticode signing through Azure Artifact Signing starts once Microsoft finishes validating Kainor's signing account; until then the release zip says unsigned in its name. |

## How a run works

An administrator runs `Start-PostureRun` on a machine you choose. The module signs that person in, reads
configuration from Microsoft's APIs, writes the evidence and a report into a folder on that machine, and stops. Nothing
is installed in the tenant beyond the consent records for the apps below, and nothing is scheduled unless you deploy
the Azure Automation option yourself.

| Sign-in | What it reads | Permissions |
|---|---|---|
| **TenantKeep Posture** (Kainor's multi-tenant public client) | Entra, Intune, Defender, Teams, Azure, and SharePoint tenant settings through Graph | Delegated read scopes only, listed in `TenantKeep.Posture/app.json`, which is also what the consent screen shows. No SharePoint permission. |
| **TenantKeep Posture for SharePoint** (optional, Kainor's second public client) | The SharePoint settings Graph does not return: default links, Anyone link expiry, guest expiry, the site list | Delegated SharePoint `AllSites.FullControl` plus the sign-in scopes, listed in `TenantKeep.Posture/app-sharepoint.json`. See below. |
| **Exchange Online PowerShell** (Microsoft's own app, through the ExchangeOnlineManagement module) | Exchange Online and Purview configuration | The administrator's own Exchange and Purview roles. The module runs `Get-` commands only. |
| **Azure** (through Az.Accounts) | Subscriptions, Defender for Cloud, policy, role assignments, Microsoft 365 pay-as-you-go spend | The administrator's own Azure roles (Reader, Security Reader, Cost Management Reader). |

Delegated means the app can never do more than the administrator signed in to it could do anyway, and only while that
person is signed in.

## SharePoint, and why it is separate

Microsoft offers no read-only permission for most SharePoint tenant settings: the SharePoint admin read needs
SharePoint Administrator and, for a third-party app, `AllSites.FullControl`. TenantKeep Posture does not ask for it by
default. Out of the box the SharePoint checks read Graph's read-only SharePoint settings, and the report names each
check that needs more. For full coverage you choose one of:

1. **The TenantKeep Posture for SharePoint app, granted to named administrators only.**
   `deploy/setup/Grant-PostureSharePointAccess.ps1` adds it to your tenant, requires assignment (so an account that is
   not assigned cannot sign in to it at all) and grants it one administrator at a time. It never consents for the
   organisation, and `-RemoveOrganizationWideGrant` removes such a grant if someone made one in the portal. `-Disable`
   turns sign-in to the app off between runs and `-Enable` turns it back on.
2. **The Windows collector on Microsoft's own shell.** `collectors/windows/Get-SpoBaseline.ps1` runs on a Windows
   machine (a cloud PC works) as a SharePoint administrator, through Microsoft's SharePoint Online Management Shell.
   No third-party app is involved. It runs `Get-SPO` commands only, and a test fails the build on any other. Its output
   is brought into the run with `Import-PostureEvidence`, which checks the tenant and every file's SHA-256.

Either way, the person running the SharePoint read holds SharePoint Administrator while they do. No tool can remove
that: reading those settings needs the role. What you can control is how long they hold it (activate it in PIM for the
run) and what the record shows afterwards (below).

## How read-only is enforced

- **One entry point per service, reads only.** Graph requests, Exchange and Purview commands (`Get-` only), PnP
  commands (`Get-PnP` only), Teams commands (`Get-Cs`, `Get-Team` and the two app availability reads,
  `Get-AllM365TeamsApps` and `Get-M365UnifiedTenantSettings`) and Azure requests each go through one function that
  refuses anything else.
- **Tests that fail the build.** The module's test suite fails if any code sends a request other than GET, except four
  POSTs that are reads with the question in the body, each marked in the code: Graph batches of reads, advanced
  hunting queries, directory lookups by id, and the Cost Management cost query. The same tests fail on a SharePoint,
  Teams or Exchange command that is not a read, and on any connection made outside the sign-in code.
- **Releases are checked when they load.** The integrity manifest lists every file with its hash, signed with Kainor's
  key; the module checks it when it loads and the report says what it found. Authenticode signatures on every file
  follow once the signing account is validated (until then the zip is named unsigned).
- **The only tenant writes in the repository** are the customer-side setup scripts under `deploy/setup/` (adding the
  apps, granting roles). Your administrator runs them knowingly; the module never does.

## Checking a run afterwards

- **What the run did.** Every request a run sends is counted by service, method and target in `logs/calls.json` in
  the run folder, with ids and accounts replaced by placeholders. The report's Run Health view shows it, with a
  verdict: every request was a read, or a list of any that were not (there should never be any).
- **Your own audit logs.** `deploy/verify/Test-PostureReadOnly.ps1` is a short script that does not load the module.
  Signed in with your own audit log access, it reads the unified audit log, Entra's directory audit log and Entra's
  sign-in log for the account that ran the report, over the window the run took, and lists any change that account
  made. Exchange records only commands that change something, and Entra's directory audit log holds only changes, so
  the expected answer is none. Run it the day after the run, because audit records can take hours to arrive.
- **Sign-in logs.** The account's sign-ins during the run show exactly which apps it used, by app id.

The audit log names the account, not the tool. Run the report with an account that does nothing else in that window,
or anything else it did shows up too.

## Recommended setup for the account that runs it

- A **dedicated account** for posture runs, with phishing-resistant MFA, used for nothing else.
- **Global Reader**, which covers Entra, Intune, Defender, Exchange and most Purview reads. Eligible in PIM, or
  permanent if your policy allows a read-only role standing. `Get-PostureRequirement` lists each step's least role.
- **SharePoint Administrator eligible in PIM**, activated only for the SharePoint read, or held only by the person who
  runs the Windows collector.
- **Purview role groups** for Insider Risk, Communication Compliance, audit retention and eDiscovery only if you want
  those checks; Azure Reader, Security Reader and Cost Management Reader only if you want the Azure domain.
- **A Conditional Access policy for the account**: phishing-resistant MFA and a compliant device, so the run happens on
  a managed machine or cloud PC and the evidence stays inside your environment.
- **The SharePoint app turned off between runs** (`Grant-PostureSharePointAccess.ps1 -Disable`) if you use it.
- **Device code sign-in blocked** in Conditional Access is compatible: the module signs in through the browser by
  default. Only its `-DeviceCode` option needs device code flow.

## What the evidence holds

Configuration and object metadata: policy settings, user principal names and display names, group and device names,
site addresses, role assignments, licence counts, and sign-in tallies (counts by day, country and result). Not mail or
file content, not passwords or secrets. For BitLocker the collector reads which devices have a recovery key escrowed,
never the keys themselves (`BitLockerKey.ReadBasic.All`). The banned password list is kept as a count only.

The evidence and the report are files in the folder the administrator chose. You decide how long they are kept; delete
the folder to remove them. `New-PostureReport -Redact` writes a copy of the report with names removed, for sharing
outside the team.

## Dependencies

| Module | Publisher | Used for |
|---|---|---|
| Microsoft.Graph.Authentication | Microsoft | Graph requests |
| ExchangeOnlineManagement | Microsoft | Exchange Online and Purview reads |
| MicrosoftTeams | Microsoft | Teams settings |
| Az.Accounts, Az.ResourceGraph | Microsoft | Azure reads |
| PnP.PowerShell | PnP community (open source) | SharePoint admin read through the optional SharePoint app |
| Microsoft.Online.SharePoint.PowerShell | Microsoft | SharePoint admin read in the Windows collector |

Each run records the versions it used in `collection.json`. `Get-PostureRequirement` lists the versions tested.

## Reporting a security problem

See `SECURITY.md`: security@kainor.com, acknowledged within three business days.
