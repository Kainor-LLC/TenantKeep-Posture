# Scheduling the Conditional Access snapshot (spec 5.4)

There is no Kainor server. The nightly cycle runs where the customer already runs things. All three schedulers
call the same script, `deploy/schedules/ca-snapshot-cycle.ps1`, which takes the snapshot, writes the document,
compares with the previous run, notifies, and prunes old runs. Notifications are opt-in and go only to the
customer's own services: a Teams Workflows webhook, email through Graph from a mailbox in their tenant, or email
through an SMTP relay they already run. `-FailOnRiskRelevantChange` additionally fails the job so the scheduler's
own alerting fires.

## Email

Two methods, both customer-side. The module itself stays read-only; sending lives in `deploy/schedules/ca-notifications.ps1`.

| Method | What it needs | Notes |
|---|---|---|
| `-EmailMethod Graph` (default) | `Mail.Send` application permission on the identity, admin consented, plus a sender mailbox (`-EmailFrom`) | `Mail.Send` lets an app send as any mailbox, so restrict it to the sender mailbox with an Exchange application access policy: `New-ApplicationAccessPolicy -AppId <id> -PolicyScopeGroupId ca-monitor@contoso.example -AccessRight RestrictAccess`. The cycle refuses to send if the scope is missing and says what to grant. `saveToSentItems` is false. |
| `-EmailMethod Smtp` | `-SmtpServer`, `-SmtpPort` (587), `-SmtpCredential` from the scheduler's secret store, STARTTLS on by default | No Graph permission at all. Uses the customer's existing relay. |

The message carries the summary counts and the risk table in the body and `ca-changes.html` as an attachment.
By default it is sent only when a risk-relevant change exists; `-EmailAlways` turns it into a daily digest.

A Kainor-hosted relay is an open decision (checklist). It would be the first thing to leave the customer's
environment besides the license check, so if it ever ships it carries a count and a link, never the report.

| Scheduler | Identity | Snapshots live in | Alert path | Sample |
|---|---|---|---|---|
| Azure Automation runbook | System-assigned managed identity with application permissions | Blob container; the runbook downloads the previous run and uploads the new one | Teams webhook or email, plus an alert rule on job failure | `deploy/automation/` (Bicep, deploy.ps1, grant script) and `deploy/schedules/automation-runbook.ps1` |
| GitHub Action | App registration with a federated credential (OIDC), no secret | A private repo, one commit per run | Teams webhook, plus GitHub's failed-workflow notification | `deploy/schedules/github-action.yml` |
| macOS launchd | The admin's own delegated sign-in, token cache reused | `~/tenantkeep/evidence` | Teams webhook, plus the `.err` log | `deploy/schedules/launchd/` |

## Deploying the Automation variant

```powershell
az login --tenant <tenant id>
./deploy/automation/deploy.ps1 -ResourceGroup rg-tenantkeep-dev -Location centralus -WhatIf     # preview
./deploy/automation/deploy.ps1 -ResourceGroup rg-tenantkeep-dev -Location centralus -EmailTo secops@contoso.example -EmailFrom ca-monitor@contoso.example
# then, once, as a Global Administrator:
Connect-MgGraph -TenantId <tenant id> -Scopes AppRoleAssignment.ReadWrite.All, Application.Read.All
./deploy/automation/Grant-ManagedIdentityGraphRole.ps1 -PrincipalId <printed id> -IncludeMailSend
az automation runbook start -g rg-tenantkeep-dev --automation-account-name aa-tenantkeep-dev -n Invoke-CaSnapshotCycle
```

The deployer needs Owner (or Contributor plus User Access Administrator) on the resource group; the template grants
the deployer blob data access so the module zip can be uploaded, and the account's identity Storage Blob Data
Contributor on the snapshots. Dev deployments upload an unsigned zip of the staged module; releases are signed.

## The monthly posture cycle (Automation, full report)

`deploy.ps1 -IncludePosture` adds a second runbook, `Invoke-PostureCycle`, on a monthly schedule, with two more
containers: `posture-runs` (one folder per run: evidence, report.html, report.md, checks.json, findings.csv) and
`client` (what the customer maintains: profile.json, brand.json, exceptions.json, tenantkeep.lic, and findings.csv,
which the run writes back after merging owners and statuses; hybrid tenants also drop the Windows collector's ad-*
files under `hybrid/`). The job signs in everywhere as the managed identity, runs every collector whose sign-in
succeeded, builds the report against the previous run for the trend, exports the register and uploads the lot. A
collector that could not sign in is named in the job output and in the report's "not collected" list.

```powershell
./deploy/automation/deploy.ps1 -ResourceGroup rg-tenantkeep-dev -IncludePosture -Organization contoso.onmicrosoft.com -SharePointAdminUrl https://contoso-admin.sharepoint.com -ClientFolder ~/tenantkeep/clients/contoso
Connect-MgGraph -TenantId <tenant id> -Scopes AppRoleAssignment.ReadWrite.All, Application.Read.All, RoleManagement.ReadWrite.Directory
./deploy/automation/Grant-ManagedIdentityGraphRole.ps1 -PrincipalId <printed id> -IncludePosture
az role assignment create --assignee-object-id <printed id> --assignee-principal-type ServicePrincipal --role Reader --scope /subscriptions/<id>
az role assignment create --assignee-object-id <printed id> --assignee-principal-type ServicePrincipal --role "Security Reader" --scope /subscriptions/<id>
az automation runbook start -g rg-tenantkeep-dev --automation-account-name aa-tenantkeep-dev -n Invoke-PostureCycle
```

What the identity gets with -IncludePosture: the Graph application roles the collectors use (the same list
Invoke-PostureCollection warns about), Exchange.ManageAsApp for app-only Exchange and Purview, Sites.FullControl.All
on SharePoint Online for PnP's tenant reads (verify: the least application permission that works), the Teams tenant
admin API role, and the Global Reader directory role. All read. The runtime environment also gets
ExchangeOnlineManagement, PnP.PowerShell, MicrosoftTeams and Az.ResourceGraph from the Gallery; package imports finish
in the background, so wait for them to show Available before the first job.

Learned on the first Kainor runs (2026-10-15), all baked into the runbook:

- The sandbox is a custom .NET host with no pwsh executable, so everything runs in one process and the order matters.
  Every Graph call happens before PnP.PowerShell is imported (its old Microsoft.Graph.Core breaks the Graph SDK), and
  Exchange signs in and warms up its REST cmdlets before anything else loads Microsoft.OData.Core.
- Az.Storage and ExchangeOnlineManagement each ship a Microsoft.OData.Core and cannot both load, so the runbook talks to
  blob storage over REST with the identity's token and never imports Az.Storage. Az.ResourceGraph comes with the
  runtime's Az rollup; importing a newer one separately breaks it.
- Purview is not collected in the scheduled run: ExchangeOnlineManagement has no managed identity sign-in for
  Connect-IPPSSession (certificate app auth only), so that domain reads as not collected and the report says so.
- Roles granted to the identity reach a sandbox's cached token after up to a day; a job started right after the grant
  sees the old token, names only the collectors whose roles it has, and the schedule picks up the rest next time.
- Two warnings are licence facts, not faults: lifecycle workflows need Entra ID Governance, restricted SharePoint
  search needs SharePoint Advanced Management.

Still (verify): whether a smaller SharePoint application permission than Sites.FullControl.All lets the tenant reads work.

## Permissions

Application permissions for the managed identity or the app registration: `Policy.Read.All`, `Directory.Read.All`,
`Group.Read.All`, admin consented. Delegated scopes of the same names for the launchd case. Read-only in every case.

## Cycle script parameters

| Parameter | Purpose |
|---|---|
| `-OutRoot` | Durable folder holding `<yyyyMMdd-HHmm>-ca` runs. The previous run is the newest other folder in it. |
| `-Brand` | brand.json for the document and the change report. |
| `-BreakGlass` | UPNs or names of the break-glass accounts; default is the name heuristic. |
| `-NamePattern` | Naming convention regex for the document and the naming check. |
| `-Baseline`, `-Profile`, `-Exceptions` | Inputs for the checks (spec 10): baseline name or path, profile.json, exceptions.json. Passed to the document's coverage page and to checks.json. |
| `-IncludeMembers` | Store group member lists so the diff shows who joined or left an exclusion group. |
| `-TeamsWebhookUrl` | Teams Workflows webhook. Receives an Adaptive Card with the risk-relevant changes. (verify) payload shape against the Workflows connector |
| `-EmailTo`, `-EmailFrom` | Recipients and the sender mailbox. Turns email on. |
| `-EmailMethod`, `-SmtpServer`, `-SmtpPort`, `-SmtpCredential`, `-SmtpUseTls` | Graph (default) or Smtp, and the relay settings for Smtp. |
| `-EmailAlways` | Send the email on every run, not only when something is risk-relevant. |
| `-KeepRuns` | Delete the oldest runs beyond this count. 0 keeps everything. |
| `-FailOnRiskRelevantChange` | Throw at the end when the diff found risk-relevant changes, so the job fails. |

## What a risky night looks like

1. The snapshot and document are written as usual.
2. `ca-changes.md` and `ca-changes.html` land in the new run folder with the risk-relevant changes at the top.
3. Teams gets a card and email goes out with the report attached, whichever are configured.
4. With `-FailOnRiskRelevantChange`, the job fails and the scheduler's own notification goes out too.

## After granting the identity's Graph roles

The sandbox caches the managed identity's token. A job that lands in a sandbox whose token was issued before the
grant fails at the scope check with "Graph session is missing scope(s)" even though the roles are in place, while
a job in a fresh sandbox succeeds. Seen on the dev account on 2026-10-14: job 1 after the grant completed, job 2
failed on the stale token, with the download of the previous run working in both. The cached token expires on
its own (managed identity tokens live up to 24 hours), so leave the nightly schedule alone rather than restarting
jobs by hand. (verify) exact sandbox token cache lifetime.

## Things to verify on first deployment

- Automation: deployed and import verified through `deploy/automation/deploy.ps1` (custom 7.4 runtime environment; system environments stop at 7.2). Still to verify on the first job: `Connect-MgGraph -Identity`, the Az version in the runtime, the blob round trip.
- GitHub: the federated credential token exchange in the sample; `azure/login` plus `Get-AzAccessToken -ResourceTypeName MSGraph` is the alternative.
- launchd: how long the cached refresh token survives under the tenant's own sign-in frequency policy.
