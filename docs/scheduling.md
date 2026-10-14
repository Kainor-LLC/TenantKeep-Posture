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
| Azure Automation runbook | System-assigned managed identity with application permissions | Storage account file share or blob mounted to the sandbox | Teams webhook, plus an alert rule on job failure | `deploy/schedules/automation-runbook.ps1` |
| GitHub Action | App registration with a federated credential (OIDC), no secret | A private repo, one commit per run | Teams webhook, plus GitHub's failed-workflow notification | `deploy/schedules/github-action.yml` |
| macOS launchd | The admin's own delegated sign-in, token cache reused | `~/audit/evidence` | Teams webhook, plus the `.err` log | `deploy/schedules/launchd/` |

## Permissions

Application permissions for the managed identity or the app registration: `Policy.Read.All`, `Directory.Read.All`,
`Group.Read.All`, admin consented. Delegated scopes of the same names for the launchd case. Read-only in every case.

## Cycle script parameters

| Parameter | Purpose |
|---|---|
| `-OutRoot` | Durable folder holding `<yyyyMMdd-HHmm>-ca` runs. The previous run is the newest other folder in it. |
| `-Brand` | brand.json for the document and the change report. |
| `-BreakGlass` | UPNs or names of the break-glass accounts; default is the name heuristic. |
| `-NamePattern` | Naming convention regex for the document. |
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

## Things to verify on first deployment

- Automation: PowerShell 7.4 runtime module import for Tenantkeep.Posture and Microsoft.Graph.Authentication; the Bicep `contentLink` flow (spec 6).
- GitHub: the federated credential token exchange in the sample; `azure/login` plus `Get-AzAccessToken -ResourceTypeName MSGraph` is the alternative.
- launchd: how long the cached refresh token survives under the tenant's own sign-in frequency policy.
