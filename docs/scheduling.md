# Scheduling the Conditional Access snapshot (spec 5.4)

There is no Kainor server. The nightly cycle runs where the customer already runs things. All three schedulers
call the same script, `deploy/schedules/ca-snapshot-cycle.ps1`, which takes the snapshot, writes the document,
compares with the previous run, posts risk-relevant changes to Teams when a webhook is configured, and prunes old
runs. The module never sends mail (Mail.Send is a write scope); email alerting comes from the scheduler's own
failure notifications, which `-FailOnRiskRelevantChange` triggers by failing the job.

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
| `-KeepRuns` | Delete the oldest runs beyond this count. 0 keeps everything. |
| `-FailOnRiskRelevantChange` | Throw at the end when the diff found risk-relevant changes, so the job fails. |

## What a risky night looks like

1. The snapshot and document are written as usual.
2. `ca-changes.md` and `ca-changes.html` land in the new run folder with the risk-relevant changes at the top.
3. Teams gets a card listing them, when a webhook is set.
4. The job fails, and the scheduler's notification goes out.

## Things to verify on first deployment

- Automation: PowerShell 7.4 runtime module import for Tenantkeep.Posture and Microsoft.Graph.Authentication; the Bicep `contentLink` flow (spec 6).
- GitHub: the federated credential token exchange in the sample; `azure/login` plus `Get-AzAccessToken -ResourceTypeName MSGraph` is the alternative.
- launchd: how long the cached refresh token survives under the tenant's own sign-in frequency policy.
