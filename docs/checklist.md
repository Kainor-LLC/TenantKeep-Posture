# Build checklist

Tracks the spec's section 9 plan at the deliverable level. Updated at every checkpoint commit. One line per item:
status, what, commit. Statuses: `[x]` done and tested, `[~]` in progress, `[ ]` not started, `[-]` deferred with a reason.

## Weeks 1 to 2: CA snapshot, document, diff (spec 5)

### Scaffold
- [x] Module layout per CLAUDE.md, manifest, root module, private helpers (6ff7e9e)
- [x] build.ps1: Analyze (with parse check), Test, Build, Sign, Package; Sign and Package refuse without a cert (6ff7e9e, e459304)
- [x] Pester and PSScriptAnalyzer wired locally and in CI on three OSes (6ff7e9e)
- [x] Pre-commit secret scanner with tests, enabled per clone with `git config core.hooksPath .githooks` (6ff7e9e)
- [x] LICENSE.md placeholder for the source-available license, D22 (6ff7e9e)
- [x] Spec and scrubbed audit plan committed; oncall spec gitignored (60c234d)
- [ ] Lawyer pass on LICENSE.md before first release
- [ ] Partner Center enrollment started (spec 9, runs in the background)

### 5.1 Export-PostureCaSnapshot
- [x] Seven files per run, raw wire JSON, scope check, errors.txt, metadata with API versions (386314d)
- [x] Name resolution: users, groups, service principals, roles, apps, locations, strengths, contexts; deleted flagged (386314d)
- [x] group-scope: transitive count plus SHA-256 of sorted ids; UPNs only with -IncludeMembers (386314d)
- [ ] Run against a real tenant and confirm the (verify) items: `$select=id` on transitiveMembers, `appId in (...)` batch of 15, role definitions readable with Directory.Read.All, beta-only insider risk condition

### 5.2 New-PostureCaDocument
- [x] Snapshot reader, resolved policy model, plain-English summary, health flags (9943dc4)
- [x] Markdown: per-policy pages, health table, policy matrix, naming report with proposed names, locations, strengths, contexts, appendix (cebd0f8)
- [x] brand.json: prepared-by, client, colors, font, logo, confidentiality, footer, caNamePattern (cebd0f8, e459304)
- [x] Self-contained HTML, light and dark, print stylesheet, CSP (e459304)
- [x] PDF through headless Edge or Chrome, verified on macOS (e459304)
- [-] Coverage findings page: placeholder until the check engine ships (weeks 3 to 4); checks are catalog data, not renderer code
- [ ] Policy matrix column set configurable from brand.json or profile (spec 5.2 says configurable; today only -MatrixColumn)
- [ ] "Changed by" from the audit log on the CA page (spec 7.2) once Compare exists

### 5.3 Compare-PostureCaSnapshot
- [x] Added, removed, renamed, state changed, modified; field-level before and after with resolved names (935b730)
- [x] Named location, auth strength and auth context changes (935b730)
- [x] Scope drift from group hashes; member-level diff when both snapshots have members (935b730)
- [x] Risk-relevant change rules: the seven from 5.3 plus enabledPolicyRemoved; -BreakGlass list or name heuristic (935b730)
- [ ] Field-level diff covers the resolved model; a Graph property outside the model (new in a later API version) is not diffed (verify whether a raw fallback is wanted)
- [x] Markdown and HTML change report, email-ready, risk-relevant changes first (this checkpoint)
- [x] Non-zero exit code when risk-relevant changes exist: -FailOnRiskRelevantChange throws after writing the report; verified with pwsh -Command (this checkpoint)
- [ ] "Changed by" from the audit log (spec 7.2) needs AuditLog.Read.All and a directory audit pull per changed policy; not in the snapshot today

### 5.4 Scheduling samples
- [ ] Azure Automation runbook sample with managed identity
- [ ] GitHub Action sample
- [ ] macOS launchd sample
- [ ] Teams or email notification on risk-relevant changes

## Weeks 3 to 4: check engine and identity report
- [ ] Check catalog schema and Pester schema test (CLAUDE.md field list)
- [ ] checks/ca.json from spec 4.3, then identity and auth domains
- [ ] Invoke-PostureChecks with baseline, profile, exceptions.json
- [ ] New-PostureProfile wizard
- [ ] Interactive HTML report renderer (templates/), findings.csv export, portal deep links
- [ ] Coverage findings page in the CA document fed from the engine

## Later weeks
See spec section 9 for weeks 5 to 12 and v1.1. Not broken down until weeks 3 to 4 are underway.

## Open decisions and verifications
- Gallery packaging of checks/, baselines/ and templates/ as sibling folders inside the module (verify)
- PowerShell Gallery terms for non-open-source modules (verify, spec 6)
- Automation module contentLink flow in Bicep (verify, spec 6)
