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
- [x] Run against the Kainor tenant on 2026-10-13: 15 policies, 0 errors, all references resolved; `$select=id` on transitiveMembers, `appId in (...)` filter and role definitions with Directory.Read.All all confirmed. Still open: whether insider risk conditions need `-ApiVersion beta` (no such policy in the tenant)

### 5.2 New-PostureCaDocument
- [x] Snapshot reader, resolved policy model, plain-English summary, health flags (9943dc4)
- [x] Markdown: per-policy pages, health table, policy matrix, naming report with proposed names, locations, strengths, contexts, appendix (cebd0f8)
- [x] Summary line reviewed against 15 real policies; session-only policies now say which session controls apply (this checkpoint)
- [x] brand.json: prepared-by, client, colors, font, logo, confidentiality, footer, caNamePattern (cebd0f8, e459304)
- [x] Self-contained HTML, light and dark, print stylesheet, CSP (e459304)
- [x] PDF through headless Edge or Chrome, verified on macOS (e459304)
- [x] Coverage findings page: New-PostureCaDocument runs the 15 CA checks on its snapshot with the same thresholds, -Baseline, -Profile and -Exceptions; the cycle writes checks.json next to the snapshot (weeks 3 to 4 checkpoint C)
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
- [x] Shared cycle script deploy/schedules/ca-snapshot-cycle.ps1: snapshot, document, compare with previous, notify, prune; tested with Export mocked (this checkpoint)
- [x] Azure Automation runbook with managed identity, blob-backed runs (download previous, upload new, prune) (this checkpoint)
- [x] deploy/automation: Bicep (account, system identity, custom PowerShell 7.4 runtime environment, RBAC-only storage, variables, schedule, runbook shell, deployer blob role) plus deploy.ps1 (module zip upload, package import through a user-delegation SAS, Gallery dependency, runbook publish, schedule link) and Grant-ManagedIdentityGraphRole.ps1. Deployed to Kainor-LAPSlock rg-tenantkeep-dev on 2026-10-13 (this checkpoint)
- [x] Test job on 2026-10-13: PowerShell 7.4.6 runtime, module import, Connect-AzAccount -Identity, Connect-MgGraph -Identity and the blob listing all work; the cycle stops at the scope check as designed until the roles are granted
- [x] First real Automation job on 2026-10-14 after the role grant: Completed; full snapshot and document uploaded to the ca-snapshots container (run 20261014-0332-ca)
- [x] Second job on 2026-10-14 downloaded the previous run from blob, then failed at the scope check on a cached pre-grant identity token (documented in docs/scheduling.md)
- [x] Third job on 2026-10-14 ran the full cycle in Automation: previous run downloaded, new snapshot, compare, ca-changes.md and .html uploaded (run 20261014-0336-ca). Spec 5.4 Automation path confirmed end to end
- [x] After the check engine: module redeployed to the dev account and a job uploaded checks.json with the run (20261014-0423-ca)
- [ ] Dev deployment is unsigned (zip of the staged module); releases must go through Package with the signing cert
- [x] GitHub Action sample with a federated credential (verify the token exchange; azure/login is the alternative)
- [x] macOS launchd sample reusing the admin's token cache (verify cache lifetime under sign-in frequency)
- [x] Teams Workflows webhook card on risk-relevant changes (verify card payload against the Workflows connector)
- [x] Email, opt-in, customer-side: Graph sendMail with Mail.Send scoped by an application access policy, or the customer's SMTP relay; report attached; -EmailAlways for a digest (this checkpoint). SMTP path is built but not exercised end to end (verify)
- [x] docs/scheduling.md

## Weeks 3 to 4: check engine and identity report
- [x] Check catalog schema (checks/README.md) and the catalog test over every shipped file; loader rejects a missing field, bad severity, duplicate id (this checkpoint)
- [x] Expression evaluator for pass rules: own parser, no Invoke-Expression; facts.* and thresholds.* only (this checkpoint)
- [x] Invoke-PostureChecks and Get-PostureCheckCatalog with baseline (name or path), profile.json, exceptions.json (check-level and object-level, expiry), custom check folders, checks.json output; baselines/standard.json (this checkpoint)
- [x] checks/ca.json: the 15 checks from spec 4.3 with narrative, remediation, Learn link, NIST CSF 2 / ISO 27001 / CMMC / SCuBA references; CIS left empty pending the terms check (this checkpoint)
- [x] CA fact provider from a snapshot folder; verified on the sample (13 of 15 fail as designed) and on the Kainor tenant (12 pass, 2 fail, 1 not evaluated) (this checkpoint)
- [ ] (verify) the 14 administrator roles in CA-003 against Microsoft's current recommended list, and the SCuBA ids
- [x] Invoke-PostureCollection with the Entra collector (A.1 sections 1, 2, 4, 5, 6, 7, 10, 11) and the CA snapshot in the same folder; users and PIM fallbacks; collection.json manifest; docs/collection.md (checkpoint E)
- [x] First real collection against the Kainor tenant on 2026-10-14: 32 files, PIM path, 4 active and 2 eligible roles, 2 permanent Global Administrators; the only failure was the hybrid sync step without OnPremDirectorySynchronization.Read.All, now listed as an optional scope. Caught and fixed: isPrivileged is beta-only on role definitions; the Graph wrapper now surfaces Graph's error text
- [x] Intune collector (A.1 section 9 plus the 4.4 additions: enrollment restrictions, endpoint security policy families, MDE connector, cleanup rule, BitLocker key presence) (checkpoint I)
- [x] Devices domain: checks/devices.json (14 checks from spec 4.4) and Get-PostureDevicesFact (checkpoint I)
- [x] First real Intune collection on Kainor on 2026-10-14: 55 files, 0 errors; confirmed: managedDeviceCleanupRules is the readable cleanup endpoint (managedDeviceCleanupSettings is forbidden for delegated reads), the ASR template family is endpointSecurityAttackSurfaceReduction, the MDE connector reports partnerState enabled, a missing APNs certificate is a 404. All four domains: 53 checks, 40 pass, 10 fail, 2 not evaluated, 1 not applicable
- [ ] (verify) remaining: the newer per-platform enrollment restriction shape on tenants that use it; FileVault escrow per Mac from the Intune encryption report
- [ ] Legacy sign-ins (A.1 section 12), optional
- [x] Identity domain: checks/identity.json (15 checks from spec 4.1) and Get-PostureIdentityFact over the A.1 files; ID-006 (PIM settings) and ID-014 (log export) stay not evaluated until their collectors exist (checkpoint F)
- [x] Authentication domain: checks/auth.json (9 checks from spec 4.2) and Get-PostureAuthFact; AU-009 (per-user MFA) not evaluated until collected (checkpoint F)
- [x] All three domains on the Kainor collection: 39 checks, 28 pass, 8 fail, 3 not evaluated with named reasons
- [x] A.1 additions: PIM role management policies (ID-006), legacy per-user MFA state through batched reads (AU-009), Entra devices section 8 (checkpoint H)
- [ ] Azure diagnostic settings with the Azure collector (ID-014)
- [ ] (verify) SCuBA ids on the identity and auth checks; CIS ids once the terms are cleared
- [x] New-PostureProfile wizard (spec 10.2): twelve questions, every answer a parameter, -NonInteractive, edit in place, licenses detected from evidence or Graph and confirmed; docs/profile.md (checkpoint D)
- [ ] (verify) service plan names for Entra Suite, Intune Suite and SharePoint Advanced Management in Get-PostureLicenseToken
- [ ] New-PostureProfile wizard
- [x] New-PostureReport G1: report model (weighted score with the method stated, headline numbers, domain scorecards, top risks, four recommendation buckets, admins table, CA matrix, appendix), Markdown output, -Client folder, checks.json beside it; Kainor scores 81 (B) over 36 checks (checkpoint G1)
- [x] New-PostureReport G2: self-contained interactive HTML (templates/report.css, report.js, CSP default-src none), eleven views with the uncollected ones shown as such, checks explorer with filters and search, check detail drawer with the exception snippet and CSV export, executive mode toggle, print view, PDF; verified on the Kainor report (checkpoint G2)
- [ ] findings.csv export (Export-PostureFindings), portal deep links, trend across runs
- [x] Exchange Online collector (A.2 exo-01 to exo-10 plus attack simulations and the mail DNS records with MTA-STS and TLS-RPT): one Get-only entry point, never connects, skipped with a warning without a session; `-Collector Exchange`, `-SkipMailboxEnumeration` (checkpoint J)
- [x] Email domain: checks/email.json (21 checks from spec 4.10; the inbox-rule check waits for an audit search collector) and Get-PostureEmailFact; MDO delivery checks covered by a third-party gateway from the profile, DNS, forwarding, protocol and audit checks evaluated regardless (checkpoint J)
- [x] First real Exchange collection on Kainor on 2026-10-14: 87 files across all three collectors, 0 errors; email domain 16 pass, 4 fail (no EOP or MDO preset policy, MTA-STS and TLS-RPT unpublished, POP and IMAP on by default per mailbox), 1 not evaluated (attack simulation without the scope). All five domains: 74 checks, 56 pass, 14 fail, 3 not evaluated, 1 not applicable. Caught and fixed: the evidence root is now a full provider path, so a tilde or relative root works from a script
- [ ] Inbox rules forwarding externally (spec 4.10) through an audit search, not Get-InboxRule
- [ ] (verify) SCuBA MS.EXO ids on the email checks; CIS ids once the terms are cleared
- [x] Intune policy state for endpoint security (spec 4.11, the Intune half): settings catalog values flattened per assigned policy, template and compliance policy scalars, Windows Hello config, app protection policies, feature update profiles (checkpoint K)
- [x] Endpoint domain: checks/endpoint.json (18 policy-state checks: baselines, BitLocker, firewall, LAPS, Defender AV, tamper protection, network protection, ASR rules and exclusions, SmartScreen, Office macros, Hello and cloud Kerberos trust, update rings, FileVault, macOS hardening, Platform SSO, mobile) and Get-PostureEndpointFact (checkpoint K)
- [x] First live run of the endpoint domain on Kainor on 2026-10-14 (93 files, 0 errors) confirmed the settings catalog ids for BitLocker (XTS child is encryptionmethodwithxtsosdropdown_name, TPM is configuretpmusagedropdown_name _1), firewall, LAPS, Defender AV (schedulescanday 0 is every day, 8 never), tamper protection (_options _0), network protection, all 19 ASR rule names (prevalenceagetrustedlistcriterion has no 'a'), per-rule exclusions, SmartScreen, Office macros (l_blockmacroexecutionfrominternet), passportforwork, macOS Gatekeeper, firewall, escrow and Platform SSO, SIP in compliance, update ring deadlines. Endpoint domain after the corrections: 14 pass, 3 fail (no security baselines, one ASR per-rule exclusion, no mobile app protection or iOS compliance policy), 1 not applicable
- [ ] (verify) usecloudtrustforonpremauth; com.apple.mcx.filevault2_enable _0 meaning On; baseline template display names
- [x] SharePoint app setup script (deploy/setup/New-PostureSharePointApp.ps1): registers the PnP app with read-only delegated permissions, reuses an existing one through Graph, records sharePointClientId in the profile, prints the manual remainder. Connor asked for setup to be as automated as possible (2026-10-14); it stays outside the module because it writes to the tenant (checkpoint L1)
- [x] First live registration on Kainor on 2026-10-14: the app was created on the first run; the profile write then failed on a tilde path, fixed in the script and in the two module cmdlets that resolved paths with GetFullPath; a rerun with -ClientId recorded it
- [x] Admin consent landed on the Kainor app: Connect-PnPOnline to the admin site with AllSites.Read succeeded on 2026-10-14. Connect-MicrosoftTeams with a browser fails on macOS (kernel32.dll); Azure CLI tokens or device authentication work, documented in docs/collection.md
- [x] AllSites.Read is not enough: Get-PnPTenant and Get-PnPTenantSite were denied on Kainor on 2026-10-14. The setup script now requests delegated AllSites.FullControl by default (-ReadOnlyPermission keeps Read) and can add it to an existing registration through Graph
- [x] SharePoint and Teams collectors (A.3 spo-* and teams-* files, plus the group lifecycle policy and ownerless groups in the Entra collector): Get-only entry points, never connect, skipped with a warning without a session; `-Collector SharePoint, Teams`, `-SkipSiteEnumeration` (checkpoint L2)
- [x] Collaboration domain: checks/collaboration.json (14 checks from spec 4.6) and Get-PostureCollaborationFact (checkpoint L2)
- [ ] Oversharing views from SharePoint Advanced Management reports: sites shared with Everyone except external users, active anonymous links, inactive sites (spec 4.6, SAM)
- [ ] (verify) Teams app permission policy shape on tenants moved to app centric management; SCuBA MS.SHAREPOINT and MS.TEAMS ids on the collaboration checks
- [ ] Defender effective state (4.11 Defender half: onboarding, sensor health, AV mode, ASR effective, EDR block mode, AIR, vulnerability management) with Get-DefenderBaseline; needs the the first customer tenant
- [ ] Effective-state device checks waiting on reports: BitLocker and FileVault encryption report, Credential Guard and HVCI, update compliance, local admin population, recovery key access audit
- [x] Coverage findings page in the CA document fed from the engine (checkpoint C)

## Later weeks
See spec section 9 for weeks 5 to 12 and v1.1. Not broken down until weeks 3 to 4 are underway.

## Open decisions and verifications
- Kainor-hosted email relay (Connor, 2026-10-13): not built. It would be the first data path out of the customer's environment besides the license check and contradicts CLAUDE.md and spec 11. If it ships, it carries a count and a link only, is opt-in, and the privacy statement changes. Decide before the licensed tier (weeks 11 to 12).
- Gallery packaging of checks/, baselines/ and templates/ as sibling folders inside the module (verify)
- PowerShell Gallery terms for non-open-source modules (verify, spec 6)
- Automation module contentLink flow in Bicep (verify, spec 6)
