# TenantKeep Posture

Microsoft security posture report for Entra, Intune, Defender, Exchange, Purview, SharePoint, Teams, Copilot readiness, Azure and hybrid AD, plus a Conditional Access documentation and diff generator. PowerShell 7 module. Read-only against the tenant, always. Publisher: Kainor LLC. Product name decided 2026-10-13.

The full specification is in `docs/posture-spec.md`. Read it before touching anything. `docs/architecture.md` is the one-page account of how the parts fit: what runs where, as whom, reading and writing what. The audit plan it was designed around is `docs/m365-environment-audit-plan.md`; its Appendix A scripts define the evidence file names this module consumes. The spec, the audit plan and the other planning docs are local to Connor's machine and never committed (see Layout); the product docs are.

## Non-negotiables

- **Read-only.** No cmdlet in this module writes to a tenant. No `-WhatIf` theater around writes either; there are none.
- **Notifications live outside the module.** Teams cards and email (Graph `sendMail`, which needs the `Mail.Send` write permission the customer grants knowingly, or the customer's SMTP relay) are in `deploy/schedules/ca-notifications.ps1`, opt-in, and go only to the customer's own services. The one exception is relayed alerts to TenantKeep On-Call (below). The module's read-only guard stays absolute.
- **Delegated or managed identity only.** Never app secrets in code or config. Local runs use the signed-in admin; the Automation deployment uses a managed identity. One carve-out, decided 2026-10-15: Purview has no managed identity sign-in, so the Automation deployment may use a certificate-backed app registration whose certificate lives in a Key Vault in the customer's own subscription, created by the customer's setup script and read by the managed identity at run time. Never in code, config, the runbook or the repo.
- **Nothing leaves the customer's environment.** The licence is a signed file verified offline against public keys built into the module (`docs/licensing.md`); no licence server, no telemetry, no analytics, no callbacks. Decided 2026-10-15.
- **The one exception: relayed alerts, opt-in.** Decided 2026-10-27. When the customer sets up relayed alerts to TenantKeep On-Call (`deploy/setup/New-PostureRelaySender.ps1`, the Automation variables `RELAY_SENDER_KEY` and `RELAY_PAIRING_CODES`), a risk-relevant Conditional Access change sends an alert encrypted for each paired phone to Kainor's relay, with that phone's push token and the tenant's On-Call entitlement token, which names the tenant ID; once per run the tenant ID goes to the On-Call entitlement endpoint to get that token. Nothing else crosses, Kainor cannot read the alert, and the relay keeps nothing (`docs/RELAY-API.md` in the On-Call repository). It lives in `deploy/schedules/ca-relay.ps1`, outside the module, and is off unless set up. No other exception without a decision.
- **Source published, not open source.** Anyone can read, run and change the code; the licence forbids competing products. See Licensing below.
- **Cross-platform.** macOS is the primary dev machine. Windows-only code is confined to `collectors/windows/` (the jump-box AD collector) and clearly marked.
- **Pin every API version** per call (Graph `v1.0` vs `beta`, Azure REST versions) and record them in the run metadata. The Graph wrapper makes `-ApiVersion` mandatory and collects the versions used into `metadata.json`.
- **Checks are data, not code.** `checks/*.json` holds the catalog; the engine evaluates. Adding a check must not require touching the renderer.

## Layout

```
TenantKeep.Posture/         module: .psd1, .psm1, Public/, Private/
checks/                     catalog JSON, one file per domain (identity, auth, ca, devices, endpoint, email, purview, collaboration, copilot, governance, operations, azure, hybrid)
baselines/                  standard, copilot-readiness, nist-csf-2, nist-800-171, cmmc-2, cisa-scuba, iso-27001-2022, hipaa (no CIS: benchmark content is licensed, decided 2026-10-15)
collectors/                 Get-EntraBaseline, Get-ExchangePurviewBaseline, Get-SpoTeamsBaseline, Get-DefenderBaseline, Get-AzureBaseline, windows/Get-ADBaseline
templates/                  the interactive HTML report (single file, inline CSS/JS, no CDN), print stylesheet
docs/                       product docs tracked by name (guide, licensing, footprint, architecture, collection, scheduling, profile); everything else under docs/ is planning material, gitignored by `docs/*`, edited locally and never committed. A new doc is tracked only by adding a `!docs/<name>.md` line after a scan for tenant ids, account names and resource names
deploy/                     Bicep -> mainTemplate.json, createUiDefinition.json, runbook wrapper, Static Web App opt-in; schedules/ holds the 5.4 cycle script and the runbook, GitHub Action and launchd samples; setup/ holds the one-time customer-side tenant setup scripts (app registrations, role grants): the only tenant writes in the repo, run by the customer's admin, never by the module
tests/                      Pester 5.5+ (6 works); one test file per public cmdlet; catalog schema tests
samples/                    anonymized evidence folder for tests and demos; never real tenant data
build.ps1                   Analyze, Test, Build, Sign, Package. Sign and Package fail without the signing cert
PSScriptAnalyzerSettings.psd1
.githooks/                  pre-commit secret scanner and pre-push analyzer-and-tests gate; enable once per clone with: git config core.hooksPath .githooks
.github/workflows/          ci.yml: Analyze + Test on ubuntu, macos, windows. release.yml: a v* tag opens a draft release, then a package job gated by the release environment (a maintainer approves every run) writes the integrity manifest with the licence key through OpenID Connect, packages, attaches the zip and publishes to the Gallery; with the repository variable RELEASE_SIGNING on it runs on Windows and Authenticode-signs through Azure Artifact Signing first, otherwise it packages unsigned and says so. No certificate, secret or key ever exists as a file, in CI or anywhere. Setup: deploy/release/
```

## Conventions

- Cmdlet prefix is `Posture` as the noun prefix: `Export-PostureCaSnapshot`, `Invoke-PostureChecks`, `New-PostureReport`. Approved verbs only.
- PowerShell 7.4+, `Set-StrictMode -Version Latest`, `$ErrorActionPreference = 'Stop'` inside functions, `[CmdletBinding()]` everywhere, typed parameters, comment-based help on every public cmdlet.
- Graph via `Microsoft.Graph` SDK cmdlets where they exist, `Invoke-MgGraphRequest` where they don't. Exception: snapshot exports the spec calls "untouched" (5.1 `policies.json` and its siblings) go through the module's `Invoke-PostureGraphRequest` wrapper so the file holds wire JSON; typed cmdlets re-case properties and null-fill every schema field, which bloats the snapshot and makes the 5.3 diff noisy. Exchange via `ExchangeOnlineManagement`. SharePoint via `PnP.PowerShell` (the SPO module is Windows-only; don't depend on it outside `collectors/windows/`). Azure via `Az.*` with Resource Graph for anything at scale.
- Evidence files keep the audit plan's names (`04-role-assignments-active.csv`, `exo-04-antiphish.json`, `spo-tenant-settings.json`, ...). New collectors follow the same `NN-name` pattern with a domain prefix.
- Page every Graph call. Never load the full user list into memory to join; use lookups keyed by id.
- Every check JSON has: `id`, `domain`, `title`, `severityDefault`, `license`, `applicableWhen`, `coveredBy`, `thresholds`, `evidence`, `pass`, `remediation`, `learn`, `deepLink`, `narrative`, `frameworks`. Schema is enforced by a Pester test.
- Anything uncertain in docs or comments is tagged `(verify)`, same convention as the spec.
- User-facing text (report narratives, remediation, errors): plain English, no em dashes, no "not just X but Y", no filler. Contractions are fine.
- PSScriptAnalyzer clean with the repo's `PSScriptAnalyzerSettings.psd1` before any commit.

## How to work with me (Connor)

- Give me the full file with the change applied, not a one-line diff to splice in.
- Plan first, then code, for anything that touches module structure or the deploy template.
- Checkpoint after each step on multi-step work. Don't batch and summarize at the end.
- Say plainly when you're not sure. `(verify)` beats a confident guess.
- Push back if I ask for something you think is a mistake.
- Local testing account and tenant details are in `CLAUDE.local.md` (gitignored). Never commit them, never put real tenant output in `samples/`.
- Two test tenants: Kainor (Business Premium, cloud-only) for everyday runs, and the first customer's E5 tenant with their agreement for the licensed domains (P2, Intune, Defender, Purview). Every live run pins `-TenantId`; evidence from either stays under `~/audit/evidence` and never enters the repo, `samples/` or a commit message.

## Licensing (D22, decided: source-available, public repo)

- The repository is written as public and will be: it stays private only until the history is clean of customer names (tracked in the local checklist). Source published, not open source: PolyForm Shield 1.0.0 (decided 2026-10-25, in place of the custom licence until a lawyer pass): use, change and redistribute for any purpose except providing a competing product; the tier entitlement is a product feature, not a licence condition, and versions released under Shield stay under it. `LICENSE.md` holds the text with the Required Notice and Licensor Line of Business lines; every file carries a short copyright header. Header text: `# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.` (a Pester test checks for it).
- Because the repo is public: never commit secrets, real tenant evidence, customer names, or anything from the employer. `CLAUDE.local.md` is gitignored. `samples/` holds anonymized data only. Add a pre-commit secret scanner on day one and refuse to commit if it fails.
- One module, `TenantKeep.Posture`. Tiers are enforced by the entitlement check at runtime, not by hiding code.
- Every release is Authenticode-signed through Azure Artifact Signing (decided 2026-10-25): Microsoft issues and holds the certificate, the sign-release workflow signs, and `build.ps1 -Task Verify` checks every staged file before Package. Package and Publish refuse to run without Sign (a local certificate, the emergency path) or Verify in the same run, unless `-Unsigned` says so explicitly; the integrity manifest is required either way, and an unsigned zip is named unsigned. Unsigned is the state until the signing account's identity validation passes (decided 2026-10-26). Published to the PowerShell Gallery with the license URI set, plus signed zips.
- Issues welcome, external pull requests closed with a polite note (no CLA for now).
- A public, logic-free catalog page (IDs, titles, description, license required) is generated by a build step for the website; never hand-maintain two copies.
- Assume every reader is a reviewer or a competitor. Write it clean, don't obfuscate, and never put anything in it that would embarrass us if quoted.

## Current phase

See `docs/posture-spec.md` section 9. Start with the CA snapshot, document and diff (section 5). First deliverable: `Export-PostureCaSnapshot`.

Progress is tracked in `docs/checklist.md`, one line per deliverable with its commit. It is local and never committed (docs/* is ignored); update it at every checkpoint commit all the same.

## Name

- **The name is TenantKeep, capital K, everywhere it is written.** Decided 2026-10-25. The
  app is TenantKeep On-Call; the report is TenantKeep Posture; the credentials module is
  LAPSlock. The domain stays lowercase, tenantkeep.com. The PowerShell module is
  `TenantKeep.Posture` (renamed 2026-10-25, before any Gallery publish).
