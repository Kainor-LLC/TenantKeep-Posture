# How Tenantkeep Posture works

One page for the person who has to reason about the whole thing: what runs where, as whom, reading what, writing
where. The itemised inventory of what each way of running installs, and how to remove it, is docs/footprint.md. The spec (posture-spec.md) says what the product is; this says how it is put together. Dated statements are
decisions; `(verify)` marks what has not been proven live yet.

## The parts

| Part | Where it lives | What it is |
|---|---|---|
| Module `Tenantkeep.Posture` | this repo, PowerShell Gallery and signed zips | Collectors, check engine, catalog, report renderers, licence verifier. Read-only against the tenant, always. |
| Check catalog and baselines | `checks/`, `baselines/` | Data, not code: 204 checks in 13 domains, baselines that select and weight them, framework crosswalks. |
| Report | `templates/`, rendered by the module | One self-contained HTML file per run (inline CSS and JS, no CDN), plus Markdown and optional PDF. |
| Sign-in app **Tenantkeep Posture** | one app registration in the Kainor tenant, manifest in `Tenantkeep.Posture/app.json`, registered by `deploy/setup/New-PostureClientApp.ps1` | A multi-tenant public client with delegated, read-only permissions and no credentials. Customers consent once; `Connect-PostureSession` signs the admin in to it with PKCE on a loopback port and brokers a token per service from that one sign-in (plan: docs/plan-one-signin.md, 2026-10-22). |
| Windows AD collector | `collectors/windows/Get-ADBaseline.ps1` | Standalone read-only script for a domain-joined machine; its files join the evidence folder. |
| Customer-side setup | `deploy/setup/`, `deploy/automation/Grant-ManagedIdentityGraphRole.ps1` | The only tenant writes in the repo: app registration, consents, role grants. Run once by the customer's admin, never by the module. |
| Automation deployment | `deploy/automation/` (Bicep, deploy.ps1), `deploy/schedules/` (runbooks) | Option B: an Automation account in the customer's subscription with a managed identity, a nightly Conditional Access cycle and a monthly full posture cycle. |
| Licensing | `Tenantkeep.Posture/Private/Test-PostureLicense.ps1`, `deploy/licensing/`, private repo `Kainor-LLC/tenantkeep-licensing` | A signed licence file per tenant, verified offline; issued by a Stripe-driven function in the Kainor tenant that signs through Key Vault. |
| Websites | repos `Kainor-LLC/kainor.com`, `Kainor-LLC/tenantkeep.app` | Company site and the product family site (guide, generated catalog page). |

## A run, end to end

1. **Sign in.** Locally, once: `Start-PostureRun` opens the browser for the admin's sign-in to the Tenantkeep Posture
   app, then gets a delegated token per service (Graph, Exchange, SharePoint, Teams, Azure) from the refresh token it
   holds in memory. `Connect-PostureService` is the only file in the module that opens a session, always with one of
   those tokens, except Purview: Security and Compliance PowerShell issues no delegated token to a third-party app, so
   the Exchange module signs the same admin in a second time with its own app. Exchange and Purview run in a second
   process that receives access tokens over standard input and never the refresh token. In Automation, the account's
   managed identity signs in to everything except Purview (see Identities).
2. **Collect.** `Invoke-PostureCollection` writes one evidence folder per run: JSON and CSV files named after the audit
   plan (`04-role-assignments-active.csv`, `exo-04-antiphish.json`, ...), a `collection.json` manifest with the tenant
   id, account, scopes, API versions and errors, and the Conditional Access snapshot. Every Graph call pins its API
   version. Nothing leaves the customer's environment.
3. **Profile.** `New-PostureProfile` discovers what evidence can tell (licences, platforms, identity model, BYOD,
   Copilot) and asks only what it cannot (third-party tools, thresholds, break-glass accounts, frameworks, audience).
   The result is `profile.json` in the client folder, beside `brand.json`, `exceptions.json`, `tenantkeep.lic` and
   `findings.csv`.
4. **Evaluate.** The engine reads the catalog, applies the baseline, asks one fact provider per domain for facts and
   affected objects from the evidence, evaluates each check's pass expression against thresholds, applies exceptions
   (accepted risk counts as a pass), third-party coverage and licence applicability. `checks.json` records every
   result with its reason, evidence files and affected list.
5. **Report.** `New-PostureReport` builds a model (score, headline numbers, domain scorecards, top risks, admins,
   Copilot readiness, Conditional Access, recommendations, trend against a previous run, crosswalk, appendix) and
   renders it. `Export-PostureFindings` writes the register, merging owner, status, effort and dependency by check id
   from the previous register.
6. **Keep.** Locally the run folder stays under `~/tenantkeep/evidence/`. In Automation it is uploaded to the
   `posture-runs` container, the register is written back to the `client` container, old runs are pruned.

## Identities and permissions

- **Local runs** use the signed-in admin's delegated permissions through the Tenantkeep Posture app: every token is
  that admin's and goes no further than their roles. Global Reader covers most reads; Exchange needs View-Only
  Organization Management, SharePoint the SharePoint Administrator role, Purview a compliance read role, Azure Reader
  and Security Reader. The app itself has no credentials, so there is nothing in it to steal; what Kainor controls is
  its redirect addresses and scope list, published in `app.json` and shown on the consent screen, and the app is
  publisher verified. A customer who wants no third-party app registers their own with the same manifest and passes
  its id to `Connect-PostureSession -ClientId`, or opens each session by hand.
- **Automation** uses the account's system-assigned managed identity. `Grant-ManagedIdentityGraphRole.ps1
  -IncludePosture` gives it the Graph application roles every collector needs, Exchange.ManageAsApp, SharePoint
  Sites.FullControl.All (verify the least that works), the Teams tenant admin API role and the Global Reader directory
  role; the deployer adds Reader and Security Reader on the subscriptions. The identity also has Storage Blob Data
  Contributor on the deployment's storage account and nothing else.
- **Purview in Automation** (decided and built 2026-10-15, first live run pending): Microsoft's module has no managed identity sign-in for
  Purview, only a certificate-backed app registration. The customer's setup script creates that app and a certificate
  in a Key Vault in the customer's own subscription; the managed identity reads the certificate at run time and signs
  in with it. The certificate never appears in code, configuration, the runbook or this repository, and the customer
  can revoke it at any time. This is the one exception to "delegated or managed identity only", and it is the
  customer's credential in the customer's vault.
- **No secrets anywhere else.** No app secrets in code or config, no callbacks, no telemetry.

## Licensing and integrity

- A licence is a small JSON file: tenant id, tier (`ca` or `full`), customer, issued and expiry dates, key id, and an
  ECDSA P-256 signature over the canonical fields. The module ships the public keys; the private key is in a Key Vault
  in Kainor's own tenant and never leaves it. Verification is offline and binds the licence to the tenant id
  the evidence recorded. The Conditional Access domain and the three CA cmdlets are free; everything else needs
  `full`. docs/licensing.md has the detail and the honest limits.
- Issuing is automatic: a Stripe payment link with a Tenant ID field, a webhook to an Azure Function in the Kainor
  tenant, a signature through Key Vault, an email from licensing@kainor.com, a row in the register. Renewals re-issue.
- Releases carry a signed `integrity.json` (every file's hash). At import the module checks itself and prints the
  build state, release, development or modified, in every report header. A label, not a lock.

## Storage layout in Automation

```
<storage account>/ca-snapshots/<stamp>-ca/...        nightly Conditional Access runs
<storage account>/posture-runs/<stamp>/...           monthly posture runs: evidence, checks.json, report.html, report.md, findings.csv
<storage account>/client/                            profile.json, brand.json, exceptions.json, tenantkeep.lic, findings.csv, hybrid/ad-*
<storage account>/modules/                           module zips imported into the runtime environment
```

## The report site (Option B opt-in, decided 2026-10-15, being built)

The report is a file, so until now "save an exception" meant editing `exceptions.json` by hand. The report site makes
the browser the place of record: a small web app in the customer's subscription, signed in with the customer's own
Entra accounts, that serves the latest report and accepts saves. Exceptions, the register (owner, status, effort,
dependency) and the tenant configuration (thresholds, third-party tools, baseline, break-glass accounts, frameworks)
are written to the `client` container, which is exactly what the next scheduled run reads. Recording an exception
re-scores the page immediately; the next run makes it permanent. Design details are in docs/report-site.md once built.

## What is still manual

- The Windows AD collector runs on a domain-joined machine and its files are copied into the evidence folder (local)
  or the `client/hybrid/` prefix (Automation). A Hybrid Runbook Worker is the v1.1 answer.
- Purview in Automation until the customer runs `New-PosturePurviewApp.ps1` once.
- Role grants and app registrations: always the customer's admin, by design.

## Repositories

| Repo | Visibility | Holds |
|---|---|---|
| Kainor-LLC/tenantkeep-posture | source-available (currently private on GitHub; the licence assumes readers) | the module, catalog, deployment, docs |
| Kainor-LLC/tenantkeep-licensing | private | the issuing function |
| Kainor-LLC/tenantkeep.app, Kainor-LLC/kainor.com | public | the websites, served by Cloudflare Pages (GitHub Pages does not allow purchase links) |
| Kainor-LLC/LAPSlock (public), Kainor-LLC/tenantkeep-oncall (private) | | the other products |
