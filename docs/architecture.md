# How TenantKeep Posture works

One page for the person who has to reason about the whole thing: what runs where, as whom, reading what, writing
where. The itemised inventory of what each way of running installs, and how to remove it, is docs/footprint.md. The spec (posture-spec.md) says what the product is; this says how it is put together. Dated statements are
decisions; `(verify)` marks what has not been proven live yet.

## The parts

| Part | Where it lives | What it is |
|---|---|---|
| Module `TenantKeep.Posture` | this repo, PowerShell Gallery and signed zips | Collectors, check engine, catalog, report renderers, licence verifier. Read-only against the tenant, always. |
| Check catalog and baselines | `checks/`, `baselines/` | Data, not code: the checks, one file per domain, baselines that select and weight them, framework crosswalks. |
| Report | `templates/`, rendered by the module | One self-contained HTML file per run (inline CSS and JS, no CDN), plus Markdown and optional PDF. |
| Sign-in app **TenantKeep** | one app registration in the Kainor tenant, manifest in `TenantKeep.Posture/app.json`, registered by `deploy/setup/New-PostureClientApp.ps1` | A multi-tenant public client with delegated permissions and no credentials, shared with the TenantKeep On-Call app for what that reads (`sharedWith` in the manifest). Every permission on it is read-only by its name, on every API; everything that writes lives in other registrations. Customers approve Posture's permissions once, through a link that names them. `Connect-PostureSession` signs the admin in with PKCE on a loopback port, asking the browser only to sign in, then fetches what the organisation approved with the refresh token and brokers the Graph and Power BI tokens from that sign-in. |
| Second app **TenantKeep Posture for Azure, Teams and Power Platform** | one more registration in the Kainor tenant, manifest in `TenantKeep.Posture/app-services.json`, registered by the same script | The three APIs that offer no read-only permission (Azure Service Management, the Teams admin API, the Power Platform admin API) are read through this one, which Posture alone signs in to, so the shared app stays read-only on every API. `Connect-PostureSession -Services` signs the same admin in to it; `Start-PostureRun` does that by itself when a run reads one of the three and the organisation has approved the app. |
| Windows AD collector | `collectors/windows/Get-ADBaseline.ps1` | Standalone read-only script for a domain-joined machine; its files join the evidence folder. |
| Customer-side setup | `deploy/setup/`, `deploy/automation/Grant-ManagedIdentityGraphRole.ps1` | The only tenant writes in the repo: app registration, consents, role grants. Run once by the customer's admin, never by the module. |
| Automation deployment | `deploy/automation/` (Bicep, deploy.ps1), `deploy/schedules/` (runbooks) | Option B: an Automation account in the customer's subscription with a managed identity, a nightly Conditional Access cycle and a monthly full posture cycle. |
| Licensing | `TenantKeep.Posture/Private/Test-PostureLicense.ps1`, `deploy/licensing/`, private repo `Kainor-LLC/tenantkeep-licensing` | A signed licence file per tenant, verified offline; issued by a Stripe-driven function in the Kainor tenant that signs through Key Vault. |
| Websites | repos `Kainor-LLC/kainor.com`, `Kainor-LLC/tenantkeep.app` | Company site and the product family site (guide, generated catalog page). |

## A run, end to end

1. **Sign in.** Locally, once: `Start-PostureRun` opens the browser for the admin's sign-in to the TenantKeep Posture
   app, then gets a delegated token per service from the refresh token it holds in memory: Graph, and Power BI where the
   tenant approved it. Azure, Teams and Power Platform get theirs from a second sign-in, to the second app, which
   follows the first when the run reads one of them; SharePoint from its own optional app. `Connect-PostureService` is the only file in the module that opens a session, always with one of
   those tokens, except Exchange and Purview: Security and Compliance PowerShell issues no delegated token to a
   third-party app, and Exchange Online's only delegated scope reads "Manage" on a consent screen, so both sign the same
   admin in through the Exchange module's own app, which renews its own tokens. Exchange and Purview run in a second
   process that receives access tokens over standard input and never the refresh token. It starts first and signs in
   to Purview first, so that prompt comes in the first minute, then collects alongside the main process; both write
   into one run folder, and `errors.txt` and the `collection.json` merge are serialised on a lock file in it. When
   the sign-in ends during a run (a Conditional Access sign-in frequency) and a renewal is refused, the main process
   asks the same admin to sign in again and gives the new refresh token to the thread that renews for the second
   process; with no one to ask, the run stops once and the domains that depend on the sign-in are not recorded as
   finished. In Automation, the account's managed identity signs in to everything except Purview (see Identities).
2. **Collect.** `Invoke-PostureCollection` writes one evidence folder per run: JSON and CSV files named after the audit
   plan (`04-role-assignments-active.csv`, `exo-04-antiphish.json`, ...), a `collection.json` manifest with the tenant
   id, account, scopes, API versions and errors, and the Conditional Access snapshot. Every Graph call pins its API
   version. Nothing leaves the customer's environment. A journal (`logs/journal.jsonl`) records each step as it
   starts, finishes or fails, each file as it is written and each domain as it finishes, and the manifest is
   rewritten after every domain. `Resume-PostureRun` reads both, so a run whose process stopped is picked up at the
   domain it stopped in, and a file left from an earlier attempt, whose step ran again and did not write it, is
   never read as this run's evidence. Inside the domain being collected again, a long list (users, registration,
   groups, devices, mailboxes, sites) that finished in this run less than a day ago is kept, and a Graph list that
   stopped part way carries on from a cursor (`logs/cursor-<list>.json`: the next page link, how far each file had
   got, and the step's counts, saved together every few pages and removed when the list finishes).
3. **Profile.** `New-PostureProfile` discovers what evidence can tell (licences, platforms, identity model, BYOD,
   Copilot) and asks only what it cannot (third-party tools, thresholds, break-glass accounts, frameworks, audience).
   The result is `profile.json` in the client folder, beside `brand.json`, `exceptions.json` and `tenantkeep.lic`.
4. **Evaluate.** The engine reads the catalog, applies the baseline, asks one fact provider per domain for facts and
   affected objects from the evidence, evaluates each check's pass expression against thresholds, applies exceptions
   (accepted risk counts as a pass), third-party coverage and licence applicability. `checks.json` records every
   result with its reason, evidence files and affected list.
5. **Report.** `New-PostureReport` builds a model (score, headline numbers, domain scorecards, top risks, admins,
   Copilot readiness, Conditional Access, recommendations, trend against a previous run, crosswalk, appendix) and
   renders it. `Export-PostureFindings` writes findings.csv, the failing checks most severe first, rebuilt each run.
6. **Keep.** Locally the run folder stays under `~/tenantkeep/evidence/`. In Automation it is uploaded to the
   `posture-runs` container and old runs are pruned.

## Identities and permissions

- **Local runs** use the signed-in admin's delegated permissions through the TenantKeep app: every token is
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
<storage account>/client/                            profile.json, brand.json, exceptions.json, tenantkeep.lic, hybrid/ad-*
<storage account>/modules/                           module zips imported into the runtime environment
```

## Recording decisions

The report is a file and writes nothing. Accepted risks live in `exceptions.json` and review dates under
`attestations` in `profile.json`, both in the client folder (or the `client` container for Automation), and the next
run reads them. A browser-side register and a hosted report site that accepted saves were both dropped on
2026-11-20: saving from a page and reopening it was more trouble than the files it replaced.

## What is still manual

- The Windows AD collector runs on a domain-joined machine and its files are copied into the evidence folder (local)
  or the `client/hybrid/` prefix (Automation). A Hybrid Runbook Worker is the v1.1 answer.
- Purview in Automation until the customer runs `New-PosturePurviewApp.ps1` once.
- Role grants and app registrations: always the customer's admin, by design.

## Repositories

| Repo | Visibility | Holds |
|---|---|---|
| Kainor-LLC/TenantKeep-Posture | source-available (currently private on GitHub; the licence assumes readers) | the module, catalog, deployment, docs |
| Kainor-LLC/tenantkeep-licensing | private | the issuing function |
| Kainor-LLC/tenantkeep.app, Kainor-LLC/kainor.com | public | the websites, served by Cloudflare Pages (GitHub Pages does not allow purchase links) |
| Kainor-LLC/LAPSlock (public), Kainor-LLC/tenantkeep-oncall (private) | | the other products |
