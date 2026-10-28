# Changelog

One entry per release. Pre-release work is summarised under Unreleased until the first tag; after that, every
entry names the version, the date and what changed for the person running the module. Dates are the day the
work landed on main.

## Unreleased

- Relayed alerts: a busy relay or Apple (503), the relay's rate limit (429) or no answer within 15 seconds is tried
  again, at most twice, honouring Retry-After up to 30 seconds; every other answer is final. The run's relay and
  entitlement calls share one connection and time out after 15 seconds, so a relay that never answers cannot stall
  the cycle. A failure still names the relay's error code only. The same rule as the On-Call repository's sender.

## 0.3.0-alpha (2026-10-27)

- Free 30-day trial: Start-PostureRun prints the trial link with the tenant id when the tenant has no Full
  licence, and the report says "Trial licence, ends <date>" under a trial. The module still sends nothing anywhere.
- CP-009 (Restricted SharePoint Search) no longer fails on a tenant that never set the mode: PnP.PowerShell 3.2
  reports it as "Restricted search mode is currently not set.", which is off. Evidence with no mode now reads as not
  evaluated.
- Azure Automation: the runtime environment is PowerShell 7.6 (`tenantkeep-ps76`), and deploy.ps1 imports the
  collector modules at the versions the module is tested with. It now waits for every module import to finish,
  sends one that Automation fails on its side again (twice at most), and says when a job can start; it stops with an
  error if an import still has not finished after `-ImportWaitMinutes` (20 by default).

## 0.2.0-alpha (2026-10-27)

The first build Authenticode-signed by Kainor LLC on the PowerShell Gallery, through Azure Artifact Signing.

- `Initialize-PostureClient`: creates the client folder where you want it, verifies and copies the licence in, seeds
  the profile, and prints the Start-PostureRun line.
- Every release is signed and carries the integrity manifest. The release workflow drafts on the tag, then after a
  maintainer's approval signs every file on a Windows runner, verifies the signatures, writes the manifest, attaches
  the package to the GitHub release and publishes to the Gallery. No certificate or key exists as a file anywhere.
- The SHA-256 file next to each package reads correctly with `shasum -c` and `sha256sum -c` on every platform.

## 0.1.0-alpha (2026-10-25; on the PowerShell Gallery 2026-10-26, that copy unsigned; the GitHub release package Authenticode-signed by Kainor LLC through Azure Artifact Signing 2026-10-27)

First tagged pre-release, from a public repository under PolyForm Shield 1.0.0. Everything built 2026-10-13 to
2026-10-25. Not yet on the PowerShell Gallery; install from the release zip or a clone.

- Conditional Access: `Export-PostureCaSnapshot` (raw wire JSON, name resolution, group scope hashes),
  `New-PostureCaDocument` (Markdown, self-contained HTML, PDF, coverage findings) and `Compare-PostureCaSnapshot`
  (field-level diff, scope drift, risk-relevant change rules, non-zero exit for pipelines).
- Check engine: `Invoke-PostureChecks` and `Get-PostureCheckCatalog` over a data-only catalog of thirteen domains
  (identity, authentication, Conditional Access, devices, endpoint, email, Purview, collaboration, Copilot readiness,
  governance, operations, Azure, hybrid), with baselines for NIST CSF 2, NIST 800-171, CMMC 2, CISA SCuBA,
  ISO 27001:2022, HIPAA and Copilot readiness, profiles and exceptions.
- Collectors: Entra, Intune, Defender (advanced hunting), Exchange Online, SharePoint, Teams, Purview and Azure
  through `Invoke-PostureCollection`, plus the Windows-only Active Directory script for a jump box.
- Report: `New-PostureReport` (weighted score, domain scorecards, interactive single-file HTML with a risk register,
  exception form and settings view, trend against a previous run, PDF), `Export-PostureFindings` for the register,
  `New-PostureProfile` for tenant discovery and the questions evidence cannot answer.
- One sign-in: `Connect-PostureSession`, `Disconnect-PostureSession` and `Start-PostureRun`, which runs every
  collector from one delegated sign-in through the Kainor-published multi-tenant app and opens the report.
  Purview signs in on its own because Security and Compliance PowerShell issues no token to a third-party app.
- Requirements: `Get-PostureRequirement` shows each service module installed against the version the collectors
  were tested with; `Start-PostureRun` warns on an older one, and collection.json records the module versions,
  PowerShell version and operating system of every run.
- Licence: PolyForm Shield 1.0.0 (use, change and redistribute for anything except a competing product) replaces the
  placeholder text, with Kainor's Required Notice and Licensor Line of Business lines.
- Licensing: offline, signed licence files verified against public keys in the module; the Conditional Access domain
  is free, the rest needs the Full tier. Signed integrity manifest and build state in every report.
- Deployment: Azure Automation templates and runbooks for the scheduled Conditional Access cycle and the monthly
  posture cycle, with a managed identity and a customer-side Key Vault for the Purview certificate; GitHub Action
  and launchd samples; Teams and email notifications that stay inside the customer's environment.
