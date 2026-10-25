# Changelog

One entry per release. Pre-release work is summarised under Unreleased until the first tag; after that, every
entry names the version, the date and what changed for the person running the module. Dates are the day the
work landed on main.

## Unreleased

- Release signing through Azure Artifact Signing: the Sign release workflow, `build.ps1 -Task Verify`, and the
  Kainor-side setup script under deploy/release.

## 0.1.0-alpha (2026-10-25)

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
