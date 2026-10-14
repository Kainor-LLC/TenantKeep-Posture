# Tenantkeep Posture

Read-only Microsoft 365 security posture report, with Conditional Access documentation and diff.
PowerShell 7. Mac first; Windows and Linux supported.

**Source published, not open source.** Read every line; you can't fork it. See [LICENSE.md](LICENSE.md).

## Status

Pre-release. Shipped: `Export-PostureCaSnapshot` (spec 5.1), `New-PostureCaDocument` (5.2: Markdown, self-contained HTML, PDF, with the Conditional Access checks on its Coverage findings page), `Compare-PostureCaSnapshot` (5.3), the scheduling layer with an Azure Automation deployment (5.4), the check engine with the Conditional Access, identity and authentication catalogs (`Invoke-PostureChecks`, `Get-PostureCheckCatalog`), the Entra collector (`Invoke-PostureCollection`), the profile wizard (`New-PostureProfile`) and the interactive posture report (`New-PostureReport`). Next: devices and endpoint security. Progress: [docs/checklist.md](docs/checklist.md).

## Use

```powershell
Import-Module ./Tenantkeep.Posture
Connect-MgGraph -Scopes Policy.Read.All, Directory.Read.All, Group.Read.All -NoWelcome
Export-PostureCaSnapshot                       # writes ~/audit/evidence/<yyyyMMdd-HHmm>-ca/
Export-PostureCaSnapshot -IncludeMembers       # also stores group member UPNs
New-PostureCaDocument -Snapshot ~/audit/evidence/<stamp>-ca -NamePattern '^CA-\d{3}-'   # ca-document.md and .html next to the snapshot
New-PostureCaDocument -Snapshot ~/audit/evidence/<stamp>-ca -Format Pdf -Brand ./brand.json  # adds ca-document.pdf via headless Edge or Chrome
Compare-PostureCaSnapshot -Before <older>-ca -After <newer>-ca                              # ca-changes.md and .html, risk-relevant changes first
Compare-PostureCaSnapshot -Before <older>-ca -After <newer>-ca -FailOnRiskRelevantChange     # non-zero exit for a runbook or CI step
Invoke-PostureChecks -Evidence ~/audit/evidence/<stamp>-ca -Domain ca                       # checks.json: the 15 CA checks against the snapshot
Get-PostureCheckCatalog -Domain ca | Format-Table Id, Severity, Title                         # what the catalog checks
Invoke-PostureCollection -OutRoot ~/audit/evidence                                            # A.1 identity evidence plus the CA snapshot in one run folder
New-PostureReport -Evidence ~/audit/evidence/<stamp> -Profile ~/audit/profile.json            # report.html (interactive), report.md, checks.json; add -Format Pdf
New-PostureProfile -Path ~/audit/profile.json -FromGraph                                      # the org profile the checks read
```

## Develop

```powershell
git config core.hooksPath .githooks            # once per clone: pre-commit secret scanner
./build.ps1 -Task Analyze, Test
./build.ps1 -Task Package -CertificatePath ./signing.pfx   # release zip; fails without a code-signing cert
```

Conventions for contributors and for Claude are in [CLAUDE.md](CLAUDE.md).
