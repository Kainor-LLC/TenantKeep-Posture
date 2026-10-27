# TenantKeep Posture

Read-only Microsoft 365 security posture report, with Conditional Access documentation and diff.
PowerShell 7. Mac first; Windows and Linux supported.

**Source published, not open source.** Read every line, run it, change it for your own use; you may not build a competing product on it. PolyForm Shield 1.0.0, see [LICENSE.md](LICENSE.md).

## Status

Pre-release 0.2.0-alpha on the [PowerShell Gallery](https://www.powershellgallery.com/packages/TenantKeep.Posture), Authenticode-signed by Kainor LLC. Everything in [CHANGELOG.md](CHANGELOG.md) runs today:
one sign-in, every collector (Entra, Intune, Defender, Exchange Online, SharePoint, Teams, Purview, Azure, plus a
Windows-only Active Directory script), thirteen check domains, the interactive report, the findings register, the
Conditional Access snapshot, document and diff, and the Azure Automation deployment for scheduled runs. Next: the
first tagged release, the Marketplace listing, the trial licence on first run.

## Use

Two lines. The sign-in is delegated, read-only, and the only one (Purview opens a second window of its own).

```powershell
Install-PSResource TenantKeep.Posture -Prerelease   # or Install-Module TenantKeep.Posture -AllowPrerelease; from a clone: Import-Module ./TenantKeep.Posture
Start-PostureRun                                    # sign in, collect everything the account can read, open report.html
```

With a licence, or a folder of your own choosing, one more line first:

```powershell
Initialize-PostureClient -LicensePath ~/Downloads/tenantkeep.lic          # or -Path <folder> -ClientName 'Contoso Ltd'
```

Useful switches: `-TenantId` refuses any other tenant, `-Collector Entra, Intune, Exchange` runs a subset,
`-DeviceCode` signs in without a browser, `-Client` names the client folder. The step-by-step guide, including the
manual path with your own sessions, is [docs/guide.md](docs/guide.md). The pieces on their own:

```powershell
Export-PostureCaSnapshot                                                   # ~/tenantkeep/evidence/<stamp>-ca/, raw wire JSON
New-PostureCaDocument -Snapshot <stamp>-ca -Format Pdf -Brand ./brand.json  # ca-document.md, .html, .pdf
Compare-PostureCaSnapshot -Before <older>-ca -After <newer>-ca -FailOnRiskRelevantChange
Invoke-PostureCollection -OutRoot ~/tenantkeep/evidence                    # the evidence folder, every collector with a session
Invoke-PostureChecks -Evidence <stamp> -Baseline cisa-scuba                # checks.json
New-PostureReport -Evidence <stamp> -ProfilePath <client>/profile.json -Previous <last>/checks.json   # report.html with trend
Export-PostureFindings -Path <stamp>/checks.json                         # findings.csv, the register
Get-PostureCheckCatalog -Domain ca | Format-Table Id, Severity, Title
Get-PostureRequirement | Format-Table Name, Installed, Tested, Status      # service modules here against the tested versions
```

Nothing leaves the customer's environment: the licence is a signed file verified offline
([docs/licensing.md](docs/licensing.md)), there is no telemetry, and the scheduled deployment runs as a managed
identity in the customer's own subscription ([docs/scheduling.md](docs/scheduling.md),
[docs/footprint.md](docs/footprint.md)). How the parts fit: [docs/architecture.md](docs/architecture.md).

## Develop

```powershell
git config core.hooksPath .githooks            # once per clone: secret scan before commit, analyzer and tests before push
./build.ps1 -Task Analyze, Test
./build.ps1 -Task Package -CertificatePath ./signing.pfx   # release zip; fails without a code-signing cert
```

Conventions for maintainers are in [CLAUDE.md](CLAUDE.md). Issues are welcome; pull requests are not accepted yet
([CONTRIBUTING.md](CONTRIBUTING.md)). Security problems go to [SECURITY.md](SECURITY.md).
