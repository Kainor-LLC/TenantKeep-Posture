# Tenantkeep Posture

Read-only Microsoft 365 security posture report, with Conditional Access documentation and diff.
PowerShell 7. Mac first; Windows and Linux supported.

**Source published, not open source.** Read every line; you can't fork it. See [LICENSE.md](LICENSE.md).

## Status

Pre-release. Shipped: `Export-PostureCaSnapshot` (spec 5.1) and `New-PostureCaDocument` (spec 5.2, Markdown). Next: HTML output, then `Compare-PostureCaSnapshot` (5.3).

## Use

```powershell
Import-Module ./Tenantkeep.Posture
Connect-MgGraph -Scopes Policy.Read.All, Directory.Read.All, Group.Read.All -NoWelcome
Export-PostureCaSnapshot                       # writes ~/audit/evidence/<yyyyMMdd-HHmm>-ca/
Export-PostureCaSnapshot -IncludeMembers       # also stores group member UPNs
New-PostureCaDocument -Snapshot ~/audit/evidence/<stamp>-ca -NamePattern '^CA-\d{3}-'   # ca-document.md next to the snapshot
```

## Develop

```powershell
git config core.hooksPath .githooks            # once per clone: pre-commit secret scanner
./build.ps1 -Task Analyze, Test
./build.ps1 -Task Package -CertificatePath ./signing.pfx   # release zip; fails without a code-signing cert
```

Conventions for contributors and for Claude are in [CLAUDE.md](CLAUDE.md).
