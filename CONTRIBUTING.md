# Contributing

Thank you for reading the code. That is the point of publishing it: anyone can audit what a read-only posture tool
does before running it against their tenant.

## Issues

Bug reports and questions are welcome through GitHub issues. Say which module version, PowerShell version and
operating system you used, what you ran and what you saw. Never paste evidence files, reports or anything else from
a real tenant; describe the shape instead. Security problems go to [SECURITY.md](SECURITY.md), not to a public issue.

## Pull requests

TenantKeep Posture is source-available, not open source ([LICENSE.md](LICENSE.md), PolyForm Shield 1.0.0). The
licence lets you change it for your own use, but there is no contributor agreement yet, so external pull requests
are closed with thanks and the idea goes into an issue. If you have a fix, open an issue describing it; a maintainer will write it, credit you
in the changelog and reference the issue.

## Working on the code

The conventions a maintainer follows are in [CLAUDE.md](CLAUDE.md): read-only against the tenant, delegated or
managed identity only, every API version pinned, checks as data. Locally:

```powershell
git config core.hooksPath .githooks   # once per clone: secret scan before commit, analyzer and tests before push
./build.ps1 -Task Analyze, Test
```

CI runs the same analyzer and test suite on Ubuntu, macOS and Windows.

## Releasing (maintainers)

1. Move the Unreleased entries in CHANGELOG.md under a `## <version>` heading with the date, and set `ModuleVersion`
   and `Prerelease` in the manifest to match.
2. Tag the commit `v<version>` (for a pre-release, `v<version>-<prerelease>`) once CI is green on it, and push the
   tag. The Release workflow checks the tag against the manifest and the changelog, runs the suite, and opens a
   draft release with the changelog section as notes and the catalog page attached.
3. Approve the package job when it waits on the release environment. It signs in to Azure through OpenID Connect,
   writes the integrity manifest with the licence key in Key Vault, packages, attaches the zip and its SHA-256 to
   the draft, and publishes to the PowerShell Gallery when GALLERY_PUBLISH is on. With the repository variable
   RELEASE_SIGNING on, the job runs on Windows and Authenticode-signs every file through Azure Artifact Signing
   first (Microsoft holds the certificate; no certificate or key exists as a file); otherwise it runs on Linux and
   packages unsigned, with the zip named so. The integrity manifest is written either way: it is what makes the
   build read as a release in every report.
4. Publish the draft.

One-time setup, Kainor side: `deploy/release/New-PostureSigningIdentity.ps1 -VaultName <vault> -KeyName <key>`
creates the app registration with a federated credential for this repository's release environment, the Key Vault
role, the GitHub variables and the environment with its required reviewer, and leaves RELEASE_SIGNING off. Once the
Artifact Signing account, its Public Trust certificate profile and identity validation exist (portal only, 1 to 20
business days), run it again with the four signing parameters: it adds the role, the signing variables, and turns
RELEASE_SIGNING on. The emergency path with a local certificate (`build.ps1 -Task Sign`) still exists and is
Windows-only too; a local unsigned package is `build.ps1 -Task Build, Integrity, Package -Unsigned`.
