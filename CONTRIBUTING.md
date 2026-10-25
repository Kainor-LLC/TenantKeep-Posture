# Contributing

Thank you for reading the code. That is the point of publishing it: anyone can audit what a read-only posture tool
does before running it against their tenant.

## Issues

Bug reports and questions are welcome through GitHub issues. Say which module version, PowerShell version and
operating system you used, what you ran and what you saw. Never paste evidence files, reports or anything else from
a real tenant; describe the shape instead. Security problems go to [SECURITY.md](SECURITY.md), not to a public issue.

## Pull requests

Tenantkeep Posture is source-available, not open source ([LICENSE.md](LICENSE.md), PolyForm Shield 1.0.0). The
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
2. Run `./build.ps1 -Task Analyze, Test, Build, Sign, Integrity, Package` with the signing certificate and the
   licence key available; that produces the signed zip and its SHA-256 under `out/`.
3. Tag the commit `v<version>` (for a pre-release, `v<version>-<prerelease>`) and push the tag. The Release workflow
   checks the tag against the manifest and the changelog, runs the suite, and opens a draft release with the
   changelog section as notes and the unsigned build and catalog page attached.
4. Attach the signed zip and its `.sha256` to the draft, then publish it. The Gallery publish is a separate step
   with the same signed build.
