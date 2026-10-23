# Contributing

Thank you for reading the code. That is the point of publishing it: anyone can audit what a read-only posture tool
does before running it against their tenant.

## Issues

Bug reports and questions are welcome through GitHub issues. Say which module version, PowerShell version and
operating system you used, what you ran and what you saw. Never paste evidence files, reports or anything else from
a real tenant; describe the shape instead. Security problems go to [SECURITY.md](SECURITY.md), not to a public issue.

## Pull requests

Tenantkeep Posture is source-available, not open source ([LICENSE.md](LICENSE.md)). The licence does not allow
derivative works, and there is no contributor agreement yet, so external pull requests are closed with thanks and
the idea goes into an issue. If you have a fix, open an issue describing it; a maintainer will write it, credit you
in the changelog and reference the issue.

## Working on the code

The conventions a maintainer follows are in [CLAUDE.md](CLAUDE.md): read-only against the tenant, delegated or
managed identity only, every API version pinned, checks as data. Locally:

```powershell
git config core.hooksPath .githooks   # once per clone: secret scan before commit, analyzer and tests before push
./build.ps1 -Task Analyze, Test
```

CI runs the same analyzer and test suite on Ubuntu, macOS and Windows.
