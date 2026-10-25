TenantKeep Posture is source-available and does not accept external pull requests yet (see CONTRIBUTING.md). If you
are not a maintainer, please close this and open an issue describing the change instead; it will be credited.

Maintainer checklist:

- [ ] Read-only against the tenant; no new write permission anywhere
- [ ] Every new API call pins its version
- [ ] Analyzer clean and tests green locally (the pre-push hook enforces both)
- [ ] CHANGELOG.md updated
