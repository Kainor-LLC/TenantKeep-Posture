# Baselines

A baseline is a check selection, per-check threshold overrides, severity overrides and the framework tags it reports
(spec 10.1, 10.6). Customers and MSPs can author their own; pass a path to `-Baseline`.

```json
{
  "name": "house-standard",
  "description": "Example MSP house standard",
  "checks": ["*"],
  "exclude": ["CA-015"],
  "thresholds": { "CA-007": { "maxExclusionGroupMembers": 10 } },
  "severity": { "CA-010": "High" },
  "frameworks": ["nist-csf-2"]
}
```

## Selection entries

`checks` takes `"*"`, a check id, `"domain:<slug>"` (every check in that domain) or `"framework:<key>"` (every check
that carries a reference for that framework, so the selection grows with the catalog). The keys are the ones in each
check's `frameworks` block: `nist-csf-2`, `iso27001`, `cmmc`, `cisa-scuba`.

## Crosswalk

A baseline may carry a `crosswalk` block that the report renders as an appendix: `framework` names the reference key,
`groups` maps reference prefixes to headings (`"PR": "Protect"`), and `controls` maps the customer's own control names
to lists of references (the HIPAA baseline maps Security Rule safeguards to CSF subcategories). The appendix lists,
per group or control, the checks that map there with their statuses. Framework text is never reproduced; references only.

## Shipped

standard, copilot-readiness, nist-csf-2, iso-27001-2022, nist-800-171, cmmc-2, cisa-scuba (first pass, 35 checks
mapped), hipaa (through the HHS crosswalk, verify). CIS benchmarks are not mapped: their content is licensed through
the CIS SecureSuite vendor programme, which Kainor has not joined (decided 2026-10-15).

