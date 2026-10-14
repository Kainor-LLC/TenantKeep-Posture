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
