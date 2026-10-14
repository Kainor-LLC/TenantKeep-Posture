# profile.json

The org profile (spec 10.2): facts about the tenant and its risk appetite that every check reads. Written by
`New-PostureProfile`, hand-editable, one per tenant. Without a profile, every check is evaluated and license gating
is off; the appendix says so.

```json
{
  "version": 1,
  "clientName": "Contoso Ltd",
  "licenses": ["BusinessPremium", "P1", "P2", "Intune", "MDO1", "MDO2", "MDE2", "MDEBusiness"],
  "platforms": ["windows", "macOS", "iOS"],
  "identityModel": "cloud-only",
  "byod": "mam",
  "externalCollaboration": "governed",
  "copilot": "none",
  "azure": "platform",
  "thirdParty": { "email": "none", "edr": "none", "mfa": "none", "mdm": "none", "siem": "none", "backup": "none" },
  "frameworks": ["cisa-scuba"],
  "thresholds": {
    "maxPermanentGlobalAdmins": 2,
    "staleDeviceDays": 90,
    "maxExclusionGroupMembers": 25,
    "inactiveGuestDays": 90,
    "reportOnlyMaxDays": 90,
    "disabledMaxDays": 90,
    "criticalCveMaxAgeDays": 14,
    "namePattern": "^CA\\d{3} - "
  },
  "audience": "technical",
  "cadence": "quarterly",
  "breakGlass": ["breakglass01@contoso.example", "breakglass02@contoso.example"],
  "licensesSource": "graph:2026-10-14",
  "createdUtc": "2026-10-14T04:30:00Z",
  "updatedUtc": "2026-10-14T04:30:00Z"
}
```

| Field | Values | Drives |
|---|---|---|
| `licenses` | E3, E5, BusinessPremium, P1, P2, Intune, IntuneSuite, EntraSuite, MDO1, MDO2, MDE1, MDE2, MDEBusiness, Purview, Copilot, SAM | A check whose `license` list has no overlap is "Not evaluated (requires X)". Detected from service plans, bundles expand to what they contain |
| `platforms` | windows, macOS, linux, iOS, android | `applicableWhen.platforms` on device and endpoint checks; CA-005 requires compliance per desktop platform in scope |
| `identityModel` | cloud-only, hybrid-connect, hybrid-cloud-sync, hybrid-adfs | Whether the hybrid domain renders |
| `byod` | none, mam, mdm | Mobile checks and targets |
| `externalCollaboration` | locked, governed, open | Guest and sharing targets |
| `copilot` | none, pilot, deployed | Whether the readiness domain renders |
| `azure` | none, platform, workloads | Whether the Azure domain renders |
| `thirdParty` | category to vendor name, or none | Checks listing the category in `coveredBy` render "Covered by vendor" |
| `frameworks` | hipaa, pci, cmmc, soc2, iso27001, nist-800-171, cisa-scuba | Crosswalk appendix and severity lifts |
| `thresholds` | numbers, and `namePattern` | Override the catalog default by key; the appendix prints both |
| `breakGlass` | UPNs or display names | Exclusion checks know which accounts belong in exclusions; CA-012 fails when none are named or found |
| `audience`, `cadence` | see above | Template depth; trend window |

Threshold precedence is catalog default, then profile by key, then baseline per check id.
