# profile.json

The org profile (spec 10.2): facts about the tenant and its risk appetite that every check reads. Written by
`New-PostureProfile`, hand-editable, one per tenant. Without a profile, every check is evaluated and license gating
is off; the appendix says so.

## Discovery first, then the questionnaire

Run the collection first, then point the wizard at the evidence folder. Discovery reads what the tenant already
says about itself and the wizard asks only what evidence cannot answer:

```powershell
$folder = Invoke-PostureCollection -OutRoot ~/audit/evidence
New-PostureProfile -Path ./clients/contoso/profile.json -Evidence $folder
```

| Discovered | From | Rule |
|---|---|---|
| `licenses` | 01-subscribed-skus | service plans and SKUs; Copilot implies SAM (verify) |
| `platforms` | 09-intune-managed-devices, 08-entra-devices | a platform with 5 or more devices, or 2% of the fleet (verify the floor) |
| `identityModel` | 01-organization, 01-domains | sync on means hybrid; a federated domain means hybrid-adfs; Cloud Sync reads as hybrid-connect (verify) |
| `byod` | 09-intune-managed-devices, 09-intune-app-protection-policies | 5 or more personal devices means mdm; an assigned app protection policy means mam; else none |
| `externalCollaboration` | 06-users-summary, spo-tenant-settings, teams-federation | no guests and sharing off means locked; guests with expiration, a domain list or a Teams allow list means governed; else open |
| `copilot` | 01-subscribed-skus, 06-users-summary | seats consumed at half the members means deployed; any means pilot |
| `tenantId`, `clientName` | collection, 01-organization | |

Asked: third-party controls, thresholds, break-glass accounts and when they were last tested, the Message Center
owner, frameworks, audience, cadence, and `azure` until the Azure collector exists. Every discovered value is printed with its file and rule, a parameter always wins, and
`-AskAll` asks the discovered questions too with the discovered values as defaults. The written profile carries a
`discovery` block with the evidence folder, the keys discovered and the sources, so a reviewer can see what was
measured and what was answered.

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
  "operations": { "breakGlassTestedUtc": "2026-09-01T00:00:00Z", "messageCenterOwner": "IT operations team" },
  "licensesSource": "evidence:/Users/me/audit/evidence/20261014-1448",
  "discovery": { "evidence": "...", "timestampUtc": "...", "keys": ["licenses", "platforms", "identityModel", "byod", "externalCollaboration", "copilot", "tenantId", "clientName"], "sources": { "platforms": "..." } },
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
