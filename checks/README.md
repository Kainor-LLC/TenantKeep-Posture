# Check catalog

One JSON file per domain: `{ "domain": "ca", "checks": [ ... ] }`. Checks are data; the engine (`Invoke-PostureChecks`)
evaluates them. A new check never needs a renderer change.

Every check carries, and the catalog test enforces:

| Field | Meaning |
|---|---|
| `id` | `XX-NNN`, unique across the catalog, for example `CA-003` |
| `domain` | Domain slug; the fact provider is `Get-Posture<Domain>Fact` |
| `title` | Short, as it appears in the scorecard |
| `severityDefault` | Critical, High, Medium, Low; a baseline may override |
| `license` | Tokens the tenant must have (any of): P1, P2, Intune, MDO2, MDE2, E5 ... Empty means no gate |
| `applicableWhen` | Profile keys with allowed values, for example `{ "platforms": ["macOS"] }`. Empty means always |
| `coveredBy` | Third-party categories that make the check "covered by vendor": `mfa:*`, `edr:*`, `mdm:jamf` |
| `thresholds` | Defaults the pass expression and the fact provider read; profile and baseline can override |
| `evidence` | Evidence files the facts come from |
| `pass` | Expression over `facts.*` and `thresholds.*`: comparisons, `&&`, `\|\|`, `!`, parentheses |
| `affected` | Optional: the fact that lists the affected objects, for example `facts.exclusionGroupsOverThreshold` |
| `gate` | Optional, Copilot readiness only: `{ "code": "C1", "hard": true }`. Hard gates must all pass before the readiness page shows anything but Blocked (spec 4.7) |
| `remediation` | What to do, in plain English |
| `learn` | Microsoft Learn link |
| `deepLink` | Portal deep link, or null |
| `narrative` | Why it matters: two to four factual sentences |
| `frameworks` | Reference numbers only: `cis-m365`, `nist-csf-2`, `iso27001`, `cmmc`, `cisa-scuba`. Never framework text |

`catalog.json` holds the catalog version recorded in every run (spec 12.7).
