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
| `remediation` | What to do, in plain English: one string, or an array of steps in order when the fix is more than one action. The report numbers the steps; text outputs (CSV, CA document) join them |
| `userImpact` | What users notice when the fix lands: `level` (`none`, `low`, `medium`, `high`) and `text`, one sentence in the user's terms ("Users who sign in with SMS are asked to set up Authenticator"). Quick fixes (effort S) at none or low are the report's "Do today" list |
| `effort` | Optional: `S` (a setting, under an hour), `M` (a policy rollout with a pilot, days), `L` (a project: new licences, user change, weeks). Orders recommendations within a severity |
| `category` | Optional: `fix` (the default: a gap someone could exploit) or `improve` (hardening beyond the baseline). Improvements read as suggestions, not failures |
| `learn` | Microsoft Learn link |
| `deepLink` | Portal deep link, or null |
| `narrative` | Why it matters: two to four factual sentences |
| `frameworks` | Reference numbers only: `nist-csf-2`, `iso27001`, `cmmc`, `cisa-scuba`. Never framework text. No CIS: the benchmarks are licensed and Kainor is not a SecureSuite vendor |

`catalog.json` holds the catalog version recorded in every run (spec 12.7). `chains.json` holds the control chains
(below). `facts.json` holds a plain label for every fact a pass expression reads and every threshold, shown on the
report's finding cards beside the value ("Administrators without a phishing-resistant method: 2"); a new fact or
threshold needs a label there or the catalog test fails. `layers.json` holds the defence-in-depth sets the report draws as layered rings, each layer a list of catalog checks. None of these is a domain file.

## Control chains

`chains.json` lists controls that protect only together, for example Defender reporting device risk, compliance
acting on it and Conditional Access requiring compliance. Each chain has an `id` (`CH-NNN`), a `name`, `why` (two or
three sentences) and two or more `links`, each a `check` id from the catalog and its `role` in the chain. The report
shows one card per chain: it holds when every link passes (or is accepted or covered), breaks at its first failing
link, and is incomplete while a link could not be judged. A link to a check that is not in the catalog fails the
load, so a chain ships with its checks.
