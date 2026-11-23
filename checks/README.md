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
| `attack` | Optional: the MITRE ATT&CK Enterprise technique ids the check helps stop or detect, for example `["T1078.004", "T1110.003"]`. Sub-techniques where one fits. Left off where no technique fits (the user experience domain, housekeeping checks) |
| `references` | Optional: other tools' ids for the same setting, by kind. `secureScore` lists the Microsoft Secure Score control ids the check overlaps, for example `{ "secureScore": ["BlockLegacyAuthentication"] }`; the report then shows, beside each of Microsoft's open actions, the check here that also judges it. Those ids are Microsoft's (the `id` of a control profile in Graph) and must be in `references/secure-score.json`, which a tenant's own list feeds; the catalog test fails on one that is not. `scuba` lists CISA SCuBA policy ids the check covers beyond the one in `frameworks.cisa-scuba`, which stays the policy the check is filed under in the crosswalk. Covering a policy means judging the same setting; the check's own bar can differ from the reference's, and a baseline can raise it |

`catalog.json` holds the catalog version recorded in every run (spec 12.7). `chains.json` holds the control chains
(below). `facts.json` holds a plain label for every fact a pass expression reads and every threshold, shown on the
report's finding cards beside the value ("Administrators without a phishing-resistant method: 2"); a new fact or
threshold needs a label there or the catalog test fails. `layers.json` holds the defence-in-depth sets the report draws as layered rings, each layer a list of catalog checks. `outcomes.json` holds the board-level outcomes (ransomware readiness, identity hygiene, ...), each scored over the checks it names. `attack.json` holds the name, tactics and link of every ATT&CK technique a check names; it is generated, never edited (below). `journeys.json` holds the user journeys the Domains view draws (below). None of these is a domain file.

## Journeys

`journeys.json` lists what a person goes through, step by step, each step a catalog check and a short label. The
report draws each journey as a strip in the Domains view, a step on when its check passes, off when it fails, and not
read yet when it could not be evaluated. A step naming a check the catalog lacks fails the load. Each journey has an
`id` (`JR-NNN`), a `name`, a `domain`, `why` (one sentence) and its `steps`.

## MITRE ATT&CK

## Projects: the remediation plan

`projects.json` groups the checks into projects, the pieces of work an administrator would plan ("Bring devices under
management"), and says what each waits on. `needs` names projects that have to be finished first, because this one
causes harm or cannot work without them; `after` names a recommended order. Each carries its reason in `why`, which
the report shows. Every built-in check belongs to exactly one project: the catalog refuses to load a check in two
projects or in none, so a new check has to be given a project and the plan leaves nothing out. Loops are refused too.

The report turns this into a plan for one tenant (`Get-PosturePlan`): the projects with something to fix, in columns
by the order they can start. A project that waits on one the run could not judge is not held back and is not treated
as ready either; it says which to check first.

## References: what the catalog is measured against

`references/` holds one file per public reference with every item of it, so coverage is a count and not a claim.
`references/cisa-scuba.json` has each policy of CISA's SCuBA baselines for the ScubaGear release in `version` (ids and
statements, public domain). An item is covered when a check names it, in `frameworks.cisa-scuba` or
`references.scuba`. Every other item sits under `notCovered` with a reason and a note: `planned` (a check is still to
be written), `noReadApi` (Microsoft offers no read-only way to see the setting) or `outOfScope` (it does not apply to
the tenants this report is for). The catalog test fails on an item with neither a check nor a reason, on one with
both, and on a check that names an id the reference no longer has, which is how a renumbered policy shows up.

`build.ps1 -Task ScubaData -ScubaBaselines <folder>` rewrites the items from the `PowerShell/ScubaGear/baselines`
folder of a ScubaGear release (github.com/cisagov/ScubaGear). To move releases, change `version` and `source` in the
file, run the task, then run the tests and work through what they name. A mail address inside a statement is written
as words, because the commit guard lets no real mail domain into the repository.

`references/secure-score.json` is the list of Microsoft Secure Score actions by id, with Microsoft's titles.
Microsoft publishes no such list: a tenant's own control profiles are the list, and each tenant has the actions for
its products. `build.ps1 -Task SecureScoreData -SecureScoreControls <def-06-secure-score-controls.json>` adds what a
run's list has (the id and the title only, never a score or a state) and removes nothing. The file is marked
`passThrough`: the report lists every open action from Microsoft's own evaluation whether a check names it or not, so
an action without a check needs no reason. What the test catches here is a check naming an id Microsoft does not
have.

`catalog.json` pins the ATT&CK release under `attack.version`. `build.ps1 -Task AttackData -AttackStix
<enterprise-attack-<version>.json>` reads MITRE's STIX bundle for that release (github.com/mitre-attack/attack-stix-data),
fails on any id a check names that the release lacks, has revoked (naming the replacement) or has deprecated, and
writes `attack.json` with the techniques in use and MITRE's copyright notice and licence, as MITRE's terms of use ask.
The catalog test fails when `attack.json` is not the pinned release or does not list exactly the techniques the checks
name, so a new mapping always goes through the task. MITRE ships in April and October: move the pin, run the task,
fix what it names. Nothing is fetched at run time.

## Control chains

`chains.json` lists controls that protect only together, for example Defender reporting device risk, compliance
acting on it and Conditional Access requiring compliance. Each chain has an `id` (`CH-NNN`), a `name`, `why` (two or
three sentences) and two or more `links`, each a `check` id from the catalog and its `role` in the chain. The report
shows one card per chain: it holds when every link passes (or is accepted or covered), breaks at its first failing
link, and is incomplete while a link could not be judged. A link to a check that is not in the catalog fails the
load, so a chain ships with its checks.
