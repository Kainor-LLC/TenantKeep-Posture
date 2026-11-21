# Changelog

One entry per release. Pre-release work is summarised under Unreleased until the first tag; after that, every
entry names the version, the date and what changed for the person running the module. Dates are the day the
work landed on main.

## Unreleased

- Six checks checked against Microsoft Learn (2026-11-21), their "(verify)" tags gone from what customers read:
  SharePoint Advanced Management comes with Copilot licences (CP-002); app centric management replaces Teams app
  permission policies on tenants Microsoft has moved since April 2025 (CL-014); the Intune label is Windows Backup and
  Restore, Show restore page (UX-004); users can move their source of authority to Entra like groups, with the sync
  client versions that allow it (HY-033); Copilot settings have only a beta read API so far (CP-015). CP-013 now
  recognises the Copilot DLP location by its location id or the CopilotExperiences enforcement plane, which the
  Purview collector now keeps, instead of any policy on the Applications workload.
- AZ-026, AZ-027 and AZ-028 no longer pass on nothing (2026-11-21): a subscription without backup vaults, a Sentinel
  workspace or Entra Domain Services now reads as not evaluated with the reason, as AZ-021 does for SQL. Found on the
  first live Azure run.
- `Start-PostureRun -Name` works (2026-11-21): a loop over the SharePoint and Teams sign-ins reused `$name`, which
  PowerShell treats as the same variable as `-Name`, so every run folder was called "Teams" (then "Teams-2"). A test
  now fails on any function that loops over a variable named like one of its own parameters.
- Sessions pinned to the run's tenant (2026-11-21): `Invoke-PostureCollection` uses an Exchange, Purview or Azure
  session only when it is in the Graph session's tenant, so a context saved from another tenant (Az keeps one between
  sessions) is skipped with the command to fix it instead of being read into the wrong run. The module's own Azure
  sign-in now stays in the process (`Connect-AzAccount -Scope Process`): it no longer saves its token in the Az
  context file or replaces the admin's default context.
- A sample report from a made-up tenant (2026-11-21): `samples/demo/New-PostureDemoRun.ps1` writes a complete run for
  Fernquill Engineering, an invented 400-person cloud-only E5 organisation (reserved example domains, a seeded
  generator, the anonymized Conditional Access sample), with its client profile and one accepted risk.
  `build.ps1 -Task Demo` renders its report and the website's screenshots with headless Edge or Chrome; public
  screenshots come from here and nowhere else. A new test runs every fact provider over it, so a provider that stops
  on a missing field fails the build.
- The security review no longer says releases are Authenticode-signed (2026-11-21): they carry the signed integrity
  manifest, and Authenticode follows once the signing account is validated; until then the zip is named unsigned.
- Flow charts size their label columns from the longest label (2026-11-21): a label such as "Passkey, key or Windows
  Hello 348" was cut off at the right edge.
- Weekly upkeep (2026-11-20): `build.ps1 -Task Upkeep` reports what has gone stale in the shipped data (Microsoft's
  licensing list against bundles.json, a newer ATT&CK release or a withdrawn mapped technique, newer versions of the
  modules the collectors were tested with, catalog Learn links that no longer answer, licensing files past their review
  date), and `.github/workflows/upkeep.yml` files it as one issue every Monday, closing it when nothing is stale. It
  runs on GitHub only; the module never calls out. The first run found seven moved Learn pages (AZ-020, CL-007, CL-011,
  CP-018, EM-011, EM-015, HY-004, OP-006, OP-007), now pointing at their current pages; EM-011 now links Enhanced
  Filtering for Connectors, the page it was always about.
- Tiers enforced across the whole report (2026-11-20): without the full tier, the charts, headline figures,
  administrators table, Copilot and licensing pages and the non-CA inventory no longer render from the evidence; only
  the Conditional Access domain is shown, as docs/licensing.md says. Before, the checks were limited but the
  evidence-driven views were not.
- More of the report drawn (2026-11-20): the Domains view gains User Experience (three journeys, a new laptop,
  signing in, and mail, each step backed by its check, from the new checks/journeys.json), Network Access (the Global
  Secure Access traffic profiles) and Hybrid (privileged group sizes, key ages and the AD weaknesses attackers look
  for first).
- Azure and Secure Score (2026-11-20): AZ-024 no SSH, RDP or WinRM open to the internet, AZ-025 a budget on every
  subscription, AZ-026 backup vaults with soft delete and immutability, AZ-027 Sentinel receiving Entra, Microsoft 365
  and Defender XDR, AZ-028 Entra Domain Services without NTLMv1, TLS 1.0 or RC4. The Operations view gains Secure Score
  by Category and the top ten improvement actions with Microsoft's links; a new Azure area shows the Defender for Cloud
  secure score per subscription, open recommendations by severity and the top recommendations.
- Fourteen more user experience checks (2026-11-20), each an improvement that leads with what people gain:
  phone sign-in with Authenticator (UX-011), the strongest method offered first (UX-012), the Authenticator
  registration campaign (UX-013), Windows sign-in without a password option (UX-014), password reset from the Windows
  sign-in screen with writeback for synced users (UX-015), the Enterprise SSO plug-in on Apple devices (UX-016), a
  day's grace before update restarts (UX-017), Face ID or a fingerprint for work apps on phones (UX-018), group-based
  licensing (UX-019), profiles with job title and department (UX-020), Outlook's External tag instead of subject tags
  (UX-021), MailTips for outside and large audiences (UX-022), a one-click Report button (UX-023) and auto-expanding
  archives (UX-024). The mail ones a third-party gateway provides are covered by the email vendor.
- A third-party email gateway (2026-11-20): EM-026 mail arrives only through the gateway (with MX pointing elsewhere or
  an email vendor in the profile, a partner connector must accept mail only from the gateway, or attackers deliver
  straight to Exchange Online); EM-027 Safe Attachments and Safe Links for SharePoint, OneDrive, Teams and Office apps,
  judged apart from mail since a mail gateway does not reach files. A new profile vendor, thirdParty.training
  (KnowBe4, Proofpoint Security Awareness), covers the attack simulation check.
- Command-line access (2026-11-20): ID-023 Microsoft's admin command-line tools (Graph PowerShell, Graph Explorer,
  Azure CLI and PowerShell, the Exchange, SharePoint and Teams shells) open only to an assigned group or blocked by
  Conditional Access for everyone else; CA-016 device code sign-in blocked; EM-025 Exchange Online PowerShell only for
  administrators, read by the Exchange collector. Each says plainly that hiding the Entra admin center stops neither
  PowerShell nor Graph.
- Users and groups managed in AD or in Entra (2026-11-20): HY-032 flags groups synced from AD that a live Conditional
  Access policy uses (exclusions above all) or that assign licences, since whoever can edit them in AD decides cloud
  access; HY-033 (improvement) measures how many groups from AD have had their source of authority switched to Entra,
  with the features and user experience that brings. The Entra collector records where each user and group is
  managed, read-only; the Identity view gains Who Manages Users and Groups.
- Macs on Jamf or another Mac MDM (2026-11-20): the Intune collector reads the partners connected to Intune (Partner
  compliance management and the older device management partners). DEV-022 asks that the Mac MDM report compliance to
  Intune, live and recent; DEV-023 that its Macs show as compliant in Entra. A new profile vendor, thirdParty.macMdm,
  covers only the macOS checks (FileVault, macOS hardening, Platform SSO) and is discovered from a connected partner.
  The profile wizard names each vendor category in plain words. The Devices view gains Macs on a Partner MDM, and the
  Inventory lists the partners.
- Who manages the Windows fleet (2026-11-20): DEV-019 no Windows devices on Configuration Manager alone, DEV-020
  hybrid-joined Windows devices in use managed by Intune and not by Group Policy alone (5% allowed by default),
  DEV-021 co-management workloads moved to Intune. Each says what people notice and how to move. The Intune collector
  reads which workloads Intune holds on co-managed devices; the Devices view gains Windows Devices by Who Manages Them
  and Co-management Workloads. With the AD collector's files, DEV-020 also counts workstations in AD that Entra does not
  know at all (matched by name; servers and domain controllers left out).
- Logs to send for support (2026-11-20): each failed step now records the request it was making, where in the module
  it stopped, and the module, PowerShell and OS versions. Run Health has a Copy for Support button per failure and
  for all of them, with names, addresses and ids taken out. Export-PostureDiagnostics zips a run's logs, redacted the
  same way and without any evidence, into the run's share/ folder.
- For a cautious security team (2026-11-20): every request a run sends is counted in logs/calls.json and shown in
  Run Health under What This Run Did, with a verdict that every call was a read. deploy/verify/Test-PostureReadOnly.ps1
  checks the tenant's own audit logs (unified audit log, Entra directory audits and sign-ins) for anything the run
  account changed during the run, without loading the module. docs/security-review.md answers the usual questions:
  what is read and as whom, where results go, how read-only is enforced, how to check a run, and how to set up the
  account that runs it.
- SharePoint without full control by default (2026-11-20): the main app no longer asks for SharePoint
  AllSites.FullControl. The SharePoint checks read Graph's SharePoint settings (read-only) and say exactly which
  settings need the SharePoint admin read. That read now has its own app, TenantKeep Posture for SharePoint, never
  consented for the organisation: deploy/setup/Grant-PostureSharePointAccess.ps1 grants it to named admins, requires
  assignment and turns it off between runs. Start-PostureRun checks through Graph that the app is granted to the admin
  before opening a second sign-in (Connect-PostureSession -SharePoint by hand). Tenants that consented to the main app
  before keep that old SharePoint grant until an admin removes it.
- Split collection (2026-11-20): collectors/windows/Get-SpoBaseline.ps1 does the SharePoint admin read on Microsoft's
  own SharePoint Online Management Shell, with no third-party app, on Windows (a cloud PC works). Import-PostureEvidence
  brings its folder, the AD collector's folder or another machine's SharePoint-only run into a run: every file checked
  against the collector's bundle.json, the tenant checked, only evidence files copied, and the import listed in Run
  Health. Both Windows collectors now write bundle.json.
- HY-026 agrees with HY-031 (2026-11-20): people exempt from password expiry fail only while the domain still
  expires passwords; once Maximum password age is 0 (the NIST stance HY-031 asks for) the check passes. Before, a
  domain that followed HY-031 kept failing HY-026.
- MITRE ATT&CK (2026-11-20): 177 checks name the ATT&CK Enterprise techniques they help stop or detect (82
  techniques, release 20.1, pinned in checks/catalog.json). A new ATT&CK Coverage view shows, under each tactic, which
  techniques have a failing check, an accepted risk, passing checks or no evaluated check; cards carry the technique
  ids, and findings.csv (an ATT&CK column), findings.json and report.md list them. `build.ps1 -Task AttackData` checks
  every id against MITRE's release and fails on revoked or deprecated ones. Links inside a view (a quick win's chip, a
  tactic) now open the view that holds them instead of a blank page.
- Microsoft 365 pay-as-you-go and Backup (2026-11-20): with the Azure collector, the subscriptions that pay for
  Microsoft 365 pay-as-you-go services over the last 30 days and their budgets (AZ-023 asks for a budget alert), and
  Microsoft 365 Backup's status and protection policies (OP-008: on and protecting SharePoint, OneDrive and Exchange,
  covered by another backup product named in the profile). Cost Management's query is a read sent as a POST; one
  function makes it and refuses any other path. New permission BackupRestore-Configuration.Read.All (rerun the app
  setup and consent).
- Network access domain (2026-11-20): Global Secure Access checks: NET-001 Microsoft traffic forwarded, NET-002
  internet traffic filtered, NET-003 private apps through Private Access, NET-004 Conditional Access sees the original
  source address. Licensed by Internet Access, Private Access or Entra Suite; covered by another secure web gateway or
  ZTNA product named in the profile. Read only where the tenant holds one of those licences, with the new
  NetworkAccess.Read.All permission: rerun deploy/setup/New-PostureClientApp.ps1 and consent again to add it.
- Group Policy analytics (2026-11-20): the Intune collector reads the GPOs imported into Group Policy analytics
  (counts and percentages only); DEV-018 asks hybrid tenants to analyse Group Policy for the move to Intune, and
  the Inventory lists each GPO with the share of its settings MDM supports.
- Gap checks (2026-11-20): EM-022 a mailbox sending spam is stopped, EM-023 the common attachment filter on in every
  anti-malware policy, EM-024 partner connectors restricted to the partner, CL-016 OneDrive without Anyone links,
  DEV-016 personal phones and Macs enrol only when the BYOD stance allows it, DEV-017 devices with no compliance
  policy count as noncompliant (the Intune collector reads the tenant compliance settings). The email facts no
  longer fail as a whole on a connector row without the Enhanced Filtering properties.
- Passwords to NIST and guest settings (2026-11-20): ID-017 cloud passwords do not expire on a schedule, ID-018 a
  custom banned password list in use, ID-019 Password Protection enforced on-premises (hybrid), ID-020 guests cannot
  invite guests, ID-021 guest access limited, ID-022 outbound guest access to other tenants reviewed, HY-031 domain
  passwords do not expire on a schedule. The Entra collector reads the directory settings, keeping the banned
  password list as a count only.
- User experience domain (2026-11-20): ten improvement checks on how smoothly people work, each with what users
  notice: OneDrive signs people in and moves their folders silently, Edge sign-in not turned off, the Enrollment
  Status Page shows progress, Windows settings backup and restore, Autopilot device naming, a branded sign-in page,
  sign-in frequency no shorter than a day for everyone (admin roles and risk policies excepted), self-service
  password reset for members, sign-in name matching email, and display names written First Last. A User Experience
  outcome joins the overview. The Entra collector reads company branding, each user's mail and name parts and each
  domain's password expiry; the Intune collector reads Autopilot profiles, the Enrollment Status Page and restore
  state. The domain list now lives in checks/catalog.json.
- What To Add recomputes in the page (2026-11-20): tick goals or say another product covers a category (EDR, email,
  web gateway, private access, device management) and the options redraw; nothing is saved. The page runs the same
  search as the module (templates/licensing.js, kept equal by a test that runs it under node). Add-ons sold only on
  a base licence (the business suites on Business Premium, the Purview Suite on E3) are offered only with it.
- Licensing options side by side (2026-11-20): for the chosen goals, What To Add now lists options: the fewest add-ons,
  the add-ons that bring nothing another vendor already covers, and suite upgrades with the add-ons they still need
  (for example Microsoft 365 E5 with ID Governance). Each says what it adds, what is already covered by the
  customer's other products (from the profile's third-party controls) and what else it includes (Power BI Pro,
  Teams Phone). A feature a vendor covers counts as covered for the goals. Still no prices.
- Licensing data, wider (2026-11-20): Power BI Pro, Teams Phone, Audio Conferencing and Windows Enterprise are known as
  value a bundle brings (never a goal); the suites carry their current names (Microsoft Purview Suite, was E5
  Compliance; Microsoft Defender Suite, was E5 Security); the Purview Suite for Business and the Defender and Purview
  Suites for Business join the advisor (SKU ids verify). The profile's third-party controls gain swg and ztna.
- Fixes (2026-11-20): OP-005 compared Secure Score points with Microsoft's averages, which are percentages, so it
  passed almost always; it now compares the tenant's percentage (verify the units against Graph). The sign-in read
  compared timestamps as culture text, which keyed days month first and could misorder a restart across a year end;
  it now uses ISO 8601.
- Outcomes and exposure (2026-11-20): the overview shows five outcomes (ransomware readiness, identity hygiene, data
  exposure, email defence, Copilot readiness), each a score over the checks checks/outcomes.json names, with a
  sparkline across earlier runs and the failing checks. The Domains view adds Defender incidents per week (a new
  90-day weekly tally, counts only, def-05-incidents-weekly.json), sensitivity against exposure (sites by label and
  sharing level) and the most exposed sites from an imported SharePoint Advanced Management report; -Redact replaces
  those site names.
- More charts (2026-11-20): the Domains view adds privileged roles (permanent, activated, eligible), guests by last
  sign-in, risky users, sign-ins by day, country and error (in words), Windows builds, disk encryption, last
  check-in, attack surface reduction rules by mode, critical vulnerabilities, an email authentication grid per domain
  (DKIM, SPF, DMARC, MTA-STS), sites by sharing level, DLP policies by mode and Secure Score against Microsoft's
  averages. The Crosswalk opens with coverage per framework group. The Inventory's mail table gains MTA-STS.
- The story of a run (2026-11-20): the overview opens with the score as a ring (change since the last run, the
  target, and where the top five fixes would take it), the score over time across earlier runs of the tenant, open
  findings by severity, the attack path from phishable members to phishable administrators, and accepted risks by
  expiry. Recommendations adds Quick Wins (open findings by effort against what users will notice) and a Roadmap
  in 30, 60 and 90 day lanes.
- Goals in the profile (2026-11-20): `New-PostureProfile -Goal` (tab-completed from licensing/goals.json) and a question
  in the questionnaire; the licensing advisor works from them, else from the core goals.
- Licensing view and advisor (2026-11-20): the Licensing view opens with What To Add: for the profile's goals, or
  the core goals, whether the licences held cover them, else the fewest add-ons and the one bundle that would, for
  the licensed seat count, with no prices. Then seats assigned per SKU, every feature owned, partly assigned (bought
  but switched on for fewer users than hold a licence, from the new 06-users-license-plans.json) or not owned, the
  goals with what each still needs, and the checks waiting on a licence. report.md and findings.json carry it.
- Licensing data (2026-11-20): licensing/features.json maps every licensed feature to the service plans that grant it,
  from Microsoft's service plan list; bundles.json (built by `build.ps1 -Task LicensingData`) lists what each SKU
  carries; goals.json the goals the advisor works from. Licence detection reads them, which fixes plan names that
  did not exist: Defender for Endpoint Plan 1 inside E3 and Business Premium, Copilot, ID Governance. Suspended and
  deleted subscriptions no longer count. GV-005 (lifecycle workflows) needs ID Governance, from Entra Suite or alone.
- Defence in depth (2026-11-20): checks/layers.json stacks catalog checks into layers; the overview draws email
  protection, Conditional Access coverage and Copilot data readiness as layered rings, each layer holds, partly or
  missing with n of m checks beside it.
- Charts (2026-11-20): the overview opens with header tiles (members, groups, apps, devices, managed, sign-ins), a
  passed-of-evaluated bar per domain that opens its checks, and charts: how members sign in (a flow from members to
  phishing-resistant, phishable or no MFA, to method), sign-ins through Conditional Access to MFA, device
  compliance, administrators by sign-in strength, check results. The Domains view adds sign-ins by device trust,
  managed devices by platform, join type and compliance, ownership and Defender Antivirus mode. Each chart has a
  one-line takeaway, a table and a link into its checks. Administrators count as phishing-resistant on the same
  device-bound methods AU-008 asks for; a synced passkey is shown on its own.
- Sign-in flows (2026-11-20): the sign-in read also tallies successful sign-ins by Conditional Access applied and MFA
  (CaByMfa) and by device trust, managed and compliant, managed only or unmanaged (DeviceTrust, from deviceDetail),
  in 06-signins-summary.json. No new permission.
- User impact (2026-11-20): every check says what users notice when the fix lands (none, low, medium or high, and a
  sentence). Cards, the drawer, report.md and findings.json show it; Recommendations opens with Do today, up to ten
  quick fixes users will barely notice. The unused `impact` field is retired in its favour.
- Plain labels on the finding cards (2026-11-20): every value a check judged reads in words ("Sharing level below
  Anyone: no"), from checks/facts.json, in report.html, report.md and findings.json (found: label and value).
- Catalog filled (2026-11-20): every check has an effort (115 quick fixes, 73 planned changes, 19 projects) and a
  category (41 improvements); 84 have their fix as numbered steps, in the order to do them.
- Inventory view (2026-11-20): what the tenant has, as tables from evidence already collected: mail domains with
  DKIM, SPF, DMARC and MX; transport rules; mail connectors; devices by platform and compliance; compliance
  policies, configuration profiles and endpoint security policies with assignment counts; privileged roles held
  permanently, activated or eligible; Conditional Access policies by state. Each table names its evidence files;
  report.md carries the first 50 rows of each. Recommendations moves next to the overview in the navigation.
- Control chains (2026-11-20): checks/chains.json names controls that only protect together; the Recommendations
  view opens with one card per chain, the first failing link marked as the one to fix. Three chains: a device under
  attack loses access, a risky sign-in is challenged, Copilot cannot surface what was overshared. New check DEV-015:
  compliance policies require a Defender device risk level; the Intune collector now reads that setting.
- Recommendations as finding cards (2026-11-20): one card per failed check with what was found in this tenant (the
  values the check judged, beside its thresholds), why it matters, the affected objects, numbered steps, portal and
  Learn links and frameworks; quick fixes first within a priority; improvements marked as such; what already
  passes listed per domain. checks.json records each check's observed values; findings.json and report.md carry
  steps, effort, category and the values, in the same order.
- Catalog fields (2026-11-20): a check's remediation can be a list of steps; optional `effort` (S, M, L)
  and `category` (fix, improve). `Get-PostureCheckCatalog` shows effort and category, and with `-Full` the steps.
- Output for tools and AI (2026-11-20): findings.json beside the report, a summary then every failing check ranked
  with why, how to fix, links, licence and affected samples, explained in its own "about" field; report.md opens with
  the ranked list; report.html embeds the same JSON. `-Redact` writes share/ copies with people, addresses and
  affected names replaced by placeholders, the key in logs/redaction-key.csv.
- Run folders (2026-11-20): `Start-PostureRun -Name "<name>"` names the run (default: date and time). report.html,
  report.md, findings.csv and README.txt sit at the top; evidence/, affected/, errors/ and logs/ hold the rest.
  Runs are found by their run.json, so any name works; older one-folder runs keep working everywhere.
- Report (2026-11-20): the overview's recommendations are a card per priority with one finding per line; a
  Licensing view lists every licence the tenant holds with purchased, assigned and free seats; the Crosswalk link
  explains how to get one instead of falling back to the overview; the appendix says who ran the assessment, with
  their directory roles and the role check per domain (recorded in run.json).
- Simpler resume (2026-11-20): `Resume-PostureRun` with no arguments resumes the newest run, `-Client <name>` the
  newest of one client; the domains to collect again come from the run's own plan. A cmdlet the account's roles or
  the tenant's licences do not expose is a new cause, unavailable, which a resume leaves alone.
- Fixes from the first Kainor run: a failed collector no longer stops the others; the sign-in log reads Graph beta
  (authenticationRequirement is beta-only); a query Graph rejects outright is not retried.
- Exchange signs in like Purview (2026-11-20): through the Exchange module's own Microsoft app, so the TenantKeep
  Posture app no longer asks for Exchange.Manage ("Manage Exchange configuration" on the consent screen). One
  sign-in in the Exchange module covers Exchange and Purview, at the start of the run, and the module renews its own
  tokens on long runs. Rerun deploy/setup/New-PostureClientApp.ps1 to take the permission off the registration;
  existing consents keep it until the enterprise application's permission is removed or consent is given again.
- Graph read of the SharePoint tenant settings (2026-11-20), written beside the PnP one as
  spo-tenant-settings-graph.json to see whether Global Reader is enough. Adds the delegated scope
  SharePointTenantSettings.Read.All to the TenantKeep Posture app: tenants consent again to pick it up, and until
  then that one step reports the missing permission and the run goes on (tokens are requested as .default, so the
  sign-in is unaffected).
- Long runs: Exchange, SharePoint, Teams and Azure renew their token before a call when it is near expiry; the
  Exchange and Purview process gets fresh tokens from the main process over a current-user-only pipe and never
  holds the refresh token. Per-user MFA samples 1,000 members on tenants over 5,000 and reads everyone only when
  one has it (`-FullPerUserMfa` reads all). The sign-in read also tallies report-only policy impact, admin
  sign-ins and single-factor use, failures by error code and password-spray addresses.
- Scale (2026-11-20), for tenants with hundreds of thousands of users, groups and devices and millions of
  sign-ins: every Graph read retries throttling and transient failures (honouring Retry-After) and renews an expired
  token mid-read; users, registration, groups, Entra devices and Intune devices stream to disk in one pass with
  their summaries tallied on the way; evidence is parsed once per evaluation and shared by every domain; the
  report page carries at most 500 affected objects per check, with affected/<id>.csv holding all of them.
- `SignIns` collector and check ID-016 (2026-11-20): the Entra sign-in log for `-SignInDays` (default 7, up to
  30), streamed and tallied, checkpointed every ten pages, self-resuming after a failure and resumable with
  Resume-PostureRun. Needs Entra ID P1 and Reports Reader or Global Reader.
- Clear errors and Resume-PostureRun (2026-11-20): requirements.json names the least-privilege role, delegated
  permission and licence for every collector and the steps that differ; a failed step is classified from its error
  text and written to errors.jsonl with what it needs. Start-PostureRun checks the account's roles before collecting
  and ends with the failures grouped by cause; the report has a banner and a Run Health view with what to grant.
  `Resume-PostureRun -Path <run>` collects again, into the same folder, only the domains that did not finish or failed
  for a reason a retry fixes, and rebuilds the report. Each run writes run.json (tenant, client, planned and skipped
  collectors). Start-PostureRun takes `-Folder` to collect into an existing run.
- `Import-PostureSharingReport` and check CL-015 (2026-11-20): the SharePoint Advanced Management site permissions
  report (downloaded from the admin center; no API reads it) gives Anyone links, organization-wide links and
  Everyone grants per site. The cmdlet validates and files it, summarises it into the newest run
  (spo-dag-site-permissions.json) and rebuilds the report; every run summarises the newest files again.
- Run folders where you want them (2026-11-20): `outputRoot` in profile.json (`New-PostureProfile -OutputRoot`, or
  the wizard's new last question) is where Start-PostureRun puts a client's runs; `-OutRoot` still wins for one run.
- A pleasanter run (2026-11-20): a progress bar with the domain and step, time so far and an estimate of the time
  left (each run records its per-collector times in collection.json for the next estimate); the machine is kept from
  idle sleep until the run ends (`-AllowSleep` to opt out); Exchange and Purview start first in their second
  process, Purview signing in first, so the one extra prompt comes in the first minute and the two processes collect
  at the same time.
- Fixed: when Exchange and Purview wrote collection.json after the main process, the Graph API versions and scopes
  the main process recorded were overwritten. The manifest is now merged under a lock file in the run folder.
- Fixed: New-PostureProfile, which Start-PostureRun calls on every run, dropped every profile key it does not own,
  so review dates under `attestations` were lost on the next run. It now keeps them.
- Risk register retired (2026-11-20): the report no longer has the Risk Register or Settings views, the exception
  form or the save bar, and writes no files. `Export-PostureFindings` drops `-Merge` and writes findings.csv fresh
  each run (ID, Domain, Finding, Severity, Priority, Status, Affected, Remediation, Portal, Learn, Evidence, Checked,
  Licence). Accepted risks stay in exceptions.json; the runbook no longer writes findings.csv back to the `client`
  container.
- `Add-PostureException`, `Get-PostureException`, `Remove-PostureException` and `Set-PostureAttestation` (2026-11-20):
  accept a risk, list and withdraw accepted risks, and record a portal review date in the client folder, found from
  the tenant id. Each change rebuilds the newest report from its evidence, so a page refresh shows it. The report's
  check panel copies the matching command.
- Relayed alerts to TenantKeep On-Call retired (2026-11-15): `ca-relay.ps1`, `New-PostureRelaySender.ps1` and the
  `-RelayPairingCode` and `-RelaySenderKey` parameters are gone, and the runbook no longer reads `RELAY_SENDER_KEY` or
  `RELAY_PAIRING_CODES`. Phone alerts are TenantKeep On-Call's Instant alerts. Nothing leaves a customer's tenant now.

- Relayed alerts: a busy relay or Apple (503), the relay's rate limit (429) or no answer within 15 seconds is tried
  again, at most twice, honouring Retry-After up to 30 seconds; every other answer is final. The run's relay and
  entitlement calls share one connection and time out after 15 seconds, so a relay that never answers cannot stall
  the cycle. A failure still names the relay's error code only. The same rule as the On-Call repository's sender.

## 0.3.0-alpha (2026-10-27)

- Free 30-day trial: Start-PostureRun prints the trial link with the tenant id when the tenant has no Full
  licence, and the report says "Trial licence, ends <date>" under a trial. The module still sends nothing anywhere.
- CP-009 (Restricted SharePoint Search) no longer fails on a tenant that never set the mode: PnP.PowerShell 3.2
  reports it as "Restricted search mode is currently not set.", which is off. Evidence with no mode now reads as not
  evaluated.
- Azure Automation: the runtime environment is PowerShell 7.6 (`tenantkeep-ps76`), and deploy.ps1 imports the
  collector modules at the versions the module is tested with. It now waits for every module import to finish,
  sends one that Automation fails on its side again (twice at most), and says when a job can start; it stops with an
  error if an import still has not finished after `-ImportWaitMinutes` (20 by default).

## 0.2.0-alpha (2026-10-27)

The first build Authenticode-signed by Kainor LLC on the PowerShell Gallery, through Azure Artifact Signing.

- `Initialize-PostureClient`: creates the client folder where you want it, verifies and copies the licence in, seeds
  the profile, and prints the Start-PostureRun line.
- Every release is signed and carries the integrity manifest. The release workflow drafts on the tag, then after a
  maintainer's approval signs every file on a Windows runner, verifies the signatures, writes the manifest, attaches
  the package to the GitHub release and publishes to the Gallery. No certificate or key exists as a file anywhere.
- The SHA-256 file next to each package reads correctly with `shasum -c` and `sha256sum -c` on every platform.

## 0.1.0-alpha (2026-10-25; on the PowerShell Gallery 2026-10-26, that copy unsigned; the GitHub release package Authenticode-signed by Kainor LLC through Azure Artifact Signing 2026-10-27)

First tagged pre-release, from a public repository under PolyForm Shield 1.0.0. Everything built 2026-10-13 to
2026-10-25. Not yet on the PowerShell Gallery; install from the release zip or a clone.

- Conditional Access: `Export-PostureCaSnapshot` (raw wire JSON, name resolution, group scope hashes),
  `New-PostureCaDocument` (Markdown, self-contained HTML, PDF, coverage findings) and `Compare-PostureCaSnapshot`
  (field-level diff, scope drift, risk-relevant change rules, non-zero exit for pipelines).
- Check engine: `Invoke-PostureChecks` and `Get-PostureCheckCatalog` over a data-only catalog of thirteen domains
  (identity, authentication, Conditional Access, devices, endpoint, email, Purview, collaboration, Copilot readiness,
  governance, operations, Azure, hybrid), with baselines for NIST CSF 2, NIST 800-171, CMMC 2, CISA SCuBA,
  ISO 27001:2022, HIPAA and Copilot readiness, profiles and exceptions.
- Collectors: Entra, Intune, Defender (advanced hunting), Exchange Online, SharePoint, Teams, Purview and Azure
  through `Invoke-PostureCollection`, plus the Windows-only Active Directory script for a jump box.
- Report: `New-PostureReport` (weighted score, domain scorecards, interactive single-file HTML with a risk register,
  exception form and settings view, trend against a previous run, PDF), `Export-PostureFindings` for the register,
  `New-PostureProfile` for tenant discovery and the questions evidence cannot answer.
- One sign-in: `Connect-PostureSession`, `Disconnect-PostureSession` and `Start-PostureRun`, which runs every
  collector from one delegated sign-in through the Kainor-published multi-tenant app and opens the report.
  Purview signs in on its own because Security and Compliance PowerShell issues no token to a third-party app.
- Requirements: `Get-PostureRequirement` shows each service module installed against the version the collectors
  were tested with; `Start-PostureRun` warns on an older one, and collection.json records the module versions,
  PowerShell version and operating system of every run.
- Licence: PolyForm Shield 1.0.0 (use, change and redistribute for anything except a competing product) replaces the
  placeholder text, with Kainor's Required Notice and Licensor Line of Business lines.
- Licensing: offline, signed licence files verified against public keys in the module; the Conditional Access domain
  is free, the rest needs the Full tier. Signed integrity manifest and build state in every report.
- Deployment: Azure Automation templates and runbooks for the scheduled Conditional Access cycle and the monthly
  posture cycle, with a managed identity and a customer-side Key Vault for the Purview certificate; GitHub Action
  and launchd samples; Teams and email notifications that stay inside the customer's environment.
