# Changelog

One entry per release. Pre-release work is summarised under Unreleased until the first tag; after that, every
entry names the version, the date and what changed for the person running the module. Dates are the day the
work landed on main.

## 0.4.0-alpha (2026-11-21)

The short version, for someone coming from 0.3.0-alpha. The entries under it say what changed and why.

- The catalog went from 204 checks in 13 domains to 282 in 15 (catalog 2026.11.2). User experience and network
  access are new domains, and Azure, email, devices, identity and hybrid each have more checks.
- The report draws what it used to list: outcomes, charts, sign-in flows, a licence recommendation, an inventory, and a
  card for each failed check that says what was found and what users will notice when it is fixed.
- A check is judged only on evidence it has. What could not be read has no answer; it never passes and never fails.
- Collection and the report hold no long list in memory. Measured on a made-up tenant of 300,000 users.
- A run that stops carries on: after a failed step, after a sign-in that ended, and in Azure Automation after the
  three-hour limit.
- Evidence collected elsewhere has one way in. The two Windows collectors ship with the module, and "To complete
  this assessment" in the report says who has to run what and where to bring it.
- The consent changed. Two permissions are gone, five read-only ones are new, and the scheduled run no longer holds
  full control of SharePoint unless asked. An admin consents again once; until then each new read says which
  permission it lacks.
- Run against a live tenant with a normal sign-in and through the scheduled run. Not yet seen live: the five new
  reads through the scheduled run's identity (Azure keeps its old token for up to a day; a run without them says
  which permission it lacks), the reads that need Microsoft 365 E5, the two that need a tenant that syncs from
  Active Directory or federates a domain (Defender for Identity health, a federated domain's certificate), and the
  Windows AD collector's changes on a real domain.

- The catalog is measured against Microsoft's Zero Trust Assessment (2026-11-22).
  `checks/references/zero-trust-assessment.json` lists the 364 tests of release 3.1.0. 110 are covered by a check and
  251 are planned, each with a note: the largest groups are Global Secure Access detail, Azure network security,
  Microsoft Sentinel configuration and settings in policies the run already collects. Three are out of scope (a
  licence held, and Security Copilot capacity). `build.ps1 -Task ZeroTrustData` rewrites the list from a release.
- The catalog is measured against Maester (2026-11-22). `checks/references/maester.json` lists the 613 tests of
  Maester 2.3.0 in five families: its own tests (220), the Entra ID configuration tests (EIDSCA, 44), the Defender
  for Office 365 ones (ORCA, 67), exposure management (12) and Active Directory (270). 116 are covered by a check and
  197 are planned, most of them single settings in policies the run already collects. 300 are out of scope: 47 are
  Azure DevOps, and 253 are Active Directory tests that read a count or a list for a person to look at and judge
  nothing, or that watch replication health. `build.ps1 -Task MaesterData` rewrites the list from a Maester release.
  Maester's CISA tests are the SCuBA policies above, and its CIS tests are left out because CIS benchmark content is
  licensed.
- One app for everything TenantKeep reads (2026-11-22). The sign-in app is now named TenantKeep and is shared with
  the TenantKeep On-Call app for what that reads; the client id is unchanged, and so is every consent already given.
  `app.json` lists what Posture asks for under `resources` and what On-Call asks for under `sharedWith`. Nothing on
  the app can write: every write lives in a separate On-Call app, and a test fails if a scope that could is added
  here. Two things changed in the sign-in because the app is shared. The link an unapproved tenant is given now names
  Posture's permissions one by one (the older link approved everything registered, which would now include On-Call's
  reads, a LAPS password and a BitLocker key among them). And the browser step asks only to sign the admin in; what
  the organisation approved is fetched with the refresh token, which can show no prompt. In a tenant that uses both
  products a token for either carries what was approved for both; Microsoft issues one set of permissions per app.
  `New-PostureClientApp.ps1` finds the registration by its client id, so the new name renames it. Run live on
  2026-11-22: the registration was updated, and Microsoft showed the approval screen for the one link that names the
  permissions of all three APIs.
- A remediation plan (2026-11-22). Recommendations gains a flow chart under the Roadmap lanes. The lanes still sort
  findings by risk; the plan says what has to happen first. The checks are grouped into 42 projects, every check in
  exactly one (`checks/projects.json`), each naming what it needs first and what it is better after, with the
  reason. For a run, the projects with something to fix sit in columns by the order they can start: the first column
  can run side by side, and an arrow leads to each project that waits. A project waiting on something the run could
  not judge is told to check it first. Highest Risk Only dims the rest. The same plan is in words under the chart, in
  `report.md` and in `findings.json` (`plan`).
- The catalog is measured against CISA's SCuBA baselines, policy by policy (2026-11-22). A new file,
  `checks/references/cisa-scuba.json`, lists all 109 policies of ScubaGear v2.0.0. 55 are covered by a check; 53 are
  planned, each with a note on what it needs (17 of them Power BI and Power Platform, which need permissions the app
  does not hold yet); one applies to US federal agencies only. A test fails when a policy has neither a check nor a
  reason, or when a check names an id CISA no longer has. That found 13 checks filed under ids CISA has renumbered or
  moved (the Defender for Office 365 policies went from MS.EXO to MS.SECURITYSUITE); they now carry the current ones,
  and CL-013 is filed under the lobby policy it judges, not the one about requesting control. A check can name
  further policies in `references.scuba`. `build.ps1 -Task ScubaData` rewrites the list from a ScubaGear release.
- Every open Secure Score action, by product (2026-11-22). Under Top Secure Score Improvements in Operations, a list
  that opens shows every action Microsoft still scores as open in the tenant, under the product it belongs to, with
  the points to earn and Microsoft's link. The last column opens the check in this report that judges the same
  setting, with its answer; the rest are marked Microsoft's only. It reads what a run already collects. A new
  collection also saves each action's product (`Service` in `def-06-secure-score-controls`); older evidence falls
  back to the category. Checks name the actions they overlap in a new optional catalog field,
  `references.secureScore`: 62 checks name 103 of Microsoft's actions. Microsoft publishes no list of the ids, so
  `checks/references/secure-score.json` keeps the 461 a tenant's own control list showed, and a test fails when a
  check names one that is not there. `build.ps1 -Task SecureScoreData` adds the actions of another run's list (ids
  and titles only). An action no check names still reaches the report from Microsoft's own evaluation.
- The licensing advisor recommends one combination (2026-11-22), in place of a list of options to compare: licences
  to add, or a suite to move to with the add-ons it still needs. Each licence comes with the goals it covers, what it
  brings and what needs it first; a move says what it takes the place of and what stays. The search no longer stops
  at three add-ons, brings what an add-on needs first (ID Governance needs Entra ID P1), and never takes away a goal
  the tenant meets today. Licences held today where one includes all of another are listed. `findings.json` carries
  `licensing.advice.recommended` in place of `options`.
- `New-PostureReport -PriceFile`, or `TENANTKEEP_PRICE_FILE` (2026-11-22): a licence price file of your own lets the
  advisor choose between combinations that all work by the lowest total for a user. The module ships and fetches no
  prices, and nothing of the file reaches a report: no amount, total or comparison, in the page's data either. The
  console and `logs/licensing-basis.json` say which file was used, what it assumes and whether it is more than 35
  days old. Without a file, or when one licence in the comparison has no figure, the choice is on function alone.
  Guide, section 8e.
- Executive Mode is a short view (2026-11-22): the Overview, Recommendations and the domain scorecards, without the
  technical detail. It used to hide two tabs and some columns, and read like the full report. A link to a view it
  does not have lands on the Overview. `-Template Executive` opens the page that way; the button switches.
- `Start-PostureRun -TeamsAppSignIn` (2026-11-22) reads the two Teams app settings the one sign-in cannot: the
  org-wide app settings and each app's availability, which CL-014 goes by. The Teams module reads them with a token
  no permission of the TenantKeep Posture app provides, so with the switch it signs in by itself, with a device
  code, when the run reaches Teams. The session must be the run's tenant and account. Without the switch the two
  steps say "Not readable with this sign-in" and name the switch.
- The Teams module's own sign-in when Conditional Access refuses it (2026-11-22, from the first live run): a tenant
  that blocks device code sign-in answered AADSTS53003, and the run then advised entering the code again and would
  have asked a second time for the second read. Now it says once that the tenant's policy refused the sign-in, as a
  read this sign-in cannot make with nothing to collect again, and puts the run's own Teams session back. On Windows
  the switch signs in through a browser window instead of a device code (not yet run live); elsewhere the Teams
  module offers only the code.
- A logo on the report and an icon on its browser tab (2026-11-22). The TenantKeep mark by default. In a licensed
  tier the organisation's own logo and icon take its place, read from its Entra company branding when the branding
  has them (`01-company-branding-logos`; pictures only, by their first bytes, and never above half a megabyte). A
  logo named in brand.json still wins, and `preparedBy.icon` is new there for the tab. A copy made with `-Redact`
  never carries the organisation's logo, and a report prepared under another name shows no TenantKeep mark.
- The second process names the step it is on from its first step. The line under the run's progress bar said
  "starting" for as long as the first step took, which for Purview is the longest one.
- The ATT&CK view has a section for each tactic, folded until asked for, with its techniques across the page. A
  column for each tactic left the short ones beside the long ones with holes under them. A tactic's bar above
  opens its section, and the tactics sit beside their donut.
- Microsoft 365 Backup (OP-008) has an answer where no Azure subscription pays for it. Backup is paid for through
  Azure and no other way, and the run already reads which subscriptions pay for Microsoft 365 services: when every
  subscription answered and none was billed for Backup in the last 30 days, the check fails saying so (and that a
  subscription the account cannot see is not counted), and Graph is not asked. A tenant without Backup had an
  error row for a read Microsoft refuses and a check with no answer.
- The charts sit in even rows (2026-11-22). Cards were pinned to the top of rows as tall as their tallest card, so
  a short card beside a tall one left a hole under it. The cards of a row now share a height, with "View the
  checks" along the bottom edge. The three layered-ring cards have a row of their own on the Overview, "Defence in
  Depth", with the rings above their list: beside it, every layer wrapped to three lines and the card stood twice
  as tall as its neighbours. A donut's legend stays beside it and wraps its own words. The opening cards and the
  six outcomes fill their rows.
- The Domains tab opens on the scorecards. The charts follow, a section for each domain, folded until asked for,
  with one button to open or fold them all. Printing opens them.
- Run Health lists every source an assessment can draw on and where the run stands with each: collected, not
  collected, or not needed here, with the kind of tenant that would need it. "To Complete This Assessment" speaks
  only when a check waits for something, so a run that lacked nothing explained nothing, and a reader could not
  tell "not needed for this tenant" from "nobody told me" about the Active Directory read or the SharePoint site
  permissions report. The rows are data, in the completion block of the catalog.
- Four fixes from the first run of this version against a live tenant (2026-11-21):
  - Azure Lighthouse delegations (AZ-030) were asked of a Resource Graph table that does not exist, and Azure
    answered Bad Request. The table is `managedservicesresources`.
  - Microsoft 365 Backup (OP-008) told a Global Administrator to grant a role they held and collect again. Microsoft
    refuses the read to this sign-in even with the permission consented, in a tenant without the service at least;
    it documents these reads for backup controller applications. With the permission on the sign-in the step now
    says "Not readable with this sign-in", with nothing to grant, and OP-008 says the same. Where the policies can
    be read and only the service's status is refused (it is behind `BackupRestore-Control.Read.All`, which the
    module does not ask for), the status is recorded as not read: a workload without an active policy still fails
    the check, and three active policies with an unknown status have no answer.
  - The two Teams reads for app centric management cannot be made with the one sign-in: the Teams module wants a
    token the sign-in does not carry. Run Health now says "Not readable with this sign-in" with nothing to grant,
    and CL-014 has no answer from such a run. It used to fall back to the old app permission policy, which a tenant
    moved to app centric management no longer goes by.
  - `Start-PostureRun -Client contoso` means the client named contoso under `~/tenantkeep/clients`, as it does on
    `Resume-PostureRun`. It was a path and nothing else, so a bare name started a second client folder in whatever
    directory the admin was in, without the licence of the real one. A folder that exists where you are, and
    anything written as a path, is still that folder.
- The second process no longer writes over the progress display (2026-11-21). Exchange and Purview collect in a
  process of their own, and it listed its files on the console the main process was drawing its progress on: lines
  ran into each other and the bar looked stuck. It is quiet now, and the main process says how many files it wrote
  when it ends.
- The per-user MFA count moves with every batch. It was redrawn every 500 accounts, so a sample of 1,000 stood at
  "20 of 1,004" for most of the step.
- The closing lines of a run, and Run Health in the report, offer `Resume-PostureRun` only when collecting again
  can change something. With nothing but missing licences and reads Microsoft does not give the sign-in, they say
  so.
- Five new read permissions on the consent, and what they read (2026-11-21, catalog 2026.11.2). All are read-only
  delegated scopes on Microsoft Graph, added together so a tenant consents again once. A tenant on the earlier
  consent keeps working: the five reads fail with the permission named, and the report's "To complete this
  assessment" says to consent again.
  - `DeviceManagementRBAC.Read.All`: Intune's own role assignments, scope tags and multi-admin approval. DEV-025,
    a multi-admin approval policy exists; DEV-026, no role that can change things is assigned over every device
    and user.
  - `SecurityIdentitiesHealth.Read.All`: Defender for Identity health issues, read on tenants that sync from a
    domain. HY-034, none is open.
  - `ServiceHealth.Read.All` and `ServiceMessage.Read.All`: what Microsoft has open for the tenant, listed in Run
    Health and judged by no check; and the Message Center posts with a date to act by. OP-011, none is inside the
    warning window.
  - `Domain-InternalFederation.Read.All`: for each federated domain, when its token-signing certificate runs out.
    On the expiry calendar (OP-006); the certificate itself is never kept. This is the narrower of the two
    permissions that read it (`Domain.Read.All` is the other).
- The managed identity's grant script lists the same five as application roles.
- `build.ps1 -Task AttackData` writes `attack.json` with the same line endings on Windows as elsewhere, and four
  tests no longer depend on how the platform ends a line (the first Windows CI run of them failed on that alone).
- `deploy/automation/deploy.ps1` stopped right after the template deployment whenever the Azure CLI had something to
  say first ("A new Bicep release is available"): the notice was read as part of the JSON. The CLI's warnings and
  notices are now shown and kept out of what is parsed, there and in the four other places that read its output
  (the Purview setup script, the release setup script, licence signing and the integrity manifest). A deployment
  that stopped this way had applied the template and nothing after it; running the script again finishes it.
- A run made of several collections into one folder (the scheduled run, a resumed run) no longer repeats one
  collection's news under the next. A missing scope is warned about only when a collector in that call reads with
  it, and the closing line counts the steps that failed since that collection began and is left out when none did.
  The first scheduled run after new roles were granted printed eight scope warnings and "7 step(s) failed" under
  "collect (Exchange)", none of them Exchange's.
- The sign-in line `deploy.ps1` prints before the grant script now carries `RoleManagement.ReadWrite.Directory` when
  the deployment includes posture. The grant script refuses without it, so a first deployment that followed the
  printed line was turned away. The grant script's last line now says what the scheduling guide says: Azure keeps a
  managed identity's token for up to a day, so a job started sooner may run without the new roles.
- `build.ps1 -Task AttackData` prints each mapping to fix on a line of its own before it fails. The weekly upkeep
  report read them out of the error text, which PowerShell wraps to the console's width, so a long one arrived cut
  (and a test of it failed on Windows, where the console is 120 columns wide).
- A calendar with nothing near its date has no answer when a federated domain's signing certificate could not be
  read.

- Ten new checks from reads that need no new permission (2026-11-21, catalog 2026.11.1).
  - OP-009: Secure Score against its best day in the 90 Microsoft keeps, as a share of the maximum. A fall of more
    than five points means something was undone.
  - OP-010: subscriptions in their grace period, suspended or locked out.
  - DEV-024: Intune certificate connectors that Intune calls inactive, or that had been silent for more than three
    days when they were read.
  - ID-024: applications that hold Graph application permissions and have not signed in for 90 days. Applications
    made in that time are left out, and a holder the run cannot find is never counted as in use.
  - AZ-029: the share of the resources Azure Policy evaluated that break no policy, with the assignments most
    resources break.
  - AZ-030: Azure Lighthouse delegations that give another tenant more than read access, or whose roles could not
    be read.
  - EM-028: whether Exchange Online rejects Direct Send. No answer where the environment does not have the setting.
  - CL-017, CL-018, CL-019: how long a deleted user's OneDrive is kept, OneDrive sync limited to the organisation's
    own domain-joined computers (hybrid tenants), and idle browser sessions signed out. All three from the Graph
    read of the SharePoint settings the run already makes.
- The expiry calendar (OP-006) gains Apple Automated Device Enrollment tokens, trial subscriptions and
  subscriptions in their grace period. A paid subscription in good standing is not on it: its date is its next
  renewal.
- New evidence: `01-subscriptions`, `10-app-signin-activity`, `09-apple-ade-tokens`, `09-certificate-connectors`,
  `def-06-secure-score-history`, `az-03-policy-compliance`, `az-03-policy-noncompliant-assignments`,
  `az-17-lighthouse-delegations`; `exo-01-orgconfig` gains `RejectDirectSend`. The demo tenant has the Microsoft 365
  ones.

- "To complete this assessment" (2026-11-21). A run that lacked a piece said so check by check, in forty reasons
  that each named a script path. The report's overview now opens with one row for each missing piece (the Active
  Directory read, the SharePoint admin read, the site permissions report, a domain that was skipped, steps that
  failed and the permissions the sign-in lacks): how many checks wait for it, who can add it, where, the command
  with this run's paths in it, and the command that brings the result back. The run prints the same rows when it
  ends. The rows are data in checks/catalog.json (`completion`), so a new check adds no code to the report.
- A site permissions report saved straight into the client folder's `imports/` is filed by the next run, with
  the checks `Import-PostureSharingReport` makes. A CSV of something else there is left alone.
- A run says how big the tenant is before it collects: users, devices and groups from three small reads, and for
  a large tenant how many requests the long lists are, that per-user MFA is read as a sample, that OneDrive
  sites are not listed, and that the run can be stopped and resumed.
- Run and client folders are the owner's alone on macOS and Linux (mode 700). They were created readable by every
  account on the machine. docs/footprint.md says what is in them and what Windows does.

- `Export-PostureCollector` (2026-11-21). The two scripts that run on a Windows machine, the Active Directory read
  and the SharePoint admin read on Microsoft's own shell, lived in the repository and had to be found there. They
  now ship inside the module, and `Export-PostureCollector -Kind ActiveDirectory|SharePoint -Run <run>` writes one
  to a folder with a RUN-ME.txt: who runs it, where, the exact command with the run's tenant filled in, and the
  command that brings the result back.
- One way in for evidence collected elsewhere. `Start-PostureRun` and the Automation runbook copied the client
  folder's `hybrid/ad-*` files into a run as they were; they now go through `Import-PostureEvidence`, with its
  check of every file against the collector's bundle.json. A folder that fails is not used, and Run Health says why.
- Active Directory evidence is checked against the tenant. Nothing tied an AD read to a tenant, so a consultant
  with twenty client folders could put one client's domain controllers into another client's report. One of the
  forest's UPN suffixes must now be a domain the run's tenant has verified (or sit under or over one); a forest
  that shares none is refused unless `-Force`. The record of each import says how the check went.
- `Import-PostureEvidence` rebuilds the report of a run that has one (`-NoReport` leaves it), files an Active
  Directory read for later runs with `-Client`, and takes a run kept in one folder.
- The hybrid scorecard says when Active Directory was read, and how long before the rest of the run.
- The hints on checks that need a Windows collector name the two commands, not a path in the repository.

- The Automation runbook carries on instead of starting over (2026-11-21). Azure Automation stops a sandbox job
  after three hours and starts it again from the top; the runbook began every job with an empty folder and
  uploaded nothing until the end, so a tenant that needed more than three hours never finished. The run is now
  copied to the customer's container as it goes (each evidence file when its step closes, with the journal), and
  a job that finds a run from the last day with a journal and no report downloads it and continues: finished
  domains are left alone, finished long lists are kept. New on `Invoke-PostureCollection`: `-StepCompleted`, a
  block called with the files each step closed (the module does nothing with them itself), and `-SkipFinished`.
- The runbook uploads the run's subfolders. `affected/<check>.csv`, which the report points to for the full
  lists, never reached the container.
- The scheduled run reads SharePoint settings through Graph, and no longer holds full control of every site by
  default. `Grant-ManagedIdentityGraphRole.ps1 -IncludePosture` grants `SharePointTenantSettings.Read.All`, whose
  absence failed that read on every scheduled run, and grants nothing on SharePoint Online.
  `Sites.FullControl.All`, a standing permission to read and change every file in every site, is granted only
  with `-IncludeSharePointAdminRead`, for the site list, and the script says what it is. An identity that already
  holds it keeps it until an admin removes it. A refused SharePoint read no longer costs the Teams read.
- A large tenant can run the posture runbook on a Hybrid Runbook Worker: `deploy.ps1 -HybridWorkerGroup` and
  `-HybridWorkerPrincipalId`. docs/scheduling.md says when (20,000 users until measured) and what the worker's
  identity needs.
- The runbook sends its Key Vault token only to an Azure Key Vault secret address. It went to whatever URL the
  `TENANTKEEP_PURVIEW_CERT` variable held.
- A report over 2 MB is not attached to the runbook's email, which would not have been sent; the message says
  where the report is.

- A run that outlives its sign-in (2026-11-21). An admin account often has a Conditional Access sign-in frequency
  of a few hours. Past it every renewal is refused, and every remaining step failed one by one, each with its own
  line. Now, when a renewal is refused because the sign-in has ended (`invalid_grant` or `interaction_required`:
  AADSTS70043, 70044, 700082, 50173) and someone is at the console, the run pauses, asks the same account to sign
  in again and repeats the request it was making. The new sign-in must be the same account in the same tenant, at
  most three times in a run, and the second process's renewals get the new sign-in too. With no one to ask, or
  when no one signs in within fifteen minutes, the run stops once: the steps that depend on the sign-in are not
  attempted and send nothing, each domain gets one line with how many were left, the domain is not recorded as
  finished, and `Resume-PostureRun` carries on after a new sign-in. Exchange and Purview, which sign in through
  the Exchange module, are not touched by this.
- The run says beforehand which sign-in frequency applies. From the Conditional Access snapshot: the shortest
  frequency among the enabled policies that cover the account (by id, by "All users", or by a role in its token)
  and Microsoft Graph, and what will happen when the run outlasts it. A policy that depends on a group is reported
  as "may", since group membership is not read for this.
- A bare 401 is an ended sign-in. It was classed as a missing role and Run Health advised granting one. A 401 is
  the service not accepting the token; 403 is the answer that means a role is missing.
- A domain started again that did not finish is not finished. `Resume-PostureRun` and Run Health took a domain as
  finished when an earlier attempt had put it in collection.json, even when a later attempt at it died or stopped
  part way after its failures had been cleared for the retry. The journal's last word on a domain now decides.
- Run Health lists the steps that were not attempted because the sign-in had ended.

- The long lists are not read twice (2026-11-21). Collecting a domain again in the same run, after a failure or a
  process that stopped, read every list again: the users, registration, groups and devices of a large tenant are
  hours. A list that finished in this run less than a day ago is now kept (users, registration, per-user MFA,
  groups, Entra devices, Intune devices, Defender devices and antivirus state, mailboxes, CAS mailboxes,
  SharePoint sites), as long as every file it wrote is still there at the length it was and what it depends on
  is unchanged (who holds a role, `-StaleDays`, `-IncludeOneDriveSites`). The console says "kept, read <time>".
- A Graph list that stops part way carries on from where it stopped. Users, registration, groups, Entra devices
  and Intune devices save a cursor every ten pages (`logs/cursor-<list>.json`: the next page link, how far each
  file had got, the step's counts). When the read fails, what was read stays in the `.part` files, which no
  reader opens; the next attempt cuts the files back to the cursor, puts the counts back and asks for the next
  page. A cursor is used for a day, only for the same request and the same inputs; when Graph no longer accepts
  the link, that list alone starts over. A sign-in that ends in page 2,400 of the users no longer costs 2,400
  pages.
- Per-user MFA and PIM for Groups read the members and the role-assignable groups from the lists on disk, not
  from memory. When the list was never collected, the step now fails and says so; it used to write a summary of
  zero members, or zero role-assignable groups, which read as an answer.

- A run that stops part way is resumed where it stopped (2026-11-21). The record of what a run collected,
  collection.json, was written once, at the very end. A run whose process died in its last domain after hours of
  collection left no record, and `Resume-PostureRun` collected every domain again. The run now keeps a journal
  (`logs/journal.jsonl`: each step as it starts, finishes or fails, each file as it is written, each domain as it
  finishes), and collection.json is rewritten after every domain. Resume reads both and collects only what did
  not finish.
- A file left from an earlier attempt is not read. When a step ran again and failed (a role taken away, a licence
  that lapsed), the file its earlier attempt wrote was still in the folder and was judged as today's evidence. The
  journal now says which attempt wrote each file: a file whose step ran again and did not write it is treated as
  not collected, by every reader, and the checks that need it say not evaluated and why. A file a step wrote
  before it failed in the same attempt is still read. A run folder with no journal is read as before.
- Run Health says where a collection stopped and what was judged on part of the data. New lists: the domains that
  did not finish with the command that collects only those, the steps that started and never finished, files left
  from an earlier attempt, writes that were cut short (`.part` files, never read), and every check whose answer
  came from part of the data (a sample, a list with a ceiling, some subscriptions) with how much was read. A
  result carries that sentence as `judgedOnPart`. The overview says when the collection stopped before the end.
- ID-012 names the file it lacks: the users list when the guests cannot be read, not the users summary.

- The Windows AD collector on a large domain (2026-11-21). It read every user and every computer into a variable,
  gigabytes in Windows PowerShell on a domain of hundreds of thousands, and ran one Group Policy report per GPO,
  hours with thousands of them. Users and computers now go through the pipeline and are counted as they arrive.
  GPO links come from one query for `gPLink`, and stored passwords from one pass over the preference files in
  SYSVOL. When SYSVOL cannot be read, HY-030 has no answer; it used to read as "no stored passwords".
- A forest read on one domain says so. The collector reads one domain for each run and the report judged the
  forest on it without a word. The checks on a domain's accounts, groups, policies and computers now keep a
  finding with "Judged on the domain X, one of N in the forest" and have no answer where nothing was found.
  Reading every domain in one run is not built. bundle.json gains the forest, its domains and its UPN suffixes.
- The sign-in read keeps no list of who failed from where (2026-11-21). To spot a password spray the collector
  remembered, for each address, every account that failed from it, up to 1,000 accounts for each of 20,000
  addresses, and wrote that to its checkpoint on disk every ten pages (276 MB at the ceilings). An account is now
  remembered by a keyed hash wherever the question is only how many different accounts: per address, per
  report-only policy, and for the legacy total. The names are in neither the tallies nor the checkpoint, an
  address keeps 200 accounts at most (`AccountsFailedOrMore` says when it met that), and the accounts listed for
  legacy sign-ins are bounded. A checkpoint from before this change is converted before the read carries on.
- A restart of the sign-in read counts no record twice. The ids at the oldest second were kept for the last page
  only; when more than one page shared that second, a restart counted the earlier pages' records again.
- The sign-in summary says what it counts (`Scope`): interactive user sign-ins.
- Azure: every subscription, and a refusal costs one subscription (2026-11-21). The per-subscription reads
  (Defender plans, security contacts, activity log export, classic administrators, budgets, pay-as-you-go spend)
  stopped at the first 200 subscriptions, and one subscription that refused a read failed the whole step, so a
  tenant with one locked-down subscription had no Defender plans for any. Every enabled subscription is read now;
  a refusal is recorded against that subscription (`DetailError` in `az-01-subscriptions`), the others are
  written, and the checks judge the subscriptions that answered and say how many did not. Throttling is waited
  out, after Retry-After when Azure sends one. Budgets are read once. Resource Graph is paged by position when it
  gives no page token, and an answer it marks as cut short is an error.
- Intune and Defender collection without holding the long lists (2026-11-21). Autopilot devices, Intune apps and
  active incidents are written as their pages arrive; BitLocker keys are counted per device as they page (only
  how many a device has was ever kept); the ninety-day incident trend is counted as it pages. The settings of
  assigned settings catalog policies are read twenty policies to a request, and one policy that is refused no
  longer costs the others. Intune apps are read with only the properties that are written.
- A Defender device list larger than one query returns. A shard that comes back with fewer rows than it has is
  read again in sixteen parts, so a fleet up to sixteen times larger than before is listed whole. Past that the
  list is still marked cut short and the checks on it have no answer.
- The Entra collector holds none of its long lists (2026-11-21). App registrations, service principals, delegated
  grants, risk detections and ownerless groups are written as their pages arrive. Risky users are the users at
  risk now: the list used to be everyone who ever had a risk, dismissed and remediated included. PIM for Groups
  is read twenty groups to a request.
- A fallback only for the reason it exists. Two reads fall back to a lesser one: users without sign-in activity,
  and plain role assignments without PIM. They did so on any error, so a timeout wrote the roles with no eligible
  assignments and the checks read a tenant with none. They now fall back on a refusal or a missing licence and
  fail the step, with its cause, on anything else.
- Per-user MFA on a large tenant is a sample, and says so (2026-11-21). Above 5,000 members the collector reads
  every administrator and 1,000 other members at random. When one of them had per-user MFA it then read everyone,
  a request per account, with no checkpoint: hours on a tenant of hundreds of thousands. The sample is now the
  answer either way, AU-009 says what it judged ("3 of the 1,012 accounts sampled have per-user MFA; the tenant
  has 80,000 members"), and `-FullPerUserMfa` reads everyone when the full list is wanted. The rows are written
  as each batch answers.
- Exchange Online PowerShell access without the whole directory. The setting is on for everyone by default, so
  the list was a row per user. The collector now skips it when the Exchange Online PowerShell app is closed to
  everyone but assigned people (EM-025 passes on that alone), and otherwise counts everyone and keeps the first
  500 accounts that are people and, when the role holders are in the run folder, not administrators.
- SharePoint: the site list is the sites, not the OneDrives (2026-11-21). Both SharePoint collectors listed every
  OneDrive, one per user, and no check reads them: on a large tenant that was most of the collector's time and
  the largest file in the run. They are left out now; `-IncludeOneDriveSites` lists them all the same, and the
  summary says whether they were listed (`OneDrivesIncluded`; `OneDrives` is empty when they were not).
- Conditional Access group scope without holding the members. The member hash is fed one id at a time, and gives
  the same hash as before. A group over 50,000 members is counted in one request and not hashed (it was a page
  per 999 members on every snapshot); the diff compares such a group by its count, and `-HashLargeGroups` hashes
  it all the same.
- The named locations table in the CA document shows the type of each location and its IP ranges. Both columns
  were empty for IP locations: the value reader could not read a key with a dot in it (`@odata.type`).
- Tables with one row. A Markdown table built from a single row came apart into one row per cell: the named
  locations of a tenant with one location, a single health flag, a single drifted group, a domain with one check.
  The first row of the two appendix tables ran its cells together. All fixed, in the CA document, the CA diff
  and report.md.
- Measured at 300,000 users (2026-11-21). On the made-up tenant the review used (300,000 users, 300,000
  OneDrives, 50,000 devices, 50,000 groups, 1.1 GB of evidence) the report now peaks at 524 MB and takes 114
  seconds. It peaked at 10.2 GB before the large lists were read a row at a time.
- Faster lookups (2026-11-21). The Azure checks asked each list again for every subscription: 197.7 seconds on a
  made-up tenant of 1,500 subscriptions. The lists are indexed by subscription once, and the same tenant takes
  1.6 seconds. Finding a handful of rows in a large list (the principals behind Azure role assignments, the
  accounts behind shared mailboxes) reads the CSV's fields without building an object for every row, about two
  and a half times as fast.
- The report costs the same memory on a large tenant as on a small one (2026-11-21). Every list with a row per
  user, device, group, mailbox or site was loaded whole somewhere after collection, and kept in a cache: the
  report peaked at 10 GB on a made-up tenant of 300,000 users. Each of those reads is now a pass over the CSV a
  row at a time, or a summary the collector counted while it wrote the list (`05-auth-registration-summary`
  gains `Tally`, `07-groups-summary` is new, the Defender device lists are written as their shards arrive). At
  20,000 users the report now peaks where the demo does (368 MB against 373 MB; it was 709 MB), and no fact
  provider keeps more than 7 MB (the worst kept 70 MB). The scale test's budgets were tightened to hold that, the
  evidence cache no longer keeps a file over 8 MB, and a test reads the source and fails the build on a
  whole-file read of one of these lists.
- More true counts. The lists of devices not onboarded to Defender, unhealthy sensors, antivirus not active,
  inactive guests, unaddressed high-risk users, legacy protocol mailboxes and per-user MFA accounts keep the
  first 500 rows; the count beside each is of all of them.
- Dates in CSV evidence no longer shift with the machine's time zone (2026-11-21). The CSV twin of a list carried
  dates as plain text with no zone, and the reader took them for local time: the same folder read six hours off
  in Chicago and eleven in Sydney, which moved the dates shown in affected lists. The CSV now carries ISO 8601 in
  UTC, as the JSON always did, and text with no zone is read as UTC, which also corrects the files already on disk.
- A scale test on every build. The made-up demo tenant is grown to 20,000 users with the module's own writers,
  the report runs on both in a fresh process, and the difference in peak memory is held to a budget; a second
  pass holds what each fact provider leaves in memory to a budget of its own. The budgets start at today's
  numbers (the report peaks 335 MB higher at 20,000 users than on the demo) and come down as the whole-file reads
  are removed.
- No more "Parameter 'NoTypeInformation' is obsolete" warnings on PowerShell 7.7.
- Catalog 2026.11.0, and a trend that knows the catalog changed (2026-11-21). The first report after this update
  compared with one from before it would have shown checks "started failing" or "resolved" that moved only
  because the check changed. `checks/catalog.json` now records, per version, the checks whose meaning changed and
  why. When the two runs were judged with different catalogs the trend says so, says the two scores are not
  measured the same way, and lists those results under "Changed with the catalog" with the reason, apart from
  new failures and fixes.
- A check that could be judged before and has no answer now is listed under "No answer in this run". It used to
  count as resolved when it had been failing.
- Everyone who holds a role is counted (2026-11-21). A role assigned to a group names the group, not its people,
  and the report took the group for one administrator: its members were not held to a phishing-resistant method
  (AU-008), not counted as Global Administrators (ID-001), and not in the admins table; an administrator who was
  only eligible was not counted by AU-008 either. The Entra collector now reads the members of every group that
  holds a role, and who PIM for Groups lets join it, into `04-role-holders`: one row per person and role, held
  directly, as eligible, through a group, or as eligible through a group. The registration and users files, the
  sign-in tallies, AU-008, ID-001 to ID-004, EM-025 and the admins table all read that list. Expect ID-001,
  ID-002, ID-004 and AU-008 to move on a tenant that assigns roles to groups: the numbers are people now.
- A group nobody opened is not "no one". When the members of a group that holds a role could not be read, or the
  run is from before they were, the checks that count administrators say so: a gap they saw is still a finding,
  with "Judged on the role holders that were read" as its reason; with none seen there is no answer, and the
  count of Global Administrators stays out of the headline.
- The authentication methods policy without its methods is no answer. A `02-authentication-methods-policy` file
  with no method configurations used to stop every authentication check with an error; AU-001 to AU-005 now say
  the policy was not read whole.
- The demo tenant has a group that holds a role, an administrator who is only eligible and one who can join the
  admin group through PIM for Groups. A generated person no longer shares a sign-in name with a named administrator.
- No finding from a cap (2026-11-21). Three reads stop short on a large tenant, and what they did not read used
  to count against the tenant. The Azure collector reads Defender plans, security contacts, activity log exports,
  classic administrators and budgets on the first 200 subscriptions; the other subscriptions were reported as
  having no contact, no export and no plan (1,300 false flags on a made-up tenant of 1,500). `az-01-subscriptions`
  now says which were read (`DetailRead`), the checks judge those only, a gap among them is a finding whose reason
  says "Judged on 200 of N subscriptions", and with no gap among them the check has no answer. The Defender device
  lists ask each shard how many rows it has before reading it; a shard that returns fewer marks the summary
  `Truncated`, and EP-019, EP-020 and EP-021 then have no answer instead of counting devices over a short list.
  PIM for Groups reads every role-assignable group (the first 100 before) and records how many it read.
- A check that lists the first 500 affected objects now counts all of them. The count on the page, in
  `checks.json` and in the exports was the length of the list, so 12,000 mismatched sign-in names read as 500.
  `affectedCount` is the true number, `affectedListed` how many the run holds, and the page says "The run lists
  500 at most for this check" instead of promising every one in the CSV. An exception that covers every listed
  object no longer turns the check into an accepted risk while unlisted objects remain. The number of synced
  groups that access depends on (HY-032) was itself capped at 500 and is now counted in full.
- No answer for what was not read (2026-11-21). Where a provider could not read a file it used to carry on with
  "off", "none" or zero; it now says unknown, and the check is judged only when the rest decides it. This covers
  the device cleanup rule (DEV-002), feature update profiles (EP-014), quarantine notifications (EM-007), the
  Exchange PowerShell app and its users (EM-025), label policies (CP-006), Apple VPP tokens (DEV-008), the mail
  gateway (EM-026), Windows Hello (EP-012), password writeback (UX-015), Teams guest governance (CL-012), jailbreak
  detection (EP-018), synced subscription owners (AZ-011) and the admin tools when the Conditional Access snapshot
  is missing (ID-023). Removing one evidence file at a time from the demo run used to flip five passes to fails;
  a test now does that for every file on every build and allows none.
- One missing file no longer takes a whole domain down. The authentication checks stopped with an error without
  the role assignments, identity without the eligible assignments, endpoint without the compliance policy
  settings; each now evaluates what it can. An incomplete Conditional Access snapshot names the files that are
  missing, and no reason carries the run folder's path any more.
- A DNS lookup that fails is not a record that is missing. The mail DNS step records the lookups that got no
  answer (`LookupFailed` in `dns-01-mail-records`), and the DMARC, SPF, MTA-STS and gateway checks read those
  as unknown: a gap that was seen still fails, and with none seen and some domains unanswered the check waits
  for the next collection. A timeout used to read as "no DMARC record".
- A rate over nothing is not a rate: BitLocker escrow with no Windows devices, the join type mix with no devices
  and self-service password reset with no members read "not evaluated" with the reason, where they passed at
  100 percent or 0. The demo tenant wrote join types the collector never writes, so its BitLocker check had been
  passing on zero devices; it is judged on the real fleet now.
- A check is judged only on evidence it has (2026-11-21). The engine now holds every check to its evidence list:
  a file the check needs that is not in the run folder makes it "not evaluated" and names the file, before
  anything is compared. A check can mark a file as one it can do without (`evidenceOptional`) or name
  alternatives where one is enough (`evidenceAnyOf`: the SharePoint settings from the admin read or from Graph, a
  slim file or the full list it replaced). Inside a pass expression a value that could not be read is unknown, a third answer beside true and false,
  where `!facts.x` on a missing value used to pass: "no stale devices, or a cleanup rule" passes on a tenant with
  no stale devices even when the rule could not be read, and has no answer, naming the rule, when there are stale
  devices. The evidence lists of 59 checks were corrected against what the providers read. Custom
  checks follow the same rule: name in `evidence` only files the check needs, or list the others as optional.
- A sign-in under the user name "Count" or "Keys" no longer stops the sign-in log read (2026-11-21). A failed
  sign-in is logged under whatever name was typed, and the tallies are kept per name; PowerShell answers `.Count`
  and `.Keys` on such a table with the entry of that name, so one attempt from anywhere on the internet made the
  step throw, or hid a password spray from the list of addresses. The tallies and the `-Redact` name map now
  read those members through their methods.
- Evidence is written whole or not at all (2026-11-21). Every evidence file is written as `<name>.json.part` and
  `<name>.csv.part` and takes its name only when it is complete. A run that is killed while a list is being
  written (the laptop sleeps, the process runs out of memory, an Automation job hits its time limit) used to
  leave a cut-off CSV that the device, mailbox and site checks read as the whole list; now those checks read
  "not collected" and name the file. A second attempt at a list no longer leaves the first attempt's file behind
  when it fails. `profile.json` and `checks.json` go through a temporary file too, so a stop mid-write cannot
  leave half a profile for the next run.
- Names from the tenant can no longer act in a spreadsheet or break the page (2026-11-21). A guest chooses their
  own display name, so an affected list can carry `=HYPERLINK(...)`: in `affected/<check>.csv`, `findings.csv`,
  the redaction key and the page's own CSV export, a cell that starts with `=`, `+`, `-`, `@`, a tab or a
  carriage return now gets a leading apostrophe, which a spreadsheet shows as plain text. `Export-PostureFindings
  -PassThru` returns the rows unchanged. The JSON the report page embeds is written with angle brackets and
  ampersands escaped, so a name such as `<!--<script` cannot swallow the rest of the page.
- Two permissions fewer on the consent screen (2026-11-21): `Sites.Read.All` ("read items in all site collections")
  and `Reports.Read.All` are gone from the TenantKeep Posture app's manifest and from the managed identity grant
  script. No collector ever called an API that needs them. A tenant that already consented keeps working; the
  two stay in its consent record until an admin consents again or removes them. A test now fails when the
  manifest asks for a Graph permission no collector or step uses, and requirements.json names only permissions
  the app carries, so Run Health never tells an admin to grant one that the consent cannot give.
- Commit guards for company information (2026-11-21): the scan that stops credentials now also refuses anything
  named in the developer's local notes or client folders (a deny list built when the hook runs, never stored, a
  hit reported by file and line without its text) and any mail domain or Microsoft tenant name that is not a
  reserved example name. The same rules run on the commit message and, before a push, on every commit about to
  leave, so a commit made with `--no-verify` is caught while it is still local. CI applies the allow list to the
  whole tree. A test fixture carried the client id of a SharePoint app in the publisher's own tenant; it is a
  made-up id now.
- The weekly upkeep watches for beta Graph APIs a check waits on (2026-11-21): it reads Graph's published v1.0
  schema, which needs no sign-in, and files a finding when a listed type arrives. First on the list:
  copilotPolicySetting for CP-015, so the Copilot settings check can read what the API covers once it leaves beta.
- System-preferred MFA is read again (2026-11-21): Graph answered 400 to the `$select` on the beta authentication
  methods policy (seen on Kainor), so the step reads the whole policy and keeps the one setting.
- Teams apps under app centric management (2026-11-21): the Teams collector reads the org-wide app settings
  (`Get-M365UnifiedTenantSettings`, `teams-app-settings`) and every app's availability and block state
  (`Get-AllM365TeamsApps`, `teams-app-availability`). CL-014 now judges the org-wide default for third-party apps,
  names the setting when it fails and counts the catalog by availability; the app permission policy decides only on a
  tenant Microsoft has not moved yet, or evidence from before this read. The Teams entry point accepts those two
  read cmdlets by exact name and still refuses everything else.
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
