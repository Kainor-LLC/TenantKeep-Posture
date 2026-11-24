# Using TenantKeep Posture, step by step

Written for the administrator or MSP engineer who runs the report. Everything below reads the tenant; nothing in the
module writes to it. Each run leaves an evidence folder you keep, a report you deliver, and a findings list you
work from until the next run.

## 1. Two lines

```powershell
Install-PSResource TenantKeep.Posture -Prerelease -Scope CurrentUser   # or Install-Module TenantKeep.Posture -AllowPrerelease
Start-PostureRun
```

A browser window asks you to sign in with an admin account. That is the only sign-in. The module gets a token for
each service from it, runs every collector it can, builds the profile from what the tenant says about itself, writes
the report and opens it. Twenty minutes later for a mid-sized tenant you are looking at report.html. The module is a
pre-release on the PowerShell Gallery, which is why the first line asks for pre-releases; from a clone of the
repository, `Import-Module ./TenantKeep-Posture/TenantKeep.Posture/TenantKeep.Posture.psd1` replaces it.

<div class="shots">
  <figure class="shot wide"><a href="https://tenantkeep.app/posture/sample-report/#overview"><img src="https://tenantkeep.app/assets/posture/report-overview.jpg" width="1400" height="940" loading="lazy" alt="The overview of a report: what the assessment still lacks, the posture score, open findings by severity and the shortest attack path."></a><figcaption>What opens when the run finishes. Every picture on this page is from the sample report of a made-up tenant, Fernquill Engineering; select one to open that view in the report.</figcaption></figure>
</div>

The whole sample report is at [tenantkeep.app/posture/sample-report](https://tenantkeep.app/posture/sample-report/): open it and click around.


With a licence file, or a client folder somewhere other than the default, run `Initialize-PostureClient -LicensePath
<file>` (or `-Path <folder> -ClientName '<customer>'`) once before the first run: it verifies the licence, copies it
into the folder, seeds the profile with the tenant and prints the Start-PostureRun line to use.

What you need:

- PowerShell 7.4 or later on macOS, Windows or Linux, and Microsoft.Graph.Authentication. For the other domains,
  the modules you already use: ExchangeOnlineManagement (Exchange and Purview), PnP.PowerShell (SharePoint),
  MicrosoftTeams, Az.Accounts with Az.ResourceGraph (Azure). A missing module is skipped with the install line.
  `Get-PostureRequirement` lists what is installed against the versions the collectors were tested with
  (Graph 2.39, Exchange 3.10, PnP 3.2, Teams 7.9, Az.Accounts 5.5, Az.ResourceGraph 1.3 as of October 2026); an
  older version runs with a warning, and every run records the versions it used in collection.json. PnP.PowerShell
  2.12.0 is known to work except for the restricted search read behind the Copilot gate C9.
- An account that can read: Global Reader covers Entra, Intune, Defender, Exchange, Teams and most of Purview;
  SharePoint needs SharePoint Administrator; Azure needs Reader and Security Reader on the subscriptions. A few reads
  need a role of their own and show as not evaluated without it: Insider Risk, Communication Compliance, audit
  retention and eDiscovery (their Purview role groups) and hybrid sync features (Hybrid Identity Administrator, only
  for a tenant that syncs from on-premises AD). The report's Run Health page names each one. The module never reads
  more than the account can.
- On a tenant whose Conditional Access demands phishing-resistant MFA, a new read-only account has no passkey to sign
  in with yet: issue it a Temporary Access Pass, sign in once and register a passkey.
- Consent, once per tenant. TenantKeep is a multi-tenant app published by Kainor with delegated, read-only
  permissions (the list is in the module's app.json and on the consent screen). The first run in a tenant that has
  not consented stops and prints the admin consent link; an admin clicks it once, then runs the command again.
- Azure, Teams and Power Platform are read through a second app, TenantKeep Posture for Azure, Teams and Power
  Platform. Microsoft offers no read-only permission for those three APIs, only one to act as the signed-in
  administrator, so they are kept off the TenantKeep app, which holds read-only permissions only. An admin approves
  the second app once, from its own link; a run in a tenant that has not skips those three, prints the link and
  collects everything else. Where it is approved, its sign-in follows the first as the same account, and the
  browser usually passes it without asking.
- Exchange and Purview sign in through the Exchange module's own Microsoft app, not the TenantKeep app.
  Exchange Online's only delegated permission reads "Manage Exchange configuration" on a consent screen and Security
  and Compliance PowerShell issues no token to a third-party app at all, so the app asks for neither. The Exchange
  module may open one window for the same admin (a device code with `-DeviceCode` or `-NoBrowser`); it often reuses
  its own earlier sign-in and asks nothing, and one sign-in covers both. The run starts them first, so that prompt
  comes within a minute of your sign-in; after it the run needs nothing from you. The module renews its own tokens
  however long Exchange takes. Everything else comes from the sign-ins above, with one exception.
- Two Teams reads need the Teams module's own sign-in: the org-wide app settings and each app's availability, which
  the Teams apps check (CL-014) goes by. The Teams module reads them with a token no permission of the TenantKeep
  app provides. `Start-PostureRun -TeamsAppSignIn` lets the module sign in by itself as the same admin: a
  browser window on Windows, a device code elsewhere, because the Teams module has no browser sign-in outside
  Windows. It asks when the run reaches Teams, near its end, so stay for it. Many tenants block device code sign-in
  with Conditional Access, and should: there the code is refused (seen on macOS, 2026-11-22), the run says so once,
  and the two reads can be collected from Windows instead. Without the switch those two steps say "Not readable with
  this sign-in" and the check has no answer. The browser sign-in on Windows has not been run live yet (verify).
- While it runs: a progress bar shows the domain and step under way, the time so far and the time left (estimated
  from this tenant's last run; rough on the first), with a second bar for Exchange and Purview. The computer is kept
  from idle sleep until the run ends (`caffeinate` on macOS, `systemd-inhibit` on Linux, the Windows power request
  call); `-AllowSleep` turns that off. A closed laptop lid still sleeps.
- Conditional Access. A policy that blocks sign-ins to unapproved apps, or requires a compliant device, stops the run
  with the app id in the message. Allow the app or exclude the admin running the report; the module works around
  nothing.

Useful switches: `-TenantId` (an id or `contoso.onmicrosoft.com`) refuses a sign-in to any other tenant; without
it you pick the account in the browser and the tenant comes from that sign-in. `-Collector Entra, Intune, Exchange`
runs a subset; `-DeviceCode` signs in from a machine without a browser; `-Client` points at a client folder other than
the default `~/tenantkeep/clients/<tenant name>/`; `-OutRoot ~/Clients/Contoso/Assessments` puts the run folders
somewhere else for one run, and `New-PostureProfile -OutputRoot` (or the wizard's last question) makes that the
client's default.

The sign-in log: the run reads the last 7 days of Entra sign-ins (`-SignInDays` up to 30) for legacy protocol use,
Conditional Access outcomes, failures and countries. On a large tenant that is millions of records and the longest
part of the run; it streams, saves a checkpoint every ten pages, carries on by itself after a failure, and
`Resume-PostureRun` continues it from the page it stopped at. It needs Entra ID P1.

## 2. The licence

The Conditional Access tools are free. The full report needs the licence file Kainor sent for your tenant: save it as
`tenantkeep.lic` in the client folder next to profile.json, and `Get-PostureLicense -Path <file>` tells you its tier and
expiry. docs/licensing.md explains what is checked (offline, nothing is sent). Without it, `Start-PostureRun` still
produces the Conditional Access domain and says what the full tier adds.

## 3. What the run leaves behind

- `~/tenantkeep/evidence/<run name>/`, one folder per run: name it with `Start-PostureRun -Name "Contoso Q4 2026"`
  (default: the date and time, 2026-11-20-0957). What people open sits at the top, the rest in folders:

  ```
  report.html  report.md  findings.csv  findings.json  README.txt
  evidence/    everything collected, one file per area (prefixes: exo- Exchange, pv- Purview, spo- SharePoint, ...)
  affected/    every affected object per check, one CSV each
  errors/      what could not be read and why
  logs/        transcript, run plan, journal of the collection, check results, and the cursor of a list that
               stopped part way (it holds rows of the list, like the evidence, and goes when the list finishes)
  ```

  README.txt in each run says the same. Runs made before this layout keep everything in one folder and still work
  with every command.
- `~/tenantkeep/clients/<tenant name>/`: profile.json (discovered on the first run, yours to change with
  New-PostureProfile, section 6), exceptions.json once you accept a risk (section 8a), tenantkeep.lic, imports/ for
  the reports you provide (section 8b), hybrid/ for the Windows AD collector's files.

Nothing is written anywhere else. Nothing leaves the machine.

The logo at the top of the report, and the icon on its browser tab, come from the first of these that exists: a
logo named in the client folder's brand.json (`preparedBy.logo`, `client.logo`, and `preparedBy.icon` for the tab);
the organisation's own logo and icon from its Entra company branding, which the run reads when the branding has
them (in a licensed tier); the TenantKeep mark. A copy made with `-Redact` never carries the organisation's logo,
and a report prepared under another name in brand.json shows no TenantKeep mark.

## 4. Hybrid tenants

The on-premises domain is read by a script that ships with the module, on a domain-joined Windows machine, by
someone with an account there. Three commands, the first and last where the run is:

```powershell
Export-PostureCollector -Kind ActiveDirectory -Run ~/tenantkeep/evidence/2026-11-21-0957
# carry collectors/active-directory/ from the run folder to the Windows machine; RUN-ME.txt there has the command:
#   .\Get-ADBaseline.ps1
# bring the folder it wrote (or a zip of it) back, then:
Import-PostureEvidence -Path ~/Downloads/ad-baseline-20261121-1410.zip -Run ~/tenantkeep/evidence/2026-11-21-0957 -Client ~/tenantkeep/clients/contoso
```

The import checks every file against the collector's bundle.json, checks that the forest is this tenant's (one of
the names its people sign in with must be a domain the tenant has verified; another organisation's directory is
refused), rebuilds the run's report, and with `-Client` files the read in the client folder's `hybrid/`, where every
later run of that client picks it up through the same checks. The hybrid scorecard says when Active Directory was
read. A domain controller has everything the script needs; a workstation needs the Active Directory and Group Policy
RSAT tools (on Windows Server: `Install-WindowsFeature GPMC`; on Windows 10 or 11:
`Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0`, then a new PowerShell window),
and without Group Policy the GPO checks are reported as not evaluated. The LAPS check reads the schema first, so an
unextended schema is reported, not an error.

## 4a. SharePoint without full control

Out of the box the SharePoint checks read Graph's read-only SharePoint settings, and the report names each check that
needs more. For the rest, the SharePoint admin read, pick one:

- Grant the TenantKeep Posture for SharePoint app to the admins who run the report
  (`deploy/setup/Grant-PostureSharePointAccess.ps1`, docs/collection.md); Start-PostureRun then signs in to it as
  well. It is never consented for the organisation, and only assigned admins can sign in to it.
- Or run Get-SpoBaseline.ps1 on a Windows machine (a cloud PC is fine) as the SharePoint admin, on Microsoft's own
  SharePoint shell with no third-party app, and bring the folder into the run. The script ships with the module:

  ```powershell
  Export-PostureCollector -Kind SharePoint -Run ~/tenantkeep/evidence/20261120-0957   # RUN-ME.txt has the command, with the tenant filled in
  Import-PostureEvidence -Path ./spo-baseline-20261120-1015 -Run ~/tenantkeep/evidence/20261120-0957   # rebuilds the report
  ```

  This goes into one run on purpose: sharing settings change, so a later run should not quietly reuse an old read.

## 5. The same run, step by step

`Start-PostureRun` is `Connect-PostureSession`, `Invoke-PostureCollection`, `New-PostureProfile`, `New-PostureReport`
and `Export-PostureFindings` in order. Each is a cmdlet you can run alone; sections 6 to 9 say what each does and the
switches it takes. Section 11 has the fully manual path, with a sign-in per service and no Kainor app involved.

## 6. Build the profile

`Start-PostureRun` writes the profile from discovery alone. Run the wizard to answer the rest: discovery reads what the tenant says about itself and it
asks only what evidence cannot answer: third-party controls, thresholds, break-glass accounts and their last test,
the Message Center owner, frameworks, audience, cadence.

```powershell
New-PostureProfile -Path ~/tenantkeep/clients/contoso/profile.json -Evidence $folder
```

Rerun it after any change; `-AskAll` re-asks the discovered questions too. The profile is plain JSON and the keys are
explained in docs/profile.md.

## 7. Evaluate and report

```powershell
New-PostureReport -Evidence $folder -Client ~/tenantkeep/clients/contoso
```

Writes report.html (self-contained, interactive), report.md and checks.json into the folder. Pick a baseline with
`-Baseline nist-csf-2` (or iso-27001-2022, nist-800-171, cmmc-2, cisa-scuba, hipaa, copilot-readiness) to narrow the
checks and add the crosswalk appendix. Add `-Format Pdf` for a PDF through a headless Edge or Chrome.

<div class="shots">
  <figure class="shot wide"><a href="https://tenantkeep.app/posture/sample-report/#recommendations"><img src="https://tenantkeep.app/assets/posture/report-recommendations.jpg" width="1400" height="940" loading="lazy" alt="The Recommendations view: Do Today, a list of quick fixes with their severity and what users will notice."></a><figcaption>Recommendations: what to fix, most urgent first, starting with the fixes users will not notice.</figcaption></figure>
</div>

<div class="shots">
  <figure class="shot wide"><a href="https://tenantkeep.app/posture/sample-report/#domains"><img src="https://tenantkeep.app/assets/posture/report-domains.jpg" width="1400" height="940" loading="lazy" alt="The Domains view: a scorecard for each area, with how many checks pass, fail, are accepted or covered."></a><figcaption>Domains: a score for each area, and the checks behind it.</figcaption></figure>
</div>


The ATT&CK Coverage view lays the run over MITRE ATT&CK: under each tactic, the techniques the checks address, each a
gap (a check for it fails), accepted risk, covered (its checks pass) or not checked (no check for it could be
evaluated). Checks the profile rules out are left out, so a cloud-only tenant sees no Kerberos techniques. Covered
lowers the risk; it does not prove a technique cannot be used. Finding cards, findings.csv, findings.json and report.md
carry each check's technique ids.

<div class="shots">
  <figure class="shot wide"><a href="https://tenantkeep.app/posture/sample-report/#attack"><img src="https://tenantkeep.app/assets/posture/report-attack.jpg" width="1400" height="940" loading="lazy" alt="The ATT&CK Coverage view: techniques under each tactic, marked as a gap, accepted, covered or not checked."></a><figcaption>ATT&amp;CK Coverage: the techniques the checks address, tactic by tactic.</figcaption></figure>
</div>

Three more views are built from the same evidence: who holds which role and how they sign in, whether the tenant is ready for Copilot, and what the tenant contains.

<div class="shots">
  <figure class="shot wide"><a href="https://tenantkeep.app/posture/sample-report/#admins"><img src="https://tenantkeep.app/assets/posture/report-admins.jpg" width="1400" height="940" loading="lazy" alt="Your Administrators: each role holder with permanent and eligible roles, strongest sign-in method and last sign-in."></a><figcaption>Your Administrators: every role holder, how each signs in, and when they last did.</figcaption></figure>
</div>

<div class="shots">
  <figure class="shot wide"><a href="https://tenantkeep.app/posture/sample-report/#copilot"><img src="https://tenantkeep.app/assets/posture/report-copilot.jpg" width="1400" height="940" loading="lazy" alt="The Copilot Readiness view: gates for oversharing, labelling and governance, each open or closed."></a><figcaption>Copilot Readiness: the gates to pass before Copilot reaches your data.</figcaption></figure>
</div>

<div class="shots">
  <figure class="shot wide"><a href="https://tenantkeep.app/posture/sample-report/#ca"><img src="https://tenantkeep.app/assets/posture/report-ca.jpg" width="1400" height="940" loading="lazy" alt="The Conditional Access view: a matrix of policies against who and what each applies to."></a><figcaption>Conditional Access: every policy against who it applies to, and what it asks of them.</figcaption></figure>
</div>

<div class="shots">
  <figure class="shot wide"><a href="https://tenantkeep.app/posture/sample-report/#inventory"><img src="https://tenantkeep.app/assets/posture/report-inventory.jpg" width="1400" height="940" loading="lazy" alt="The Inventory view: counts and lists of what the tenant holds, from policies to connectors."></a><figcaption>Inventory: what the tenant holds, as lists you can read and search.</figcaption></figure>
</div>


## 8. Work the findings

report.html opens in any browser and changes nothing: select a check for what was found, why it matters, how to fix
it and the affected objects, with links to the portal page and Microsoft Learn. findings.csv in the run folder is the
same list as a spreadsheet, most severe first, rebuilt on every run for whoever tracks remediation in their own tool:

```powershell
Export-PostureFindings -Path $folder
```

<div class="shots">
  <figure class="shot wide"><a href="https://tenantkeep.app/posture/sample-report/#checks"><img src="https://tenantkeep.app/assets/posture/report-checks.jpg" width="1400" height="940" loading="lazy" alt="The Checks Explorer: every check with its domain, title, status, severity and how many objects it affects, with filters above."></a><figcaption>Checks Explorer: every check, filtered by status, domain or severity. Select one for what was found and how to fix it.</figcaption></figure>
</div>


Two views in Recommendations answer two different questions. The Roadmap lanes sort the findings by risk and effort:
what matters most. The Remediation Plan under them puts the work in order: the checks are grouped into projects, and a
flow chart shows which projects can start now, side by side, and which wait on another, with a solid arrow where one
is needed first and a dashed one where it is only better to wait. The same plan is written out below the chart with
the reason for each wait and the checks each project fixes. Highest Risk Only dims everything but the critical and
high risk projects. The order is a recommendation, and a project that waits on something the run could not read says
so.

Microsoft's own list sits beside this one. Under Operations, Top Secure Score Improvements shows the ten actions worth
the most points, and "All open Secure Score actions, by product" under it opens every action Microsoft still scores as
open in the tenant, including products this report cannot read a setting from (Defender for Cloud Apps, for one). The
last column opens the check here that judges the same setting, with its answer; an action with none is marked
Microsoft's only, and its link goes to Microsoft's page for it.

## 8a. Accepting a risk

When a failing check is a decision rather than a gap, accept it. In the report, select the check: Accept This Risk
shows the command for the whole check or for one affected object, with a Copy button. Paste it into PowerShell:

```powershell
Add-PostureException -TenantId 00000000-0000-0000-0000-000000000000 -Check 'EM-016' -Object 'payroll@contoso.example'
```

It asks why the risk is accepted, who owns it, who approved it and until when (a year by default), writes
exceptions.json in the client folder, and rebuilds the newest report from the same evidence in a few seconds, with no
sign-in. Refresh the page and the check reads as accepted. It fails again on its expiry date until someone decides
again. Nothing is saved in the browser and nothing is written to the tenant.

`Add-PostureException -TenantId <id>` with no check lists the newest run's failures to pick from.
`Get-PostureException` lists what is accepted and what has expired; `Remove-PostureException -Check <id>` withdraws
one (each accepted risk in the report has its own copy-ready command), and `-Expired` clears every lapsed entry.
The tenant id finds the client folder whose profile.json names it; `-Client <folder>` works instead.

For Automation-produced reports, copy exceptions.json to the deployment's `client` container (`az storage blob
upload`), or pass the folder to `deploy.ps1 -ClientFolder` again.

## 8b. Reports and reviews you provide

**Anyone links, organization-wide links and Everyone grants per site** come from SharePoint Advanced Management's
site permissions report, which no API reads and which the module will not start (starting it is a job on
Microsoft's side). Before or after a run, an admin with SharePoint Administrator or SharePoint Advanced Management
Administrator runs it: SharePoint admin center, Reports, Data access governance, Site permissions across your
organization, Run report for SharePoint and again for OneDrive. The first run can take up to five days, later ones
a day; it can run once every 30 days and needs SAM, which any Microsoft 365 Copilot licence in the tenant includes.
Download the CSVs, then:

```powershell
Import-PostureSharingReport -TenantId 00000000-0000-0000-0000-000000000000 -Path ~/Downloads/SharePoint.csv, ~/Downloads/OneDrive.csv
```

It checks each file is that report and belongs to the tenant, files it in `imports/sam-dag/`, adds the totals and the
most exposed sites to the newest run (check CL-015) and rebuilds the report. Later runs read the newest files on
their own. Without a report, CL-015 says what to do instead of reading zero; its panel copies the command.

A few Copilot readiness gates have no API behind them. Their check panels say exactly what to provide and link to the
portal page: the data access governance CSV reports go into `imports/sam-dag/` in the client folder, and the portal
reviews (DSPM for AI, Copilot settings, site access reviews) are dates: the check's panel copies the
`Set-PostureAttestation -TenantId <id> -Key <key>` command that records today and rebuilds the report. Both count on
the next run.

## 8c. When part of a run fails

Right after the sign-in, the run checks your account's directory roles against what each domain needs and prints
one line per domain: covered, missing (with the role to grant), or checked when it connects (Exchange and Purview
role groups and Azure roles, which Graph cannot see). PIM roles count once activated. The run goes on either way.

The report's overview opens with what the assessment still lacks, when it lacks anything: one row for each missing
piece (the Active Directory read, the SharePoint admin read, the site permissions report, a domain that was skipped,
steps that failed), with how many checks wait for it, who can add it, where, the command, and the command that
brings it back. The run prints the same rows when it ends. A site permissions report can also just be saved into the
client folder's `imports/`: the next run checks it is that report and this tenant's, and files it.

Run Health opens with every source an assessment can draw on and where the run stands with each: collected (and
how many files), not collected (the Overview's "To Complete This Assessment" then says who can add it and how), or
not needed here, with the kind of tenant that would need it. The on-premises domain and the SharePoint site
permissions report are the two that are collected somewhere else and brought in; a tenant that needs neither is
told so, not left to wonder.

<div class="shots">
  <figure class="shot wide"><a href="https://tenantkeep.app/posture/sample-report/#health"><img src="https://tenantkeep.app/assets/posture/report-health.jpg" width="1400" height="940" loading="lazy" alt="The Run Health view: each source of evidence and whether it was collected, with the steps that failed and why."></a><figcaption>Run Health: what was collected, what was not, and what each failed step needs.</figcaption></figure>
</div>


A step that fails is recorded with its cause: needs a role, needs a licence, sign-in ran out, throttled, network,
not readable with this sign-in, or not set up in this tenant. The console ends with the failures grouped by cause and what to do, the report opens
with a banner, and its Run Health view lists each step with the role, delegated permission or licence it needs
(from the module's requirements.json) and Microsoft's own message. Microsoft answers "forbidden" both for a missing
permission and for a missing role, so the run records which of the step's permissions the sign-in carried. A step
that lacked one reads "Needs a permission" and links to where a Global Administrator approves the app again; a step
that had them all is told which roles to grant. Checks that depend on a failed step say not evaluated, never pass
or fail.

After granting what was missing, collect only what failed, into the same run:

```powershell
Resume-PostureRun                      # the newest run
Resume-PostureRun -Client contoso      # the newest run of one client, when there are several
```

It reads the run's plan (run.json), collects again each domain that did not finish or had a failure a second attempt
can fix, leaves the facts about the tenant (not licensed, not set up) alone, and rebuilds the report in the same
folder. A domain is collected again whole, since later steps use what earlier ones read; every other file stays.
A run that stopped part way (the machine slept, the window was closed, the process was killed) resumes the same
way: the run's journal says which domains finished, and only the one it stopped in and the ones after it are
collected. Run Health says where it stopped. A file left from an earlier attempt, whose step ran again and could
not write it, is not read: the checks that need it say not evaluated.

A long run can outlast its sign-in. Admin accounts often have a Conditional Access sign-in frequency of a few hours,
and past it Microsoft refuses every renewal until the admin signs in again. The run says so before the long reads
start, from the Conditional Access snapshot it has just taken: "Sign-in frequency: the Conditional Access policy
'Admins, 4 hours' asks this account to sign in again every 4 hours." When that moment comes and someone is at the
console, the run pauses, asks the same account to sign in again (a device code, or the browser, as the run began),
and repeats the request it was making; the new sign-in must be the same account in the same tenant. When no one
signs in within fifteen minutes, or the run has no console, it stops there once: the steps that depend on the
sign-in are not attempted, each domain gets one line saying how many, and Resume-PostureRun carries on after a new
sign-in.

The long lists are not read twice. When a domain is collected again in the same run, a list that already finished
(users, authentication registration, groups, devices, mailboxes, sites) is kept, and the console says so: "Users
kept, read 2026-11-21 09:40 UTC". A list that stopped part way (the sign-in ended, the network dropped) carries on
from the page it had reached. Both hold for a day; after that, or when what the list depends on has changed (who
holds a role, the number of days that count as stale), the list is read again. To read everything again, start a
new run.
A failure that needs a licence or role the tenant does not have (a Purview feature Business Premium leaves out,
for example) is left alone, since collecting again would say the same; after granting it, `-Collector Purview`
names that domain. `-Path <run folder>` resumes an older run. The Run Health view copies the exact command.

When a failure needs someone else to look at it, Run Health has a Copy for Support button on each failure (and one
for all of them): a block of text with the module, PowerShell and OS versions, the step and its cause, the request it
was making, Microsoft's message and where in the module it stopped, with names, addresses and ids taken out. For the
whole run's logs at once:

```powershell
Export-PostureDiagnostics -Run ~/tenantkeep/evidence/20261120-0957
```

It writes `share/diagnostics-<stamp>.zip` in the run folder: summary.txt with every failure, plus errors, run plan,
call ledger, collection record and transcript, each redacted the same way. No evidence, report, checks or redaction
key goes in. Read summary.txt before sending; the redaction is by pattern and by the names the run knows.

## 8d. For tools and AI

findings.json at the top of the run is the assessment as one document: a summary, then every failing check ranked
(severity, then how many objects it affects) with what was found, why it matters, how to fix it, the portal and Learn
links, the licence it needs and up to 25 affected objects, plus accepted risks and what could not be evaluated. Its
"about" field explains the shape to whoever reads it. report.md starts with the same ranked list, and report.html
carries the same JSON, so any of the three can be handed to an AI model.

Before handing a report to an AI service or anyone outside, run with `-Redact` (on Start-PostureRun or
New-PostureReport): share/ gets copies with email addresses, sign-in names, SharePoint addresses, IP addresses and the
names of affected accounts, devices and sites replaced by placeholders (user-003, site-014), the same placeholder for
the same value throughout. logs/redaction-key.csv maps them back; keep it. Replacement is by pattern and by the names
the report lists, so read the copy before sending it.

## 8e. The licence recommendation

The Licensing view says which goals the licences cover, and for the rest it recommends one combination: licences to
add to what the tenant holds, or a suite to move to with the add-ons it still needs. Each licence comes with the
reason it is there: the goals it covers, what it brings, and when another licence in the combination needs it first
(ID Governance needs Entra ID P1). It also says what a move takes the place of, what stays, what overlaps with a
product named in the profile's `thirdParty`, and which licences the tenant holds today where one includes all of
another.

<div class="shots">
  <figure class="shot wide"><a href="https://tenantkeep.app/posture/sample-report/#licensing"><img src="https://tenantkeep.app/assets/posture/report-licensing.jpg" width="1400" height="940" loading="lazy" alt="The Licensing view: what to add for the chosen goals, the seats assigned per licence, and the features owned."></a><figcaption>Licensing: the goals the licences cover, and what to add for the rest.</figcaption></figure>
</div>


Beside the recommended combination the view lists up to two others that cover the same goals: Microsoft 365 E7
beside E5 with its add-ons, or a suite beside the add-ons that would do the same on the one you hold. The report does
not say which is the better buy. Take them to your Microsoft partner and compare. They are listed in the order the
rules below give, never by price, and a move that would take away something you have today is not offered.

How the one combination is chosen. Every combination that works is built from the rules in `licensing/`: it covers
every chosen goal, brings what its own licences need first, and takes away no goal the tenant meets today. Then:

- **On function alone**, which is what every run does unless you give it prices: first, nothing nobody asked for.
  A suite is made of products (Microsoft 365 E7 is E5 with Copilot, Entra Suite and Agent 365), and a suite that
  would bring a product the tenant neither holds nor needs for a chosen goal is passed over when something else
  does the job, so two gaps are not answered with E7. Then the fewest licences, then keeping the suite the tenant
  holds, then the least overlap with other products.
- **With a price file of your own**, the lowest total for a user, then the same order. Only when every licence in the
  comparison has a price; if one is missing the whole choice goes back to function, and the run tells you which.

The module ships no prices and fetches none. A Microsoft partner's price sheet is confidential, so it stays where you
keep it and is read from there:

```powershell
New-PostureReport -Evidence ~/tenantkeep/evidence/20261120-0957 -PriceFile ~/pricing/data/licenses.csv
$env:TENANTKEEP_PRICE_FILE = "$HOME/pricing/data/licenses.csv"     # or once, in your PowerShell profile, for every run
```

The file is a CSV. These columns are read; others are ignored, a partner's own price among them:

| Column | What |
|---|---|
| `ProductName` | Microsoft's name for the licence |
| `PartNumber` | Optional. The SKU part number (`SPE_E5`), for a licence whose name in the sheet differs |
| `Term`, `BillingCycle` | `P1M`, `P1Y`, `P3Y`; `Monthly`, `Annual`, `Triennial`. Only rows of the assumed pair are used, so every figure compared is in the same unit |
| `Erp` | What a customer pays for one user |
| `EffectiveDate` | `yyyy-MM-dd`. The latest row that has taken effect is the one used |
| `Market`, `Currency` | Optional. Rows of another market or currency than the file's own record are skipped |

Beside it, `licenses.meta.json` may say when the sheet was last checked and what to assume:
`{ "checkedUtc": "2026-11-22T09:17:00Z", "market": "US", "currency": "USD", "assume": { "term": "P1Y", "billingCycle": "Monthly" } }`.
Without it the term is one year billed monthly and the age is unknown.

What is written where:

- **In every report** (HTML, Markdown, findings.json, the redacted copies): the recommended combination and its
  reasons. No amount, no total, no comparison between combinations, and no word about what anything is worth. The
  page recomputes on function alone when a reader ticks other goals, because it holds no figures to choose with, and
  goes back to the report's own answer when the reader returns to the starting choices.
- **For you only**: the console says which file was used, when it was last checked, the market and term assumed, how
  many licences had a figure, whether the choice used them, and warns when the sheet was last checked more than 35
  days ago. A run folder keeps the same in `logs/licensing-basis.json`. With `-OutputPath` everything lands in one
  folder that may be handed on, so there it is the console only.

Not licensing advice: it is a starting point to take to a Microsoft partner, who confirms eligibility and terms.

## 9. Next run, and the trend

```powershell
New-PostureReport -Evidence $newFolder -Client ~/tenantkeep/clients/contoso -Previous $folder
```

The Trend view shows the score and domain deltas, the checks that started or stopped failing, and the affected counts
that moved. Two things it keeps apart from those. A check that had an answer before and could not be judged this
time is listed under "No answer in this run": it is neither a fix nor a failure. And when the module was updated
between the two runs and the check catalog changed with it, the view says so, and lists the results that moved
because a check changed under "Changed with the catalog", each with what changed. The Conditional Access snapshot in each folder also feeds Compare-PostureCaSnapshot for a policy-level
diff, and the scheduled cycle in deploy/schedules runs that nightly with a Teams or email alert.

<div class="shots">
  <figure class="shot wide"><img src="https://tenantkeep.app/assets/posture/report-trend.jpg" width="1400" height="940" loading="lazy" alt="The Trend view: the score before and after, three checks that started failing, six resolved, and the affected counts that moved."><figcaption>Trend, three months on: what was fixed, what slipped, and what moved. The sample report is a first run, so this picture comes from a second run of the same made-up tenant.</figcaption></figure>
</div>

## 9a. Without Azure

Not every organisation has, or wants, anything in Azure. Local runs need no Azure at all: with `azure: none` in the
profile (the wizard sets it when no subscription is in scope) the Azure collector is skipped and the Azure domain
reads as not applicable. Nothing is installed in the tenant beyond the consent to the TenantKeep app. What does need
an Azure subscription is the scheduled cycle, because the Automation account is where it runs; the full inventory of
what that puts where is in docs/footprint.md. For a nightly Conditional Access cycle without Azure, the GitHub Action
and launchd samples in deploy/schedules run it from a machine you already have.

## 9b. Power Platform and Power BI

These checks are optional, and each product is approved from a link of its own; nothing approved earlier is asked for
again. Power BI has a read-only permission, Tenant.Read.All, which goes on the TenantKeep app. Power Platform has
none, so its permission goes on the second app, the one Azure and Teams are read through. A run in a tenant that has
not approved one says so under what it skipped, gives the link for it, and collects everything else.

The account that signs in needs a role each product accepts, and neither has a read-only one for these settings:

- **Power BI:** Fabric Administrator, on an account with a Power BI or Fabric licence (the free Microsoft Fabric licence
  counts) that has opened the Power BI portal once.
- **Power Platform:** Power Platform Administrator.

Global Administrator covers both. With PIM, activate the role before the run. A scheduled run can read Power BI
(docs/scheduling.md says how, with no role granted) and never reads Power Platform. To collect only these two into
a run you already have:

```powershell
Resume-PostureRun -Path <run folder> -Collector PowerBI, PowerPlatform
```

## 10. Unattended, in the customer's Azure

deploy/automation deploys an Automation account with a managed identity that runs the Conditional Access cycle nightly
and, with -IncludePosture, the whole posture report monthly: every collector, the trend, the findings list, with no
sign-in by anyone. docs/scheduling.md walks through it. Set the execution policy to AllSigned on anything that runs the module
unattended: releases are Authenticode-signed, so an edited file refuses to run. The full posture collection on a schedule and the Marketplace listing
follow.

## 11. Without the Kainor app: a sign-in per service

Some organisations consent to no third-party app, published or not. The module works the same way with your own
sessions; `Invoke-PostureCollection` uses whatever is open and says what is not.

Register an app of your own for SharePoint (PnP.PowerShell needs an app id to sign the admin in) and record it in
the profile:

```powershell
Connect-MgGraph -TenantId <tenant id> -Scopes Application.ReadWrite.All, DelegatedPermissionGrant.ReadWrite.All
./deploy/setup/New-PostureSharePointApp.ps1 -Tenant contoso.onmicrosoft.com -ProfilePath ~/tenantkeep/clients/contoso/profile.json
```

Then sign in to each service you want collected. Graph first; on macOS import PnP and Az only after that.

```powershell
Connect-MgGraph -TenantId <tenant id> -Scopes <the scopes in docs/collection.md> -NoWelcome
Connect-PnPOnline -Url https://contoso-admin.sharepoint.com -ClientId <sharePointClientId> -Interactive
Connect-MicrosoftTeams
Connect-AzAccount -Tenant <tenant id>
$folder = Invoke-PostureCollection -OutRoot ~/tenantkeep/evidence
```

Exchange Online and Purview run in processes of their own (their cmdlet names overlap), each after its own sign-in,
writing into the same folder:

```powershell
Connect-ExchangeOnline -UserPrincipalName <reader>
Invoke-PostureCollection -Collector Exchange -SkipCaSnapshot -OutputFolder $folder
Connect-IPPSSession -UserPrincipalName <reader>
Invoke-PostureCollection -Collector Purview -SkipCaSnapshot -OutputFolder $folder
```

The macOS sign-in workarounds are in docs/collection.md. Copy the AD collector's files into `$folder` for hybrid
tenants, then continue at section 6. Or sign in once with a registration of your own that carries the same delegated
permissions as app.json: `Connect-PostureSession -ClientId <your app id>` and `Start-PostureRun` from there
(`Connect-PostureSession -Services -ClientId <id>` for one of your own with the permissions app-services.json lists).
