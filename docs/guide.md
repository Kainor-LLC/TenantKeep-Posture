# Using Tenantkeep Posture, step by step

Written for the administrator or MSP engineer who runs the report. Everything below reads the tenant; nothing in the
module writes to it. Each run leaves an evidence folder you keep, a report you deliver, and a findings register you
work from until the next run.

## 1. Two lines

```powershell
Install-Module Tenantkeep.Posture -Scope CurrentUser
Start-PostureRun
```

A browser window asks you to sign in with an admin account. That is the only sign-in. The module gets a token for
each service from it, runs every collector it can, builds the profile from what the tenant says about itself, writes
the report and opens it. Twenty minutes later for a mid-sized tenant you are looking at report.html. Until the module
is on the PowerShell Gallery, clone the repository and `Import-Module ./tenantkeep-posture/Tenantkeep.Posture/Tenantkeep.Posture.psd1`
instead of the first line.

What you need:

- PowerShell 7.4 or later on macOS, Windows or Linux, and Microsoft.Graph.Authentication. For the other domains,
  the modules you already use: ExchangeOnlineManagement (Exchange and Purview), PnP.PowerShell (SharePoint),
  MicrosoftTeams, Az.Accounts with Az.ResourceGraph (Azure). A missing module is skipped with the install line.
  `Get-PostureRequirement` lists what is installed against the versions the collectors were tested with
  (Graph 2.39, Exchange 3.10, PnP 3.2, Teams 7.9, Az.Accounts 5.5, Az.ResourceGraph 1.3 as of October 2026); an
  older version runs with a warning, and every run records the versions it used in collection.json. PnP.PowerShell
  2.12.0 is known to work except for the restricted search read behind the Copilot gate C9.
- An account that can read: Global Reader covers Entra, Intune and Defender; Exchange needs View-Only Organization
  Management; SharePoint needs SharePoint Administrator; Purview a compliance read role; Azure Reader and Security
  Reader on the subscriptions. The module never reads more than the account can.
- Consent, once per tenant. Tenantkeep Posture is a multi-tenant app published by Kainor with delegated, read-only
  permissions (the list is in the module's app.json and on the consent screen). The first run in a tenant that has
  not consented stops and prints the admin consent link; an admin clicks it once, then runs the command again.
- Purview is the one service with a second sign-in. Security and Compliance PowerShell issues no token to a
  third-party app, so when the Purview collector runs, the Exchange module opens its own window for the same admin
  (a device code with `-DeviceCode` or `-NoBrowser`). Everything else comes from the one sign-in.
- Conditional Access. A policy that blocks sign-ins to unapproved apps, or requires a compliant device, stops the run
  with the app id in the message. Allow the app or exclude the admin running the report; the module works around
  nothing.

Useful switches: `-TenantId` refuses a sign-in to any other tenant; `-Collector Entra, Intune, Exchange` runs a
subset; `-DeviceCode` signs in from a machine without a browser; `-Client` points at a client folder other than the
default `~/tenantkeep/clients/<tenant name>/`.

## 2. The licence

The Conditional Access tools are free. The full report needs the licence file Kainor sent for your tenant: save it as
`tenantkeep.lic` in the client folder next to profile.json, and `Get-PostureLicense -Path <file>` tells you its tier and
expiry. docs/licensing.md explains what is checked (offline, nothing is sent). Without it, `Start-PostureRun` still
produces the Conditional Access domain and says what the full tier adds.

## 3. What the run leaves behind

- `~/tenantkeep/evidence/<yyyyMMdd-HHmm>/`: the evidence files, checks.json, report.html, report.md, findings.csv.
- `~/tenantkeep/clients/<tenant name>/`: profile.json (discovered on the first run, yours to edit in the report's
  Settings view), exceptions.json and findings.csv once you save from the report, tenantkeep.lic, imports/ for the
  reports you provide (section 8b), hybrid/ for the Windows AD collector's files.

Nothing is written anywhere else. Nothing leaves the machine.

## 4. Hybrid tenants

Run collectors/windows/Get-ADBaseline.ps1 once on a domain-joined Windows machine with RSAT and copy the files it
wrote into the client folder's `hybrid/`; every later run picks them up. A domain controller has everything the
script needs; a workstation needs the Active Directory and Group Policy RSAT tools (on Windows Server:
`Install-WindowsFeature GPMC`; on Windows 10 or 11: `Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0`,
then a new PowerShell window), and without Group Policy the GPO checks are reported as not evaluated. The LAPS check
reads the schema first, so an unextended schema is reported, not an error.

## 5. The same run, step by step

`Start-PostureRun` is `Connect-PostureSession`, `Invoke-PostureCollection`, `New-PostureProfile`, `New-PostureReport`
and `Export-PostureFindings` in order. Each is a cmdlet you can run alone; sections 6 to 9 say what each does and the
switches it takes. Section 11 has the fully manual path, with a sign-in per service and no Kainor app involved.

## 6. Build the profile

`Start-PostureRun` writes the profile from discovery alone and leaves every question to the report's Settings view.
Run the wizard when you would rather answer at the console: discovery reads what the tenant says about itself and it
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

## 8. Work the findings in the report

Open report.html in Edge or Chrome. The Risk Register view lists every failing and accepted check with owner, status,
effort, dependency and notes; a check's detail panel has the exception form (scope, justification, owner, approver,
expiry). Recording an exception re-scores the page at once. Settings holds the tenant profile: thresholds, third-party
controls, break-glass accounts, frameworks, audience.

The save bar at the bottom of every view holds Choose Client Folder and Save. Recording an exception asks for the
folder if none is chosen yet. Save writes exceptions.json, findings.csv and profile.json into that folder, merging
with what is already there, and reads them back before it reports success. The next run reads them, so exceptions and owners survive every rerun.
Safari and Firefox cannot write folders; there Save downloads the files to move into the client folder by hand.
Profile changes apply on the next run; the page says so.

For Automation-produced reports, save locally and copy the three files to the deployment's `client` container
(`az storage blob upload`), or pass the folder to `deploy.ps1 -ClientFolder` again.

## 8a. Export the register by hand

```powershell
Export-PostureFindings -Path $folder -Merge ~/tenantkeep/clients/contoso/findings.csv -OutputPath ~/tenantkeep/clients/contoso/findings.csv
```

One row per failing check in the audit plan's register format. Owners and statuses you type into the register survive
the next export by check id. Accepted risks go into exceptions.json with an owner, approver and expiry; the next run
marks them as accepted instead of failed.

## 8b. Reports and reviews you provide

A few Copilot readiness gates have no API behind them. Their check panels say exactly what to provide and link to the
portal page: the data access governance CSV reports go into `imports/sam-dag/` in the client folder (the panel's Add
Report Files button copies them there), and the portal reviews (DSPM for AI, Copilot settings, site access reviews)
are dates you record in the panel or on the Settings view. Both count on the next run.

## 9. Next run, and the trend

```powershell
New-PostureReport -Evidence $newFolder -Client ~/tenantkeep/clients/contoso -Previous $folder
```

The Trend view shows the score and domain deltas, the checks that started or stopped failing, and the affected counts
that moved. The Conditional Access snapshot in each folder also feeds Compare-PostureCaSnapshot for a policy-level
diff, and the scheduled cycle in deploy/schedules runs that nightly with a Teams or email alert.

## 9a. Without Azure

Not every organisation has, or wants, anything in Azure. Local runs need no Azure at all: with `azure: none` in the
profile (the wizard sets it when no subscription is in scope) the Azure collector is skipped and the Azure domain
reads as not applicable. Nothing is installed in the tenant beyond the consent to the Tenantkeep Posture app. What does need
an Azure subscription is the scheduled cycle, because the Automation account is where it runs; the full inventory of
what that puts where is in docs/footprint.md. For a nightly Conditional Access cycle without Azure, the GitHub Action
and launchd samples in deploy/schedules run it from a machine you already have.

## 10. Unattended, in the customer's Azure

deploy/automation deploys an Automation account with a managed identity that runs the Conditional Access cycle nightly
and, with -IncludePosture, the whole posture report monthly: every collector, the trend, the findings register, with no
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
permissions as app.json: `Connect-PostureSession -ClientId <your app id>` and `Start-PostureRun` from there.
