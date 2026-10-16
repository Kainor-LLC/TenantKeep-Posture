# Using Tenantkeep Posture, step by step

Written for the administrator or MSP engineer who runs the report. Everything below reads the tenant; nothing in the
module writes to it. Each run leaves an evidence folder you keep, a report you deliver, and a findings register you
work from until the next run.

## 1. What you need

- PowerShell 7.4 or later on macOS, Windows or Linux.
- The modules: Microsoft.Graph.Authentication (required), and for the domains you want: ExchangeOnlineManagement,
  PnP.PowerShell, MicrosoftTeams, Az.Accounts and Az.ResourceGraph.
- An account that can read: Global Reader covers most of Entra, Intune and Defender; Exchange needs View-Only
  Organization Management; SharePoint needs SharePoint Administrator; Purview needs Compliance Administrator or Global
  Reader; Azure needs Reader and Security Reader on the subscriptions. The Graph scopes are listed in docs/collection.md.
- One Entra app registration for SharePoint, created once by deploy/setup/New-PostureSharePointApp.ps1 (step 3).

## 2. Install the module and place the licence

The Conditional Access tools are free. The full report needs the licence file Kainor sent for your tenant: save it as
`tenantkeep.lic` in the client folder next to profile.json, and `Get-PostureLicense -Path <file>` tells you its tier and
expiry. docs/licensing.md explains what is checked (offline, nothing is sent).

## 2a. Install the module

```powershell
git clone https://github.com/kainorllc/tenantkeep-posture
Import-Module ./tenantkeep-posture/Tenantkeep.Posture/Tenantkeep.Posture.psd1
```

Signed releases come from the PowerShell Gallery once published; the repository works as is.

## 3. One-time setup per tenant

Register the SharePoint app with delegated read permissions, consent to it, and record its id in the profile:

```powershell
Connect-MgGraph -TenantId <tenant id> -Scopes Application.ReadWrite.All, DelegatedPermissionGrant.ReadWrite.All
./deploy/setup/New-PostureSharePointApp.ps1 -Tenant contoso.onmicrosoft.com -ProfilePath ~/tenantkeep/clients/contoso/profile.json
```

The script prints what, if anything, is left by hand: the SharePoint Administrator role for the reading account.

## 4. Sign in

Sign in to each service you want collected. Graph first; on macOS import PnP and Az only after that.

```powershell
Connect-MgGraph -TenantId <tenant id> -Scopes <the scopes in docs/collection.md> -NoWelcome
Connect-PnPOnline -Url https://contoso-admin.sharepoint.com -ClientId <sharePointClientId> -Interactive
Connect-MicrosoftTeams
Connect-AzAccount -Tenant <tenant id>
```

Exchange Online and Purview run in processes of their own (their cmdlet names overlap), each after its own sign-in:
`Connect-ExchangeOnline -UserPrincipalName <reader>` and `Connect-IPPSSession -UserPrincipalName <reader>`. The
macOS sign-in workarounds are in docs/collection.md.

## 5. Collect

```powershell
$folder = Invoke-PostureCollection -OutRoot ~/tenantkeep/evidence
```

Every collector whose session is open runs; the others are skipped with a warning. Exchange, Purview and (if run
separately) Azure write into the same folder from their own processes:

```powershell
Invoke-PostureCollection -Collector Exchange -SkipCaSnapshot -OutputFolder $folder
Invoke-PostureCollection -Collector Purview -SkipCaSnapshot -OutputFolder $folder
```

For hybrid tenants, run collectors/windows/Get-ADBaseline.ps1 once on a domain-joined Windows machine with RSAT and
copy the files it wrote into `$folder` (not as a subfolder). A domain controller has everything the script needs; a
workstation needs the Active Directory and Group Policy RSAT tools (on Windows Server: `Install-WindowsFeature GPMC`; on
Windows 10 or 11: `Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0`, then a new
PowerShell window), and without Group Policy the GPO checks are reported as not evaluated. The LAPS check reads the schema first, so an unextended schema is reported, not an error.

## 6. Build the profile

Discovery reads what the tenant says about itself; the wizard asks only what evidence cannot answer: third-party
controls, thresholds, break-glass accounts and their last test, the Message Center owner, frameworks, audience,
cadence.

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

Choose Client Folder once per session, then Save writes exceptions.json, findings.csv and profile.json into that
folder, merging with what is already there. The next run reads them, so exceptions and owners survive every rerun.
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

## 9. Next run, and the trend

```powershell
New-PostureReport -Evidence $newFolder -Client ~/tenantkeep/clients/contoso -Previous $folder
```

The Trend view shows the score and domain deltas, the checks that started or stopped failing, and the affected counts
that moved. The Conditional Access snapshot in each folder also feeds Compare-PostureCaSnapshot for a policy-level
diff, and the scheduled cycle in deploy/schedules runs that nightly with a Teams or email alert.

## 10. Unattended, in the customer's Azure

deploy/automation deploys an Automation account with a managed identity that runs the Conditional Access cycle nightly
and, with -IncludePosture, the whole posture report monthly: every collector, the trend, the findings register, with no
sign-in by anyone. docs/scheduling.md walks through it. Set the execution policy to AllSigned on anything that runs the module
unattended: releases are Authenticode-signed, so an edited file refuses to run. The full posture collection on a schedule and the Marketplace listing
follow.
