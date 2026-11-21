# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Export-PostureCollector {
    <#
    .SYNOPSIS
        Writes one of the two Windows collectors to a folder you can carry to the Windows machine it runs on, with a
        RUN-ME.txt that gives the exact command for this run's tenant and the command that brings the result back.
    .DESCRIPTION
        Two parts of an assessment are read on a Windows machine, by someone with the right access there, outside the
        main run:
          - ActiveDirectory: Get-ADBaseline.ps1, on a domain-joined machine with the Active Directory tools.
          - SharePoint: Get-SpoBaseline.ps1, the SharePoint admin read on Microsoft's own SharePoint Online
            Management Shell, for a tenant that does not grant the TenantKeep Posture for SharePoint app.
        Both scripts ship with the module. This copies the one you ask for and writes the instructions beside it:
        who runs it, where, with what, the command (the tenant filled in from the run), and the
        Import-PostureEvidence command that brings its folder into the run. Both scripts only read.

        Nothing is sent anywhere and nothing is read from the tenant: the tenant id and name come from the run's
        own files.
    .PARAMETER Kind
        ActiveDirectory or SharePoint.
    .PARAMETER Run
        The run the evidence is for. Its tenant goes into the command, and its path into the import command.
        Without -OutputPath the folder is written inside the run, under collectors/.
    .PARAMETER OutputPath
        Where to write the folder. Needed when no -Run is given.
    .PARAMETER PassThru
        Return the folder, the script, the command and the import command instead of the folder path.
    .EXAMPLE
        Export-PostureCollector -Kind ActiveDirectory -Run ~/tenantkeep/evidence/2026-11-21-0957

        Writes collectors/active-directory/ in the run with Get-ADBaseline.ps1 and RUN-ME.txt.
    .EXAMPLE
        Export-PostureCollector -Kind SharePoint -Run ~/tenantkeep/evidence/2026-11-21-0957 -OutputPath /Volumes/usb/spo

        The SharePoint collector on a USB stick, with this run's tenant name and id in the command.
    .OUTPUTS
        System.String, the folder. With -PassThru, an object with Folder, Script, Instructions, Command and ImportCommand.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string], [pscustomobject])]
    param(
        [Parameter(Mandatory)] [ValidateSet('ActiveDirectory', 'SharePoint')] [string] $Kind,
        [string] $Run,
        [string] $OutputPath,
        [switch] $PassThru
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    if (-not $Run -and -not $OutputPath) { throw 'Name the run the evidence is for (-Run), or where to write the folder (-OutputPath).' }
    $resolve = { param([string] $p) $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p) }
    $scriptName = @{ ActiveDirectory = 'Get-ADBaseline.ps1'; SharePoint = 'Get-SpoBaseline.ps1' }[$Kind]
    $source = Join-Path (Get-PostureDataFolder -Name collectors) 'windows' $scriptName
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "$scriptName is not in this copy of the module ($source)." }

    # The run's tenant, from its own files: the id from the plan or the manifest, the name from the organization read.
    $runRoot = ''; $tenantId = ''; $tenantName = ''
    if ($Run) {
        $runPath = & $resolve $Run
        if (-not (Test-Path -LiteralPath $runPath -PathType Container)) { throw "Run folder not found: $runPath" }
        $layout = Get-PostureRunLayout -Folder $runPath
        $runRoot = [string]$layout.root
        $readJson = { param([string] $File) if (Test-Path -LiteralPath $File -PathType Leaf) { try { Get-Content -Raw -LiteralPath $File | ConvertFrom-Json -AsHashtable -Depth 10 } catch { $null } } }
        foreach ($record in (& $readJson (Join-Path $layout.logs 'run.json')), (& $readJson (Join-Path $layout.evidence 'collection.json'))) {
            if (-not $tenantId -and $record -is [System.Collections.IDictionary] -and $record.Contains('tenantId') -and $record['tenantId']) { $tenantId = [string]$record['tenantId'] }
        }
        $org = & $readJson (Join-Path $layout.evidence '01-organization.json')
        foreach ($o in @($org)) {
            if ($o -isnot [System.Collections.IDictionary] -or -not $o.Contains('verifiedDomains')) { continue }
            foreach ($d in @($o['verifiedDomains'])) { if ($d -and $d['isInitial'] -eq $true -and [string]$d['name'] -match '^([A-Za-z0-9-]+)\.onmicrosoft\.com$') { $tenantName = $Matches[1] } }
        }
    }
    $folder = $(if ($OutputPath) { & $resolve $OutputPath } else { Join-Path $runRoot 'collectors' (@{ ActiveDirectory = 'active-directory'; SharePoint = 'sharepoint' }[$Kind]) })

    $quote = { param([string] $Text) "'" + $Text.Replace("'", "''") + "'" }
    $bringBack = "Import-PostureEvidence -Path <the folder the script wrote, or a zip of it> -Run $(if ($runRoot) { & $quote $runRoot } else { '<the run folder>' })"
    if ($Kind -eq 'ActiveDirectory') {
        $command = '.\Get-ADBaseline.ps1'
        $text = @(
            'TenantKeep Posture: the Active Directory read'
            ''
            'What this is: Get-ADBaseline.ps1 reads the on-premises domain for the hybrid checks (domain and forest settings,'
            'domain controllers, privileged groups, admin accounts, delegation, LAPS, stale accounts, Group Policy, AD CS).'
            'It only reads. It installs nothing, changes nothing and schedules nothing.'
            ''
            'Who runs it: someone with an account in the domain. A domain user reads almost everything.'
            'Where: a domain-joined Windows machine with the Active Directory and Group Policy tools (RSAT). A domain'
            'controller has both. Windows PowerShell 5.1 is enough.'
            ''
            '1. Copy this folder to that machine.'
            '2. In PowerShell, in this folder, run:'
            ''
            "       $command"
            ''
            '   It writes a folder named ad-baseline-<date and time> here, with a bundle.json that lists every file and'
            '   its SHA-256. In a forest with more than one domain it reads the domain of the machine it runs on; run it'
            '   once in each domain you want judged.'
            '3. Bring that folder, or a zip of it, back to the machine that has the run, and there run:'
            ''
            "       $bringBack"
            ''
            '   The import checks every file against bundle.json before it copies anything, and rebuilds the report.'
        )
    }
    else {
        $command = ".\Get-SpoBaseline.ps1 -Tenant $(if ($tenantName) { $tenantName } else { '<tenant name, the part before .onmicrosoft.com>' }) -TenantId $(if ($tenantId) { $tenantId } else { '<tenant id>' })"
        $text = @(
            'TenantKeep Posture: the SharePoint admin read'
            ''
            'What this is: Get-SpoBaseline.ps1 reads the SharePoint settings Microsoft Graph does not carry, and the site'
            'list, through Microsoft''s own SharePoint Online Management Shell. No TenantKeep app is involved and nothing'
            'is consented. It runs Get-SPO commands only: it reads, and changes nothing.'
            ''
            'Who runs it: an account that holds SharePoint Administrator (activate it in PIM for the few minutes this takes).'
            'Where: a Windows machine (a cloud PC is fine) with the Microsoft.Online.SharePoint.PowerShell module:'
            ''
            '       Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser'
            ''
            '1. Copy this folder to that machine.'
            '2. In PowerShell, in this folder, run:'
            ''
            "       $command"
            ''
            '   The script refuses to read any tenant but that one. It writes a folder named spo-baseline-<date and time>'
            '   here, with a bundle.json that lists every file and its SHA-256. Add -SkipSiteEnumeration to leave the site'
            '   list out on a tenant with tens of thousands of sites.'
            '3. Bring that folder, or a zip of it, back to the machine that has the run, and there run:'
            ''
            "       $bringBack"
            ''
            '   The import refuses evidence from another tenant, checks every file against bundle.json before it copies'
            '   anything, and rebuilds the report.'
        )
    }
    $text += @(
        ''
        'If Windows will not run the script: a signed release is signed by Kainor LLC, which'
        "Get-AuthenticodeSignature .\$scriptName shows. In an unsigned build, read the script first, then:"
        ''
        "       Unblock-File .\$scriptName"
        ''
        "Written by Export-PostureCollector, TenantKeep.Posture $([string]$script:ModuleVersion)."
    )

    if ($PSCmdlet.ShouldProcess($folder, "Write $scriptName and RUN-ME.txt")) {
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination (Join-Path $folder $scriptName) -Force
        # CRLF: the file is read on Windows, in whatever opens a .txt there.
        [System.IO.File]::WriteAllText((Join-Path $folder 'RUN-ME.txt'), (($text -join "`r`n") + "`r`n"), [System.Text.UTF8Encoding]::new($false))
    }
    if ($PassThru) { return [pscustomobject]@{ Folder = $folder; Script = (Join-Path $folder $scriptName); Instructions = (Join-Path $folder 'RUN-ME.txt'); Command = $command; ImportCommand = $bringBack } }
    return $folder
}
