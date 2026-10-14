# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureCollection {
    <#
    .SYNOPSIS
        Collects evidence from the tenant into one run folder with the audit plan's file names (spec 6, Appendix A).
    .DESCRIPTION
        Read-only. The Entra collector (A.1 identity sections): organization and licensing, tenant-wide
        policies, privileged roles active and PIM-eligible, authentication method registration, users, groups,
        app registrations and service principals with credential expiry, Graph application permissions, delegated
        grants, Identity Protection. The Conditional Access snapshot (spec 5.1) is written into the same folder, so
        one folder feeds every domain's checks. Each step logs a failure to errors.txt and the run continues.

        Requires an existing Graph session with Policy.Read.All, Directory.Read.All and Group.Read.All. Optional
        scopes unlock more: User.Read.All and AuditLog.Read.All (sign-in activity, registration report),
        UserAuthenticationMethod.Read.All (registration report), RoleManagement.Read.Directory (PIM),
        OnPremDirectorySynchronization.Read.All (hybrid sync features), IdentityRiskyUser.Read.All and
        IdentityRiskEvent.Read.All (Identity Protection). Missing ones are reported
        with the steps they would unlock. Never connects on its own.
    .PARAMETER OutRoot
        Root folder for evidence. Default: ~/audit/evidence. The run folder <yyyyMMdd-HHmm> is created under it.
    .PARAMETER OutputFolder
        Write into this exact folder instead.
    .PARAMETER Collector
        Which collectors to run: Entra (A.1 identity sections), Intune (A.1 section 9 and the spec 4.4 additions). Default both.
    .PARAMETER StaleDays
        Threshold for inactive users and devices in the summaries. Default 90.
    .PARAMETER IncludeMembers
        Store group member lists in the Conditional Access snapshot.
    .PARAMETER SkipCaSnapshot
        Do not write the Conditional Access snapshot into the folder.
    .PARAMETER SkipPerUserMfa
        Skip the per-user MFA state read (one batched Graph read per member; slow at tens of thousands of users).
    .PARAMETER PassThru
        Return a summary object instead of the folder path.
    .EXAMPLE
        Connect-MgGraph -Scopes Policy.Read.All, Directory.Read.All, Group.Read.All, User.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All, RoleManagement.Read.Directory, OnPremDirectorySynchronization.Read.All, IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All -NoWelcome
        Invoke-PostureCollection

        Writes ~/audit/evidence/<stamp>/ with the A.1 files and the CA snapshot.
    .EXAMPLE
        Invoke-PostureCollection -OutRoot ./evidence -PassThru | Select-Object Folder, Errors
    .OUTPUTS
        System.String, the run folder. With -PassThru, a summary object.
    .LINK
        docs/m365-environment-audit-plan.md Appendix A
    #>
    [CmdletBinding()]
    [OutputType([string], [pscustomobject])]
    param(
        [ValidateNotNullOrEmpty()] [string] $OutRoot = (Join-Path $HOME 'audit' 'evidence'),
        [string] $OutputFolder,
        [ValidateSet('Entra', 'Intune')] [string[]] $Collector = @('Entra', 'Intune'),
        [ValidateRange(1, 3650)] [int] $StaleDays = 90,
        [switch] $IncludeMembers,
        [switch] $SkipCaSnapshot,
        [switch] $SkipPerUserMfa,
        [switch] $PassThru
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $core = @('Policy.Read.All', 'Directory.Read.All', 'Group.Read.All')
    $context = Assert-PostureGraphScope -RequiredScope $core
    $optional = [ordered]@{
        'User.Read.All'                     = 'Users'
        'OnPremDirectorySynchronization.Read.All' = 'Hybrid sync features'
        'AuditLog.Read.All'                 = 'Users sign-in activity, Auth method registration'
        'UserAuthenticationMethod.Read.All' = 'Auth method registration'
        'RoleManagement.Read.Directory'     = 'PIM eligible assignments, PIM role policies'
        'IdentityRiskyUser.Read.All'        = 'Risky users'
        'IdentityRiskEvent.Read.All'        = 'Risk detections'
        'DeviceManagementManagedDevices.Read.All' = 'Intune managed devices, Autopilot'
        'DeviceManagementConfiguration.Read.All'  = 'Intune compliance and configuration policies, enrollment restrictions, cleanup rule'
        'DeviceManagementServiceConfig.Read.All'  = 'Apple push certificate, MDE connector'
        'DeviceManagementApps.Read.All'           = 'Intune apps, Apple VPP tokens'
        'BitLockerKey.ReadBasic.All'              = 'BitLocker recovery key presence'
    }
    $granted = @($context.Scopes)
    foreach ($scope in $optional.Keys) {
        if ($scope -notin $granted) { Write-Warning "Scope $scope not granted; expect '$($optional[$scope])' to land in errors.txt." }
    }

    $startedUtc = [datetime]::UtcNow
    $folder = if ($OutputFolder) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
        (Resolve-Path -LiteralPath $OutputFolder).Path
    }
    else { New-PostureEvidenceFolder -OutRoot $OutRoot }
    $script:GraphApiVersionsUsed.Clear()

    try {
        $files = [System.Collections.Generic.List[string]]::new()
        $ran = [System.Collections.Generic.List[string]]::new()

        if (-not $SkipCaSnapshot) {
            $snap = Export-PostureCaSnapshot -OutputFolder $folder -IncludeMembers:$IncludeMembers -PassThru
            foreach ($f in $snap.Files) { $files.Add($f) }
            $ran.Add('ConditionalAccess')
        }
        if ($Collector -contains 'Entra') {
            $r = Invoke-PostureEntraCollection -Folder $folder -StaleDays $StaleDays -AsOf $startedUtc -SkipPerUserMfa:$SkipPerUserMfa
            foreach ($f in $r.files) { $files.Add($f) }
            $ran.Add('Entra')
        }
        if ($Collector -contains 'Intune') {
            $r = Invoke-PostureIntuneCollection -Folder $folder -StaleDays $StaleDays -AsOf $startedUtc
            foreach ($f in $r.files) { $files.Add($f) }
            $ran.Add('Intune')
        }

        $errorsPath = Join-Path $folder 'errors.txt'
        $errors = @(if (Test-Path -LiteralPath $errorsPath) { Get-Content -LiteralPath $errorsPath })   # @( ) outside the if: an empty array inside it unrolls to null
        $manifest = [ordered]@{
            product          = 'Tenantkeep.Posture'
            moduleVersion    = $script:ModuleVersion
            collectors       = $ran.ToArray()
            tenantId         = $context.TenantId
            account          = $context.Account
            authType         = $context.AuthType
            scopes           = @($granted | Sort-Object)
            timestampUtc     = $startedUtc.ToString('o')
            completedUtc     = [datetime]::UtcNow.ToString('o')
            graphApiVersions = @($script:GraphApiVersionsUsed | Sort-Object)
            staleDays        = $StaleDays
            files            = @(Get-ChildItem -LiteralPath $folder -File | Where-Object { $_.Name -notin @('transcript.txt', 'errors.txt') } | ForEach-Object { $_.Name } | Sort-Object)
            errorCount       = $errors.Count
            errors           = $errors
        }
        $files.Add((Write-PostureEvidence -Folder $folder -Name 'collection' -InputObject $manifest))
        if ($errors.Count -gt 0) { Write-Warning "$($errors.Count) step(s) failed; see $errorsPath" }

        if ($PassThru) {
            return [pscustomobject]@{ Folder = $folder; Collectors = $ran.ToArray(); Files = $files.ToArray(); Errors = $errors; Manifest = $manifest }
        }
        return $folder
    }
    finally {
        if (-not $OutputFolder) { try { Stop-Transcript | Out-Null } catch { Write-Verbose 'No transcript to stop.' } }
    }
}
