# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Export-PostureCaSnapshot {
    <#
    .SYNOPSIS
        Writes a read-only snapshot of the tenant's Conditional Access configuration to one folder per run.
    .DESCRIPTION
        Exports the seven files from spec section 5.1 into <OutRoot>/<yyyyMMdd-HHmm>-ca/:

          policies.json          full policy objects, untouched wire JSON
          named-locations.json   all named locations
          auth-strengths.json    built-in and custom authentication strengths
          auth-context.json      authentication context class references
          resolved-names.json    every ID any policy references, mapped to display name and type; deleted objects flagged
          group-scope.json       per included or excluded group: transitive member count and a SHA-256 of the sorted member ids
          metadata.json          tenant, timestamp, account, scopes, API versions used, module version, policy count

        Requires an existing Microsoft Graph session (Connect-MgGraph) with Policy.Read.All, Directory.Read.All and
        Group.Read.All. The cmdlet never connects on its own and never writes to the tenant. A failure on one
        endpoint is written to errors.txt in the run folder and the run continues.

        Group member UPNs are stored only with -IncludeMembers. Without it, group-scope.json holds counts and hashes.

        The policy export is pinned to Graph v1.0. Use -ApiVersion beta to capture properties that only the beta
        schema exposes, such as insider risk conditions (verify). Snapshots compared later should use the same version.
    .PARAMETER OutRoot
        Root folder for evidence. Default: ~/tenantkeep/evidence, the audit plan's convention. The run folder is created under it.
    .PARAMETER OutputFolder
        Write into this exact folder instead of creating <OutRoot>/<stamp>-ca. Used by Invoke-PostureCollection so one
        run folder holds every domain's evidence.
    .PARAMETER IncludeMembers
        Also store the transitive member list (id, type, display name, UPN) of every referenced group in group-scope.json.
    .PARAMETER ApiVersion
        Graph API version for the four Conditional Access endpoints. v1.0 (default) or beta. Recorded in metadata.json.
    .PARAMETER PassThru
        Return a summary object (Folder, PolicyCount, Files, Errors) instead of the folder path.
    .EXAMPLE
        Connect-MgGraph -Scopes Policy.Read.All, Directory.Read.All, Group.Read.All -NoWelcome
        Export-PostureCaSnapshot

        Writes ~/tenantkeep/evidence/20261013-0905-ca/ and returns that path.
    .EXAMPLE
        Export-PostureCaSnapshot -OutRoot ./snapshots -IncludeMembers -PassThru

        Stores member lists for scope diffing and returns a summary object.
    .OUTPUTS
        System.String. The run folder path. With -PassThru, a summary object.
    .LINK
        docs/posture-spec.md section 5.1
    #>
    [CmdletBinding()]
    [OutputType([string], [pscustomobject])]
    param(
        [Parameter()] [ValidateNotNullOrEmpty()] [string] $OutRoot = (Join-Path $HOME 'tenantkeep' 'evidence'),
        [string] $OutputFolder,
        [switch] $IncludeMembers,
        [ValidateSet('v1.0', 'beta')] [string] $ApiVersion = 'v1.0',
        [switch] $PassThru
    )

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    $requiredScopes = @('Policy.Read.All', 'Directory.Read.All', 'Group.Read.All')
    $context = Assert-PostureGraphScope -RequiredScope $requiredScopes

    $startedUtc = [datetime]::UtcNow
    $folder = if ($OutputFolder) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
        (Resolve-Path -LiteralPath $OutputFolder).Path
    }
    else { New-PostureEvidenceFolder -OutRoot $OutRoot -Suffix 'ca' }
    $script:GraphApiVersionsUsed.Clear()
    Write-Verbose "Writing CA snapshot to $folder"

    try {
        # 1. Raw exports, untouched.
        $policies = @(Invoke-PostureStep -Label 'CA policies' -Folder $folder -Script {
                Invoke-PostureGraphRequest -Uri 'identity/conditionalAccess/policies' -ApiVersion $ApiVersion
            })
        $locations = @(Invoke-PostureStep -Label 'Named locations' -Folder $folder -Script {
                Invoke-PostureGraphRequest -Uri 'identity/conditionalAccess/namedLocations' -ApiVersion $ApiVersion
            })
        $strengths = @(Invoke-PostureStep -Label 'Authentication strengths' -Folder $folder -Script {
                Invoke-PostureGraphRequest -Uri 'policies/authenticationStrengthPolicies' -ApiVersion $ApiVersion
            })
        $contexts = @(Invoke-PostureStep -Label 'Authentication context' -Folder $folder -Script {
                Invoke-PostureGraphRequest -Uri 'identity/conditionalAccess/authenticationContextClassReferences' -ApiVersion $ApiVersion
            })

        $files = [System.Collections.Generic.List[string]]::new()
        $files.Add((Write-PostureEvidence -Folder $folder -Name 'policies'        -InputObject $policies  -AsArray))
        $files.Add((Write-PostureEvidence -Folder $folder -Name 'named-locations' -InputObject $locations -AsArray))
        $files.Add((Write-PostureEvidence -Folder $folder -Name 'auth-strengths'  -InputObject $strengths -AsArray))
        $files.Add((Write-PostureEvidence -Folder $folder -Name 'auth-context'    -InputObject $contexts  -AsArray))

        # 2. Resolve every referenced ID to a name and type.
        $refs = Get-PostureCaReference -Policy $policies
        $resolved = Invoke-PostureStep -Label 'Resolve names' -Folder $folder -Script {
            Resolve-PostureCaName -Reference $refs -Location $locations -Strength $strengths -Context $contexts
        }
        if ($null -eq $resolved) { $resolved = [ordered]@{} }
        $files.Add((Write-PostureEvidence -Folder $folder -Name 'resolved-names' -InputObject $resolved))

        # 3. Group scope: count and hash per referenced group, members only on request.
        $groupScope = foreach ($groupId in ($refs['groups'] | Sort-Object)) {
            $entry = Get-PostureValue $resolved $groupId
            if ($entry -and $entry['deleted']) {
                [ordered]@{ groupId = $groupId; deleted = $true; memberCount = $null; memberHash = $null }
                continue
            }
            $scope = Invoke-PostureStep -Label "Group members $groupId" -Folder $folder -Script {
                Get-PostureGroupScope -GroupId $groupId -IncludeMembers:$IncludeMembers
            }
            if ($scope) { $scope } else { [ordered]@{ groupId = $groupId; error = $true; memberCount = $null; memberHash = $null } }
        }
        $files.Add((Write-PostureEvidence -Folder $folder -Name 'group-scope' -InputObject @($groupScope) -AsArray))

        # 4. Metadata.
        $errorsPath = Join-Path $folder 'errors.txt'
        $errorCount = if (Test-Path $errorsPath) { @(Get-Content -Path $errorsPath).Count } else { 0 }
        $metadata = [ordered]@{
            product         = 'Tenantkeep.Posture'
            moduleVersion   = $script:ModuleVersion
            snapshotType    = 'conditional-access'
            snapshotSchema  = 1
            tenantId        = $context.TenantId
            account         = $context.Account
            authType        = $context.AuthType
            scopes          = @($context.Scopes | Sort-Object)
            timestampUtc    = $startedUtc.ToString('o')
            completedUtc    = [datetime]::UtcNow.ToString('o')
            graphApiVersions = @($script:GraphApiVersionsUsed | Sort-Object)
            modules         = (Get-PostureModuleVersionUsed)
            policyCount     = $policies.Count
            namedLocationCount = $locations.Count
            authStrengthCount  = $strengths.Count
            authContextCount   = $contexts.Count
            groupCount      = @($groupScope).Count
            includeMembers  = [bool]$IncludeMembers
            errorCount      = $errorCount
            powerShell      = $PSVersionTable.PSVersion.ToString()
            platform        = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
        }
        $files.Add((Write-PostureEvidence -Folder $folder -Name 'metadata' -InputObject $metadata))

        if ($errorCount -gt 0) { Write-Warning "$errorCount step(s) failed; see $errorsPath" }

        if ($PassThru) {
            return [pscustomobject]@{
                Folder      = $folder
                PolicyCount = $policies.Count
                GroupCount  = @($groupScope).Count
                Errors      = $errorCount
                Files       = $files.ToArray()
                Metadata    = $metadata
            }
        }
        return $folder
    }
    finally {
        if (-not $OutputFolder) { try { Stop-Transcript | Out-Null } catch { Write-Verbose 'No transcript to stop.' } }
    }
}
