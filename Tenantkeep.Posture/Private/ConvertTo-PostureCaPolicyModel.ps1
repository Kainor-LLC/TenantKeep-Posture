# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function ConvertTo-PostureCaPolicyModel {
    <#
    .SYNOPSIS
        Builds the per-policy model that every CA document and diff renders: names instead of ids, a plain-English
        summary line, and health flags.
    .DESCRIPTION
        Input is an Import-PostureCaSnapshot object. Output is one ordered dictionary per policy, sorted by display
        name. Ages (report-only, disabled) are measured as of the snapshot timestamp unless -AsOf is given, so a
        document rendered later describes what the tenant looked like at snapshot time.
    .PARAMETER ExclusionGroupThreshold
        An excluded group with more members than this raises a health flag. Spec 4.3 default: 25.
    .PARAMETER ReportOnlyDays
        A policy left in report-only longer than this raises a health flag. Default 90.
    .PARAMETER DisabledDays
        A policy disabled longer than this raises a health flag. Default 90.
    .PARAMETER NamePattern
        Regex the policy name must match. Omit to skip the naming flag.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Snapshot,
        [int] $ExclusionGroupThreshold = 25,
        [int] $ReportOnlyDays = 90,
        [int] $DisabledDays = 90,
        [string] $NamePattern,
        [datetime] $AsOf
    )

    $ErrorActionPreference = 'Stop'

    if (-not $PSBoundParameters.ContainsKey('AsOf')) {
        $stamp = Get-PostureValue $Snapshot.Metadata 'timestampUtc'
        $AsOf = if ($stamp) { ConvertTo-PostureUtcDateTime $stamp } else { [datetime]::UtcNow }
    }

    # The leading comma keeps an empty result an array; a bare @() unrolls to nothing on return.
    $refs = {
        param([object] $Ids, [string] $Type)
        , @(foreach ($id in @($Ids)) { if ($id) { Resolve-PostureCaRef -Snapshot $Snapshot -Id ([string]$id) -ExpectedType $Type } })
    }
    # Graph omits empty lists; @($null) would be a one-element array, so lists go through here.
    $list = { param([object] $Value) , @(@($Value) | Where-Object { $null -ne $_ }) }
    $strengthById = @{}
    foreach ($s in $Snapshot.AuthStrengths) { $strengthById[[string]$s.id] = $s }

    $models = foreach ($p in $Snapshot.Policies) {
        $stateRaw = [string](Get-PostureValue $p 'state')
        $state = switch ($stateRaw) {
            'enabled' { 'enabled' }
            'enabledForReportingButNotEnforced' { 'reportOnly' }
            'disabled' { 'disabled' }
            default { $stateRaw }
        }
        $stateLabel = @{ enabled = 'Enabled'; reportOnly = 'Report-only'; disabled = 'Disabled' }[$state]
        if (-not $stateLabel) { $stateLabel = $stateRaw }

        $users = Get-PostureValue $p 'conditions.users'
        $apps = Get-PostureValue $p 'conditions.applications'
        $clientApps = Get-PostureValue $p 'conditions.clientApplications'
        $locations = Get-PostureValue $p 'conditions.locations'
        $platforms = Get-PostureValue $p 'conditions.platforms'
        $grant = Get-PostureValue $p 'grantControls'
        $session = Get-PostureValue $p 'sessionControls'

        $assignments = [ordered]@{
            includeUsers             = & $refs (Get-PostureValue $users 'includeUsers') 'user'
            excludeUsers             = & $refs (Get-PostureValue $users 'excludeUsers') 'user'
            includeGroups            = & $refs (Get-PostureValue $users 'includeGroups') 'group'
            excludeGroups            = & $refs (Get-PostureValue $users 'excludeGroups') 'group'
            includeRoles             = & $refs (Get-PostureValue $users 'includeRoles') 'role'
            excludeRoles             = & $refs (Get-PostureValue $users 'excludeRoles') 'role'
            includeGuestsOrExternal  = Get-PostureValue $users 'includeGuestsOrExternalUsers'
            excludeGuestsOrExternal  = Get-PostureValue $users 'excludeGuestsOrExternalUsers'
            includeServicePrincipals = & $refs (Get-PostureValue $clientApps 'includeServicePrincipals') 'servicePrincipal'
            excludeServicePrincipals = & $refs (Get-PostureValue $clientApps 'excludeServicePrincipals') 'servicePrincipal'
        }
        $targets = [ordered]@{
            includeApplications    = & $refs (Get-PostureValue $apps 'includeApplications') 'application'
            excludeApplications    = & $refs (Get-PostureValue $apps 'excludeApplications') 'application'
            userActions            = & $refs (Get-PostureValue $apps 'includeUserActions') 'userAction'
            authenticationContexts = & $refs (Get-PostureValue $apps 'includeAuthenticationContextClassReferences') 'authenticationContext'
            applicationFilter      = Get-PostureValue $apps 'applicationFilter'
        }
        $conditions = [ordered]@{
            clientAppTypes   = & $list (Get-PostureValue $p 'conditions.clientAppTypes')
            includePlatforms = & $list (Get-PostureValue $platforms 'includePlatforms')
            excludePlatforms = & $list (Get-PostureValue $platforms 'excludePlatforms')
            includeLocations = & $refs (Get-PostureValue $locations 'includeLocations') 'namedLocation'
            excludeLocations = & $refs (Get-PostureValue $locations 'excludeLocations') 'namedLocation'
            signInRiskLevels = & $list (Get-PostureValue $p 'conditions.signInRiskLevels')
            userRiskLevels   = & $list (Get-PostureValue $p 'conditions.userRiskLevels')
            insiderRiskLevels = Get-PostureValue $p 'conditions.insiderRiskLevels'
            deviceFilter     = Get-PostureValue $p 'conditions.devices.deviceFilter'
        }

        $strengthId = Get-PostureValue $grant 'authenticationStrength.id'
        $strength = $null
        if ($strengthId) {
            $ref = Resolve-PostureCaRef -Snapshot $Snapshot -Id ([string]$strengthId) -ExpectedType 'authenticationStrength'
            $strength = [ordered]@{ id = $ref.id; name = $ref.name; deleted = $ref.deleted; allowedCombinations = @() }
            if ($strengthById.ContainsKey([string]$strengthId)) {
                $strength.allowedCombinations = & $list (Get-PostureValue $strengthById[[string]$strengthId] 'allowedCombinations')
            }
        }
        $grantModel = [ordered]@{
            operator               = Get-PostureValue $grant 'operator'
            builtInControls        = & $list (Get-PostureValue $grant 'builtInControls')
            authenticationStrength = $strength
            termsOfUse             = & $list (Get-PostureValue $grant 'termsOfUse')
            customFactors          = & $list (Get-PostureValue $grant 'customAuthenticationFactors')
        }
        $sessionModel = [ordered]@{
            signInFrequency             = Get-PostureValue $session 'signInFrequency'
            persistentBrowser           = Get-PostureValue $session 'persistentBrowser'
            applicationEnforcedRestrictions = Get-PostureValue $session 'applicationEnforcedRestrictions'
            cloudAppSecurity            = Get-PostureValue $session 'cloudAppSecurity'
            continuousAccessEvaluation  = Get-PostureValue $session 'continuousAccessEvaluation'
            secureSignInSession         = Get-PostureValue $session 'secureSignInSession'
            disableResilienceDefaults   = Get-PostureValue $session 'disableResilienceDefaults'
        }

        $model = [ordered]@{
            id          = [string](Get-PostureValue $p 'id')
            name        = [string](Get-PostureValue $p 'displayName')
            state       = $state
            stateLabel  = $stateLabel
            created     = ConvertTo-PostureUtcDateTime (Get-PostureValue $p 'createdDateTime')
            modified    = ConvertTo-PostureUtcDateTime (Get-PostureValue $p 'modifiedDateTime')
            assignments = $assignments
            targets     = $targets
            conditions  = $conditions
            grant       = $grantModel
            session     = $sessionModel
            summary     = $null
            healthFlags = @()
            raw         = $p
        }
        $model.summary = Get-PostureCaPolicySummary -Policy $model
        $model.healthFlags = @(Get-PostureCaHealthFlag -Policy $model -AsOf $AsOf -ExclusionGroupThreshold $ExclusionGroupThreshold -ReportOnlyDays $ReportOnlyDays -DisabledDays $DisabledDays -NamePattern $NamePattern)
        $model
    }

    return @($models | Sort-Object { $_.name })
}
