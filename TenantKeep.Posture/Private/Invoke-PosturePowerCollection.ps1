# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PosturePowerBICollection {
    <#
    .SYNOPSIS
        The Power BI (Fabric) collector: every tenant setting, from one read of the Fabric admin API.
    .DESCRIPTION
        Needs a sign-in that may read the tenant settings: a Fabric Administrator whose account holds a Power BI or
        Fabric licence (the free one counts) and has opened the Power BI portal once, with Tenant.Read.All approved
        on the TenantKeep app; or, in a scheduled run, a managed identity in a security group the customer named in
        the Fabric tenant setting "Service principals can access read-only admin APIs". Never connects.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [string] $Folder)

    $ErrorActionPreference = 'Stop'
    $files = [System.Collections.Generic.List[string]]::new()
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    Invoke-PostureStep -Label 'Power BI tenant settings' -Folder $Folder -Script {
        try { $settings = @(Invoke-PostureFabricRequest -Path '/v1/admin/tenantsettings') }
        catch {
            $said = [string]$_.Exception.Message
            if ($said -match 'UserNotLicensed') {
                # Power BI says the same thing for an account with no licence and for one whose licence it has not
                # taken up yet. The account's own licences in Entra say which, and what to do differs.
                $advice = Get-PosturePowerBILicenceAdvice
                if (-not $advice) { $advice = 'Power BI refused the account that signed in because it has no Power BI or Fabric licence. Give that account the free Microsoft Fabric licence, open app.powerbi.com with it once, and collect again (Resume-PostureRun -Collector PowerBI).' }
                throw "$advice $said"
            }
            throw
        }
        if ($settings.Count -eq 0) { throw 'Power BI returned no tenant settings. Every tenant has them, so this sign-in was not allowed to see them.' }
        $names = { param($groups) @(@($groups) | Where-Object { $_ } | ForEach-Object { [string](& $v $_ 'name') } | Where-Object { $_ }) }
        $rows = @($settings | ForEach-Object {
                [ordered]@{
                    SettingName = [string](& $v $_ 'settingName'); Title = [string](& $v $_ 'title'); Group = [string](& $v $_ 'tenantSettingGroup')
                    Enabled = [bool]((& $v $_ 'enabled') -eq $true); CanSpecifySecurityGroups = [bool]((& $v $_ 'canSpecifySecurityGroups') -eq $true)
                    EnabledSecurityGroups = @(& $names (& $v $_ 'enabledSecurityGroups')); ExcludedSecurityGroups = @(& $names (& $v $_ 'excludedSecurityGroups'))
                }
            })
        $files.Add((Write-PostureEvidence -Folder $Folder -Name 'pbi-01-tenant-settings' -InputObject $rows -AsArray -Csv:$false))
    } | Out-Null

    $errorsPath = Join-Path (Get-PostureRunLayout -Folder $Folder).errors 'errors.txt'
    return @{ files = $files.ToArray(); errors = @(if (Test-Path -LiteralPath $errorsPath) { Get-Content -LiteralPath $errorsPath }) }
}

function Invoke-PosturePowerPlatformCollection {
    <#
    .SYNOPSIS
        The Power Platform collector: the tenant settings, the environments, the DLP policies and the tenant
        isolation policy, from the Power Platform admin API.
    .DESCRIPTION
        Needs the run's second sign-in (Connect-PostureSession -Services), as a Power Platform Administrator, with
        the Power Platform permission approved on that second app. The API has no read-only permission and no
        read-only role, which is why the permission is never on the TenantKeep app, and what makes this a read is
        the code: three GETs and the one POST Microsoft made the way to list tenant settings
        (Invoke-PosturePowerRequest.ps1). Not collected in a scheduled run: an unattended identity would have to be
        registered with full Power Platform administration. Never connects.
    .PARAMETER TenantId
        The tenant's id, which the tenant isolation address carries.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [Parameter(Mandatory)] [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')] [string] $TenantId
    )

    $ErrorActionPreference = 'Stop'
    $files = [System.Collections.Generic.List[string]]::new()
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    $save = { param($Data, [string] $Name, [bool] $Csv = $false) $files.Add((Write-PostureEvidence -Folder $Folder -Name $Name -InputObject $Data -AsArray -Csv:$Csv)) }
    $saveOne = { param($Data, [string] $Name) $files.Add((Write-PostureEvidence -Folder $Folder -Name $Name -InputObject $Data)) }

    Invoke-PostureStep -Label 'Power Platform tenant settings' -Folder $Folder -Script {
        $settings = Get-PosturePowerPlatformTenantSetting
        if (-not ($settings -is [System.Collections.IDictionary]) -or $settings.get_Count() -eq 0) { throw 'Power Platform returned no tenant settings.' }
        & $saveOne $settings 'pp-01-tenant-settings'
    } | Out-Null

    Invoke-PostureStep -Label 'Power Platform environments' -Folder $Folder -Script {
        $environments = @(Invoke-PosturePowerPlatformRequest -Path '/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2023-06-01')
        $rows = @($environments | Where-Object { $_ } | ForEach-Object {
                [ordered]@{
                    Name = [string](& $v $_ 'name'); DisplayName = [string](& $v $_ 'properties.displayName'); IsDefault = [bool]((& $v $_ 'properties.isDefault') -eq $true)
                    Sku = [string](& $v $_ 'properties.environmentSku'); Location = [string](& $v $_ 'location'); CreatedTime = (& $v $_ 'properties.createdTime')
                }
            })
        & $save $rows 'pp-02-environments' $true
    } | Out-Null

    Invoke-PostureStep -Label 'Power Platform DLP policies' -Folder $Folder -Script {
        # A policy applies to every environment, to the ones it names, or to all but the ones it names: the filter in
        # its definition says which, and no filter means every environment.
        $policies = @(Invoke-PosturePowerPlatformRequest -Path '/providers/Microsoft.BusinessAppPlatform/scopes/admin/apiPolicies?api-version=2016-11-01')
        $rows = @($policies | Where-Object { $_ } | ForEach-Object {
                $filter = & $v $_ 'properties.definition.constraints.environmentFilter1'
                $named = @(@(& $v $filter 'parameters.environments') | Where-Object { $_ } | ForEach-Object { [string](& $v $_ 'name') } | Where-Object { $_ })
                $kind = $(if ($null -eq $filter) { 'AllEnvironments' } elseif ([string](& $v $filter 'parameters.filterType') -eq 'include') { 'OnlyEnvironments' } else { 'ExceptEnvironments' })
                [ordered]@{ Name = [string](& $v $_ 'name'); DisplayName = [string](& $v $_ 'properties.displayName'); EnvironmentType = $kind; Environments = @($named) }
            })
        & $save $rows 'pp-03-dlp-policies' $false
    } | Out-Null

    Invoke-PostureStep -Label 'Power Platform tenant isolation' -Folder $Folder -Script {
        $policy = Invoke-PosturePowerPlatformRequest -Path "/providers/PowerPlatform.Governance/v1/tenants/$TenantId/tenantIsolationPolicy?api-version=2020-06-01" -Single
        # The other tenants on the allow list are counted, not saved.
        & $saveOne ([ordered]@{ IsDisabled = (& $v $policy 'properties.isDisabled'); AllowedTenants = @(@(& $v $policy 'properties.allowedTenants') | Where-Object { $_ }).Count }) 'pp-04-tenant-isolation'
    } | Out-Null

    $errorsPath = Join-Path (Get-PostureRunLayout -Folder $Folder).errors 'errors.txt'
    return @{ files = $files.ToArray(); errors = @(if (Test-Path -LiteralPath $errorsPath) { Get-Content -LiteralPath $errorsPath }) }
}
