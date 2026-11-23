# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Invoke-PostureNetworkAccessCollection {
    <#
    .SYNOPSIS
        The Global Secure Access part of the Entra collection: forwarding profiles, security profiles and what is
        linked to them, web filtering and TLS inspection policies, Private Access applications and the tenant
        settings. Graph beta, GET only, with NetworkAccess.Read.All.
    .DESCRIPTION
        Called by Invoke-PostureEntraCollection only where the subscriptions carry Internet Access or Private Access:
        a tenant without either answers these addresses with errors.

        What is saved is settings: names, states, kinds of rule, counts. Not saved: the host names in a filtering
        rule, who is assigned to a profile or an application, a certificate, or any traffic. A setting that cannot
        be read is left empty, so a check has no answer for it and never reads it as off.

        The connectors and connector groups of Private Access are not read: Microsoft Graph lists them only with
        Directory.ReadWrite.All, and the app this run signs in to holds read-only permissions only.
    .PARAMETER Licensed
        Which of the two the tenant holds (internetAccess, privateAccess), recorded with the settings.
    .OUTPUTS
        @{ files = <names written> }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Folder,
        [string[]] $Licensed = @(),
        [datetime] $AsOf = [datetime]::UtcNow
    )

    $ErrorActionPreference = 'Stop'
    $files = [System.Collections.Generic.List[string]]::new()
    $save = { param($Data, [string] $Name, [bool] $Csv = $false) $files.Add((Write-PostureEvidence -Folder $Folder -Name $Name -InputObject $Data -AsArray -Csv:$Csv)) }
    $saveOne = { param($Data, [string] $Name) $files.Add((Write-PostureEvidence -Folder $Folder -Name $Name -InputObject $Data)) }
    $get = { param([string] $Uri) @(Invoke-PostureGraphRequest -Uri $Uri -ApiVersion beta) }
    $one = { param([string] $Uri) Invoke-PostureGraphRequest -Uri $Uri -ApiVersion beta -Single }
    $v = { param($o, [string] $p) Get-PostureValue $o $p }
    # The type of a linked policy is in a property whose name has a dot in it, which a path cannot name.
    $typeOf = { param($o) [string]$(if ($o -is [System.Collections.IDictionary]) { $o['@odata.type'] } elseif ($o) { $o.'@odata.type' }) }
    $utc = { param($x) $(if ($x) { (ConvertTo-PostureUtcDateTime $x).ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' }) }
    # One further setting by itself: a read that fails leaves the field empty and the others read.
    $try = { param([string] $What, [scriptblock] $Read) try { & $Read } catch { Write-Verbose "Global Secure Access $What not read: $($_.Exception.Message)"; $null } }
    # Whether anyone at all is assigned to a service principal: the first assignment answers it, and none is saved.
    $anyAssigned = { param([string] $Id) @(@(& $v (& $one "servicePrincipals/$Id/appRoleAssignedTo?`$select=id&`$top=1") 'value') | Where-Object { $_ }).Count -gt 0 }

    Invoke-PostureStep -Label 'Global Secure Access forwarding profiles' -Folder $Folder -Script {
        # Each profile with whether it is handed to chosen people: its service principal's "assignment required"
        # switch, and whether anyone is assigned (verify the expansion on a live run; without it the two fields
        # stay empty).
        $fp = $(try { & $get 'networkAccess/forwardingProfiles?$expand=servicePrincipal($select=id,appId)' } catch { Write-Verbose "Forwarding profiles read without their service principals: $($_.Exception.Message)"; & $get 'networkAccess/forwardingProfiles' })
        & $save @($fp | ForEach-Object {
                $item = $_; $spId = [string](& $v $item 'servicePrincipal.id')
                $required = $null; $assigned = $null
                if ($spId) {
                    $required = & $try "assignment switch of $(& $v $item 'name')" { & $v (& $one "servicePrincipals/$($spId)?`$select=id,appRoleAssignmentRequired") 'appRoleAssignmentRequired' }
                    $assigned = & $try "assignments of $(& $v $item 'name')" { & $anyAssigned $spId }
                }
                [ordered]@{ Name = (& $v $item 'name'); TrafficForwardingType = (& $v $item 'trafficForwardingType'); State = (& $v $item 'state'); AssignmentRequired = $required; Assigned = $assigned }
            }) 'gsa-01-forwarding-profiles'
    } | Out-Null
    Invoke-PostureStep -Label 'Global Secure Access filtering' -Folder $Folder -Script {
        $prof = & $get 'networkAccess/filteringProfiles?$expand=policies'
        & $save @($prof | ForEach-Object { [ordered]@{ Name = (& $v $_ 'name'); State = (& $v $_ 'state'); Priority = (& $v $_ 'priority'); Policies = @(& $v $_ 'policies').Count } }) 'gsa-02-filtering-profiles'
    } | Out-Null
    Invoke-PostureStep -Label 'Global Secure Access security profiles' -Folder $Folder -Script {
        # Each security profile with what is linked to it: which kinds of policy (web filtering, threat
        # intelligence, TLS inspection, file, prompt, cloud firewall), whether each link is on, and how many
        # Conditional Access policies hand the profile out. The baseline profile has the fixed priority 65000 and
        # applies to all traffic without Conditional Access.
        $kind = {
            param([string] $Type)
            switch -Regex ($Type) {
                'threatIntelligence' { 'threatIntelligence'; break }
                'tlsInspection' { 'tlsInspection'; break }
                'cloudFirewall' { 'cloudFirewall'; break }
                'filePolicy' { 'file'; break }
                'promptPolicy' { 'prompt'; break }
                'filteringPolicyLink' { 'webFiltering'; break }
                default { 'other' }
            }
        }
        $prof = & $get 'networkAccess/filteringProfiles?$expand=policies($expand=policy),conditionalAccessPolicies'
        & $save @($prof | ForEach-Object {
                [ordered]@{
                    Name = (& $v $_ 'name'); State = (& $v $_ 'state'); Priority = (& $v $_ 'priority'); Baseline = ([string](& $v $_ 'priority') -eq '65000')
                    ConditionalAccessPolicies = @(@(& $v $_ 'conditionalAccessPolicies') | Where-Object { $_ }).Count
                    Links = @(@(& $v $_ 'policies') | Where-Object { $_ } | ForEach-Object { [ordered]@{ Kind = (& $kind (& $typeOf $_)); State = (& $v $_ 'state'); Priority = (& $v $_ 'priority'); PolicyId = (& $v $_ 'policy.id'); Policy = (& $v $_ 'policy.name'); Action = (& $v $_ 'policy.action') } })
                }
            }) 'gsa-04-security-profiles'
    } | Out-Null
    Invoke-PostureStep -Label 'Global Secure Access filtering policies' -Folder $Folder -Script {
        # Each web content filtering policy: what it does and the kinds of rule it holds, with the web categories
        # its category rules name. Host names in a rule are counted, not saved.
        $pol = & $get 'networkAccess/filteringPolicies?$expand=policyRules'
        & $save @($pol | ForEach-Object {
                $rules = @(@(& $v $_ 'policyRules') | Where-Object { $_ })
                $categories = @($rules | Where-Object { [string](& $v $_ 'ruleType') -eq 'webCategory' } | ForEach-Object { @(& $v $_ 'destinations') } | Where-Object { $_ } | ForEach-Object { [string](& $v $_ 'name') } | Where-Object { $_ } | Sort-Object -Unique)
                [ordered]@{ Id = (& $v $_ 'id'); Name = (& $v $_ 'name'); Action = (& $v $_ 'action'); RuleTypes = @($rules | ForEach-Object { [string](& $v $_ 'ruleType') } | Where-Object { $_ } | Sort-Object -Unique); WebCategories = $categories; HostRules = @($rules | Where-Object { [string](& $v $_ 'ruleType') -ne 'webCategory' }).Count }
            }) 'gsa-05-filtering-policies'
    } | Out-Null
    Invoke-PostureStep -Label 'Global Secure Access TLS inspection' -Folder $Folder -Script {
        # The TLS inspection policies with their default action, when each was last changed and how many rules of
        # its own bypass inspection (the system rule has the fixed priority 65000), and the certificates inspection
        # signs with: name, status and expiry, never the certificate.
        $tls = & $get 'networkAccess/tlsInspectionPolicies?$expand=policyRules'
        $certs = & $try 'TLS inspection certificates' { , @(& $get 'networkAccess/tls/externalCertificateAuthorityCertificates') }
        & $saveOne ([ordered]@{
                Policies         = @($tls | ForEach-Object {
                        $rules = @(@(& $v $_ 'policyRules') | Where-Object { $_ })
                        [ordered]@{ Id = (& $v $_ 'id'); Name = (& $v $_ 'name'); DefaultAction = (& $v $_ 'settings.defaultAction'); LastModifiedUtc = (& $utc (& $v $_ 'lastModifiedDateTime')); Rules = $rules.Count; BypassRules = @($rules | Where-Object { [string](& $v $_ 'action') -eq 'bypass' -and [string](& $v $_ 'priority') -ne '65000' }).Count }
                    })
                CertificatesRead = ($null -ne $certs)
                Certificates     = @($certs | Where-Object { $_ } | ForEach-Object { [ordered]@{ Name = (& $v $_ 'name'); Status = (& $v $_ 'status'); ExpiresUtc = (& $utc (& $v $_ 'validity.endDateTime')) } })
            }) 'gsa-06-tls-inspection'
    } | Out-Null
    Invoke-PostureStep -Label 'Global Secure Access private applications' -Folder $Folder -Script {
        # The applications reached through Private Access, Quick Access among them: whether each is on, whether it
        # asks for an assignment, and whether anyone is assigned. Who is assigned is not saved. The first 500.
        $apps = & $get "servicePrincipals?`$filter=tags/any(c:c eq 'IsAccessibleViaZTNAClient')&`$select=id,appId,displayName,accountEnabled,appRoleAssignmentRequired,tags"
        & $save @($apps | Select-Object -First 500 | ForEach-Object {
                $item = $_
                [ordered]@{
                    Name = (& $v $item 'displayName'); AppId = (& $v $item 'appId'); QuickAccess = (@(& $v $item 'tags') -contains 'NetworkAccessQuickAccessApplication'); Enabled = (& $v $item 'accountEnabled')
                    AssignmentRequired = (& $v $item 'appRoleAssignmentRequired'); Assigned = (& $try "assignments of $(& $v $item 'displayName')" { & $anyAssigned ([string](& $v $item 'id')) })
                }
            }) 'gsa-07-private-apps' $true
    } | Out-Null
    Invoke-PostureStep -Label 'Global Secure Access remote networks and signaling' -Folder $Folder -Script {
        $rn = @(& $get 'networkAccess/connectivity/remoteNetworks')
        $sig = & $try 'signaling setting' { & $one 'networkAccess/settings/conditionalAccess' }
        $since = $AsOf.AddDays(-30)
        # Deployments of the last 30 days: how many, and how many failed.
        $deployments = & $try 'deployments' { , @(& $get 'networkAccess/deployments' | Where-Object { $when = $(if (& $v $_ 'deploymentEndDateTime') { & $v $_ 'deploymentEndDateTime' } else { & $v $_ 'lastModifiedDateTime' }); $when -and (ConvertTo-PostureUtcDateTime $when) -ge $since }) }
        # Devices the service has seen in the last week (verify the function and its field on a live run).
        $stamp = { param([datetime] $d) $d.ToString('yyyy-MM-ddTHH:mm:ssZ') }
        $devices = & $try 'device usage' { & $v (& $one "networkAccess/reports/getDeviceUsageSummary(startDateTime=$(& $stamp $AsOf.AddDays(-7)),endDateTime=$(& $stamp $AsOf),activityPivotDateTime=$(& $stamp $AsOf.AddDays(-1)))") 'totalDeviceCount' }
        & $saveOne ([ordered]@{
                RemoteNetworks            = $rn.Count
                SignalingStatus           = (& $v $sig 'signalingStatus')
                Licensed                  = @($Licensed)
                # Universal tenant restrictions: whether traffic is tagged with the tenant's restrictions policy.
                TenantRestrictionsTagging = (& $try 'tenant restrictions setting' { [string](& $v (& $one 'networkAccess/settings/crossTenantAccess') 'networkPacketTaggingStatus') })
                PrivateNetworks           = (& $try 'private networks' { @(& $get 'networkAccess/privateNetworks').Count })
                DeploymentsRecent         = $(if ($null -ne $deployments) { @($deployments).Count })
                DeploymentsFailed         = $(if ($null -ne $deployments) { @($deployments | Where-Object { [string](& $v $_ 'status.deploymentStage') -eq 'failed' }).Count })
                DevicesSeen               = $devices
                # The built-in "All Compliant Network locations" location Conditional Access can name, when it exists.
                CompliantNetworkLocations = (& $try 'compliant network location' { , @(Invoke-PostureGraphRequest -Uri "identity/conditionalAccess/namedLocations?`$filter=isof('microsoft.graph.compliantNetworkNamedLocation')" -ApiVersion beta | ForEach-Object { [string](& $v $_ 'id') } | Where-Object { $_ }) })
            }) 'gsa-03-settings'
    } | Out-Null
    return @{ files = $files.ToArray() }
}
