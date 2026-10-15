#Requires -Version 5.1
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    Windows-only, read-only Active Directory collector for the hybrid domain (spec 4.14, audit plan Appendix B). Run
    it once on any domain-joined Windows machine with RSAT, copy the output folder into the run's evidence folder,
    and the hybrid checks evaluate from it. Nothing is installed, nothing is changed, nothing is scheduled.
.DESCRIPTION
    Needs the ActiveDirectory module (RSAT); GroupPolicy adds the GPO inventory when present. On Windows Server install it
    with Install-WindowsFeature GPMC (Add-WindowsCapability reports success there but installs nothing); on Windows 10 or 11
    with Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0. A domain controller has both. A domain user reads
    almost everything; AdminSDHolder and template ACLs need elevated read and are left out of this pass. Every step
    writes one file and logs a failure to errors.txt without stopping. Output file names carry the ad- prefix so they
    sit beside the cloud evidence without colliding.

    What it reads: forest and domain (functional levels, FSMO, recycle bin, machine account quota, password policies,
    trusts), domain controllers, privileged group membership (recursive), admin account hygiene, krbtgt and the
    built-in accounts, delegation, Kerberoastable and AS-REP roastable accounts, LAPS coverage, stale accounts,
    password-never-expires, GPO inventory, AD CS enrollment services and templates (ESC1 candidates), the seamless
    SSO and cloud Kerberos computer accounts.
.PARAMETER OutputPath
    Folder to write into. Default: .\ad-baseline-<yyyyMMdd-HHmm>.
.PARAMETER StaleDays
    Inactivity window for stale users and computers. Default 90.
.PARAMETER Server
    A domain controller to query. Default: the discovered one.
.EXAMPLE
    .\Get-ADBaseline.ps1 -OutputPath C:\audit\ad-20261015
    Then copy C:\audit\ad-20261015\* into the evidence folder on the machine that runs the report.
#>
[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive jump-box script; the console is the only host and the output is a progress listing')]
param(
    [string] $OutputPath = (Join-Path (Get-Location) "ad-baseline-$((Get-Date).ToString('yyyyMMdd-HHmm'))"),
    [ValidateRange(1, 3650)] [int] $StaleDays = 90,
    [string] $Server
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Get-Module -ListAvailable ActiveDirectory)) { throw 'The ActiveDirectory module (RSAT) is required on this machine.' }
Import-Module ActiveDirectory
$hasGpo = [bool](Get-Module -ListAvailable GroupPolicy)
if ($hasGpo) { Import-Module GroupPolicy }

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$out = (Resolve-Path -LiteralPath $OutputPath).Path
$errorsPath = Join-Path $out 'errors.txt'
$now = (Get-Date).ToUniversalTime()
$srv = @{}
if ($Server) { $srv.Server = $Server }

function Save-Evidence {
    param([Parameter(Mandatory)] [string] $Name, [Parameter(ValueFromPipeline)] [object] $InputObject, [switch] $Csv, [switch] $Single)
    begin { $items = [System.Collections.Generic.List[object]]::new() }
    process { if ($null -ne $InputObject) { $items.Add($InputObject) } }
    end {
        $data = $(if ($Single) { $(if ($items.Count -gt 0) { $items[0] } else { @{} }) } else { $items.ToArray() })
        $json = ConvertTo-Json -InputObject $data -Depth 10
        [System.IO.File]::WriteAllText((Join-Path $out "$Name.json"), $json, [System.Text.UTF8Encoding]::new($false))
        if ($Csv -and $items.Count -gt 0) { $items | Export-Csv -Path (Join-Path $out "$Name.csv") -NoTypeInformation -Encoding UTF8 }
        Write-Host ("{0,-40} {1,6}" -f "$Name.json", $items.Count)
    }
}
function Invoke-Step {
    param([Parameter(Mandatory)] [string] $Label, [Parameter(Mandatory)] [scriptblock] $Script)
    try { & $Script }
    catch {
        $message = (([string]$_.Exception.Message) -replace '\s*[\r\n]+\s*', ' ').Trim()
        Add-Content -Path $errorsPath -Value "$Label :: $message"
        Write-Warning "$Label failed: $message"
    }
}
$fileTime = { param($v) if ($v -and $v -gt 0) { [DateTime]::FromFileTimeUtc($v).ToString('o') } else { $null } }
$iso = { param($d) if ($d) { ([datetime]$d).ToUniversalTime().ToString('o') } else { $null } }

Start-Transcript -Path (Join-Path $out 'transcript.txt') -Append | Out-Null
try {
    $domain = Get-ADDomain @srv
    $forest = Get-ADForest @srv
    $domainDn = $domain.DistinguishedName
    $configDn = (Get-ADRootDSE @srv).configurationNamingContext

    Invoke-Step 'Forest and domain' {
        $policy = Get-ADDefaultDomainPasswordPolicy @srv
        $fgpp = @(Get-ADFineGrainedPasswordPolicy -Filter * @srv)
        $recycleBin = @(Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"' @srv | Where-Object { $_.EnabledScopes.Count -gt 0 }).Count -gt 0
        $domainObj = Get-ADObject -Identity $domainDn -Properties 'ms-DS-MachineAccountQuota' @srv
        [ordered]@{
            ForestName = $forest.Name; ForestFunctionalLevel = [string]$forest.ForestMode; DomainName = $domain.DNSRoot; DomainFunctionalLevel = [string]$domain.DomainMode
            DomainCount = @($forest.Domains).Count; Sites = @($forest.Sites).Count; GlobalCatalogs = @($forest.GlobalCatalogs).Count
            Fsmo = [ordered]@{ SchemaMaster = $forest.SchemaMaster; DomainNamingMaster = $forest.DomainNamingMaster; PdcEmulator = $domain.PDCEmulator; RidMaster = $domain.RIDMaster; InfrastructureMaster = $domain.InfrastructureMaster }
            RecycleBinEnabled = $recycleBin; MachineAccountQuota = [int]$domainObj.'ms-DS-MachineAccountQuota'
            PasswordPolicy = [ordered]@{ MinPasswordLength = $policy.MinPasswordLength; ComplexityEnabled = $policy.ComplexityEnabled; LockoutThreshold = $policy.LockoutThreshold; LockoutDurationMinutes = $policy.LockoutDuration.TotalMinutes; MaxPasswordAgeDays = $policy.MaxPasswordAge.TotalDays; PasswordHistoryCount = $policy.PasswordHistoryCount; ReversibleEncryptionEnabled = $policy.ReversibleEncryptionEnabled }
            FineGrainedPolicies = @($fgpp | ForEach-Object { [ordered]@{ Name = $_.Name; MinPasswordLength = $_.MinPasswordLength; AppliesTo = @($_.AppliesTo).Count; Precedence = $_.Precedence } })
            CollectedUtc = $now.ToString('o'); StaleDays = $StaleDays
        } | Save-Evidence -Name 'ad-01-forest-domain' -Single
    }

    Invoke-Step 'Trusts' {
        Get-ADTrust -Filter * @srv | ForEach-Object { [ordered]@{ Name = $_.Name; Direction = [string]$_.Direction; TrustType = [string]$_.TrustType; SidFilteringQuarantined = $_.SIDFilteringQuarantined; SidFilteringForestAware = $_.SIDFilteringForestAware; SelectiveAuthentication = $_.SelectiveAuthentication; IntraForest = $_.IntraForest; TgtDelegation = $_.TGTDelegation } } | Save-Evidence -Name 'ad-01-trusts' -Csv
    }

    Invoke-Step 'Domain controllers' {
        Get-ADDomainController -Filter * @srv | ForEach-Object { [ordered]@{ Name = $_.Name; OperatingSystem = $_.OperatingSystem; OperatingSystemVersion = $_.OperatingSystemVersion; Site = $_.Site; IsGlobalCatalog = $_.IsGlobalCatalog; IsReadOnly = $_.IsReadOnly; IPv4Address = $_.IPv4Address; Supported = ([string]$_.OperatingSystem -match '2016|2019|2022|2025') } } | Save-Evidence -Name 'ad-02-domain-controllers' -Csv
    }

    Invoke-Step 'Privileged groups' {
        $groups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Server Operators', 'Print Operators', 'Backup Operators', 'DnsAdmins', 'Group Policy Creator Owners')
        $rows = foreach ($g in $groups) {
            $members = @()
            try { $members = @(Get-ADGroupMember -Identity $g -Recursive @srv) } catch { if ($_.Exception.Message -notmatch 'Cannot find') { throw } else { continue } }
            foreach ($m in $members) { [ordered]@{ Group = $g; Name = $m.Name; SamAccountName = $m.SamAccountName; ObjectClass = $m.objectClass; DistinguishedName = $m.DistinguishedName } }
        }
        @($rows) | Save-Evidence -Name 'ad-03-privileged-groups' -Csv
        $nested = foreach ($g in $groups) { try { @(Get-ADGroupMember -Identity $g @srv | Where-Object { $_.objectClass -eq 'group' }) | ForEach-Object { [ordered]@{ Group = $g; NestedGroup = $_.Name } } } catch { $null } }
        @($nested | Where-Object { $_ }) | Save-Evidence -Name 'ad-03-nested-privileged-groups' -Csv
    }

    Invoke-Step 'Admin accounts' {
        $protected = @{}
        try { foreach ($m in @(Get-ADGroupMember -Identity 'Protected Users' -Recursive @srv)) { $protected[$m.DistinguishedName] = $true } } catch { Write-Verbose 'Protected Users not readable.' }
        Get-ADUser -LDAPFilter '(adminCount=1)' -Properties adminCount, PasswordLastSet, Enabled, ServicePrincipalName, AccountNotDelegated, mail, LastLogonTimestamp, PasswordNeverExpires, SmartcardLogonRequired @srv | ForEach-Object {
            [ordered]@{ SamAccountName = $_.SamAccountName; Name = $_.Name; Enabled = $_.Enabled; PasswordLastSet = (& $iso $_.PasswordLastSet); PasswordAgeDays = $(if ($_.PasswordLastSet) { [int]($now - $_.PasswordLastSet.ToUniversalTime()).TotalDays } else { $null }); HasSpn = (@($_.ServicePrincipalName).Count -gt 0); AccountNotDelegated = [bool]$_.AccountNotDelegated; InProtectedUsers = $protected.ContainsKey($_.DistinguishedName); HasMailbox = [bool]$_.mail; LastLogon = (& $fileTime $_.LastLogonTimestamp); PasswordNeverExpires = [bool]$_.PasswordNeverExpires; SmartcardRequired = [bool]$_.SmartcardLogonRequired }
        } | Save-Evidence -Name 'ad-03-admin-accounts' -Csv
    }

    Invoke-Step 'krbtgt and built-in accounts' {
        $krbtgt = Get-ADUser -Identity krbtgt -Properties PasswordLastSet @srv
        $rid500 = Get-ADUser -Identity "$($domain.DomainSID)-500" -Properties Enabled, PasswordLastSet, LastLogonTimestamp @srv
        $guest = Get-ADUser -Identity "$($domain.DomainSID)-501" -Properties Enabled @srv
        [ordered]@{
            KrbtgtPasswordLastSet = (& $iso $krbtgt.PasswordLastSet); KrbtgtPasswordAgeDays = [int]($now - $krbtgt.PasswordLastSet.ToUniversalTime()).TotalDays
            BuiltinAdministratorEnabled = [bool]$rid500.Enabled; BuiltinAdministratorName = $rid500.SamAccountName; BuiltinAdministratorLastLogon = (& $fileTime $rid500.LastLogonTimestamp); BuiltinAdministratorPasswordAgeDays = $(if ($rid500.PasswordLastSet) { [int]($now - $rid500.PasswordLastSet.ToUniversalTime()).TotalDays } else { $null })
            GuestEnabled = [bool]$guest.Enabled
        } | Save-Evidence -Name 'ad-04-builtin-accounts' -Single
    }

    Invoke-Step 'Delegation' {
        $dcs = @(Get-ADDomainController -Filter * @srv | ForEach-Object { $_.ComputerObjectDN })
        $computers = Get-ADComputer -LDAPFilter '(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))' -Properties TrustedForDelegation, 'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity', OperatingSystem @srv | ForEach-Object {
            [ordered]@{ Name = $_.Name; ObjectClass = 'computer'; OperatingSystem = $_.OperatingSystem; IsDomainController = ($dcs -contains $_.DistinguishedName); Unconstrained = [bool]$_.TrustedForDelegation; ConstrainedTargets = @($_.'msDS-AllowedToDelegateTo').Count; ResourceBased = ($null -ne $_.'msDS-AllowedToActOnBehalfOfOtherIdentity') }
        }
        $users = Get-ADUser -LDAPFilter '(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(msDS-AllowedToDelegateTo=*))' -Properties TrustedForDelegation, 'msDS-AllowedToDelegateTo' @srv | ForEach-Object {
            [ordered]@{ Name = $_.SamAccountName; ObjectClass = 'user'; OperatingSystem = $null; IsDomainController = $false; Unconstrained = [bool]$_.TrustedForDelegation; ConstrainedTargets = @($_.'msDS-AllowedToDelegateTo').Count; ResourceBased = $false }
        }
        @($computers) + @($users) | Save-Evidence -Name 'ad-05-delegation' -Csv
    }

    Invoke-Step 'Kerberoastable and AS-REP roastable accounts' {
        Get-ADUser -LDAPFilter '(&(servicePrincipalName=*)(!(samAccountName=krbtgt)))' -Properties ServicePrincipalName, PasswordLastSet, 'msDS-SupportedEncryptionTypes', Enabled, adminCount @srv | ForEach-Object {
            $enc = [int]$(if ($null -ne $_.'msDS-SupportedEncryptionTypes') { $_.'msDS-SupportedEncryptionTypes' } else { 0 })
            [ordered]@{ SamAccountName = $_.SamAccountName; Enabled = $_.Enabled; Spns = @($_.ServicePrincipalName).Count; PasswordAgeDays = $(if ($_.PasswordLastSet) { [int]($now - $_.PasswordLastSet.ToUniversalTime()).TotalDays } else { $null }); SupportedEncryptionTypes = $enc; AesOnly = (($enc -band 0x18) -ne 0 -and ($enc -band 0x7) -eq 0); Privileged = ([int]$(if ($null -ne $_.adminCount) { $_.adminCount } else { 0 }) -eq 1) }
        } | Save-Evidence -Name 'ad-05-kerberoastable' -Csv
        Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' -Properties Enabled, PasswordLastSet @srv | ForEach-Object { [ordered]@{ SamAccountName = $_.SamAccountName; Enabled = $_.Enabled; PasswordLastSet = (& $iso $_.PasswordLastSet) } } | Save-Evidence -Name 'ad-05-asrep-roastable' -Csv
        $gmsa = @(Get-ADServiceAccount -Filter * @srv).Count
        [ordered]@{ GroupManagedServiceAccounts = $gmsa } | Save-Evidence -Name 'ad-05-service-accounts-summary' -Single
    }

    Invoke-Step 'LAPS coverage and computers' {
        $staleBefore = $now.AddDays(-$StaleDays)
        # The LAPS attributes exist only where the schema was extended; asking for a missing one fails the whole query.
        $schemaDn = (Get-ADRootDSE @srv).schemaNamingContext
        $lapsAttrs = @('msLAPS-PasswordExpirationTime', 'ms-Mcs-AdmPwdExpirationTime') | Where-Object { @(Get-ADObject -SearchBase $schemaDn -LDAPFilter "(lDAPDisplayName=$_)" @srv).Count -gt 0 }
        $hasWindowsLaps = $lapsAttrs -contains 'msLAPS-PasswordExpirationTime'; $hasLegacyLaps = $lapsAttrs -contains 'ms-Mcs-AdmPwdExpirationTime'
        $computers = Get-ADComputer -Filter 'Enabled -eq $true' -Properties (@('OperatingSystem', 'LastLogonTimestamp', 'PasswordLastSet') + @($lapsAttrs)) @srv
        $rows = @($computers | ForEach-Object {
                $last = $(if ($_.LastLogonTimestamp) { [DateTime]::FromFileTimeUtc($_.LastLogonTimestamp) } else { $null })
                [ordered]@{ Name = $_.Name; OperatingSystem = $_.OperatingSystem; IsServer = ([string]$_.OperatingSystem -match 'Server'); IsDomainController = $false; LastLogon = $(if ($last) { $last.ToString('o') } else { $null }); Stale = ($null -eq $last -or $last -lt $staleBefore); WindowsLaps = ($hasWindowsLaps -and $null -ne $_.'msLAPS-PasswordExpirationTime'); LegacyLaps = ($hasLegacyLaps -and $null -ne $_.'ms-Mcs-AdmPwdExpirationTime') }
            })
        $dcNames = @(Get-ADDomainController -Filter * @srv | ForEach-Object { $_.Name })
        foreach ($r in $rows) { if ($dcNames -contains $r.Name) { $r.IsDomainController = $true } }
        $rows | Save-Evidence -Name 'ad-06-computers' -Csv
        $windows = @($rows | Where-Object { -not $_.IsDomainController -and -not $_.Stale -and [string]$_.OperatingSystem -match 'Windows' })
        [ordered]@{
            EnabledComputers = $rows.Count; ActiveWindowsNonDc = $windows.Count
            WindowsLaps = @($windows | Where-Object { $_.WindowsLaps }).Count; LegacyLaps = @($windows | Where-Object { $_.LegacyLaps -and -not $_.WindowsLaps }).Count
            ByOperatingSystem = @($rows | Group-Object { [string]$_.OperatingSystem } | ForEach-Object { [ordered]@{ Name = $_.Name; Count = $_.Count } } | Sort-Object { -$_.Count })
            StaleComputers = @($rows | Where-Object { $_.Stale }).Count; WindowsLapsSchema = $hasWindowsLaps; LegacyLapsSchema = $hasLegacyLaps
        } | Save-Evidence -Name 'ad-06-computers-summary' -Single
    }

    Invoke-Step 'Users: stale, password never expires' {
        $staleBefore = $now.AddDays(-$StaleDays)
        $users = Get-ADUser -Filter * -Properties Enabled, LastLogonTimestamp, PasswordNeverExpires, PasswordLastSet, whenChanged, ServicePrincipalName @srv
        $enabled = @($users | Where-Object { $_.Enabled })
        $stale = @($enabled | Where-Object { $t = $_.LastLogonTimestamp; (-not $t) -or [DateTime]::FromFileTimeUtc($t) -lt $staleBefore })
        $never = @($enabled | Where-Object { $_.PasswordNeverExpires -and @($_.ServicePrincipalName).Count -eq 0 })
        [ordered]@{ Users = @($users).Count; Enabled = $enabled.Count; Disabled = @($users).Count - $enabled.Count; StaleEnabled = $stale.Count; PasswordNeverExpiresEnabledHumans = $never.Count; StaleDays = $StaleDays } | Save-Evidence -Name 'ad-07-users-summary' -Single
        $never | ForEach-Object { [ordered]@{ SamAccountName = $_.SamAccountName; PasswordLastSet = (& $iso $_.PasswordLastSet) } } | Save-Evidence -Name 'ad-07-password-never-expires' -Csv
        $stale | ForEach-Object { [ordered]@{ SamAccountName = $_.SamAccountName; LastLogon = (& $fileTime $_.LastLogonTimestamp) } } | Save-Evidence -Name 'ad-07-stale-users' -Csv
    }

    Invoke-Step 'Group Policy inventory' {
        if (-not $hasGpo) { throw 'GroupPolicy module not available; GPO inventory skipped. On Windows Server: Install-WindowsFeature GPMC. On Windows 10 or 11: Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0. Then open a new PowerShell window and run this script again.' }
        $gpos = @(Get-GPO -All @srv)
        $rows = foreach ($g in $gpos) {
            $xml = [xml](Get-GPOReport -Guid $g.Id -ReportType Xml @srv)
            $links = @($xml.GPO.LinksTo | ForEach-Object { $_.SOMPath })
            $cpassword = ($xml.OuterXml -match 'cpassword=')
            [ordered]@{ Name = $g.DisplayName; Id = [string]$g.Id; Status = [string]$g.GpoStatus; Created = (& $iso $g.CreationTime); Modified = (& $iso $g.ModificationTime); Links = $links.Count; LinkedTo = ($links -join ' | '); HasCpassword = $cpassword; UserVersion = $g.User.DSVersion; ComputerVersion = $g.Computer.DSVersion }
        }
        @($rows) | Save-Evidence -Name 'ad-08-gpos' -Csv
    }

    Invoke-Step 'AD CS' {
        $cas = @(Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configDn" -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties dNSHostName, certificateTemplates, cACertificate @srv)
        $templates = @(Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configDn" -LDAPFilter '(objectClass=pKICertificateTemplate)' -Properties 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', pKIExtendedKeyUsage, 'msPKI-RA-Signature', 'msPKI-Template-Schema-Version' @srv)
        $published = @($cas | ForEach-Object { @($_.certificateTemplates) } | ForEach-Object { [string]$_ })
        $rows = foreach ($t in $templates) {
            $nameFlag = [int]$(if ($null -ne $t.'msPKI-Certificate-Name-Flag') { $t.'msPKI-Certificate-Name-Flag' } else { 0 })
            $enrollFlag = [int]$(if ($null -ne $t.'msPKI-Enrollment-Flag') { $t.'msPKI-Enrollment-Flag' } else { 0 })
            $eku = @($t.pKIExtendedKeyUsage | ForEach-Object { [string]$_ })
            $suppliesSubject = (($nameFlag -band 1) -ne 0)
            $clientAuth = ($eku.Count -eq 0 -or $eku -contains '1.3.6.1.5.5.7.3.2' -or $eku -contains '1.3.6.1.4.1.311.20.2.2' -or $eku -contains '2.5.29.37.0')
            $noApproval = (($enrollFlag -band 2) -eq 0)
            $noSignature = ([int]$(if ($null -ne $t.'msPKI-RA-Signature') { $t.'msPKI-RA-Signature' } else { 0 }) -eq 0)
            [ordered]@{ Name = $t.Name; Published = ($published -contains $t.Name); EnrolleeSuppliesSubject = $suppliesSubject; ClientAuthentication = $clientAuth; ManagerApprovalRequired = (-not $noApproval); AuthorizedSignaturesRequired = (-not $noSignature); AnyPurpose = ($eku -contains '2.5.29.37.0'); Esc1Candidate = ($published -contains $t.Name) -and $suppliesSubject -and $clientAuth -and $noApproval -and $noSignature }
        }
        [ordered]@{ EnrollmentServices = @($cas | ForEach-Object { [ordered]@{ Name = $_.Name; Host = $_.dNSHostName; Templates = @($_.certificateTemplates).Count } }); Present = ($cas.Count -gt 0) } | Save-Evidence -Name 'ad-09-adcs' -Single
        @($rows) | Save-Evidence -Name 'ad-09-adcs-templates' -Csv
    }

    Invoke-Step 'Entra hybrid accounts' {
        $sso = $null; try { $sso = Get-ADComputer -Identity 'AZUREADSSOACC' -Properties PasswordLastSet @srv } catch { Write-Verbose 'No AZUREADSSOACC account.' }
        $kerb = $null; try { $kerb = Get-ADComputer -Identity 'AzureADKerberos' -Properties PasswordLastSet @srv } catch { Write-Verbose 'No AzureADKerberos account.' }
        [ordered]@{
            SeamlessSsoPresent = [bool]$sso; SeamlessSsoKeyAgeDays = $(if ($sso -and $sso.PasswordLastSet) { [int]($now - $sso.PasswordLastSet.ToUniversalTime()).TotalDays } else { $null })
            CloudKerberosTrustPresent = [bool]$kerb
        } | Save-Evidence -Name 'ad-10-entra-accounts' -Single
    }
}
finally {
    Stop-Transcript | Out-Null
}
Write-Host "`nDone. Copy the folder $out into the run's evidence folder next to the cloud files."
if (Test-Path $errorsPath) { Write-Warning "Some steps failed; see $errorsPath" }
