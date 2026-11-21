#Requires -Version 5.1
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    Windows-only, read-only Active Directory collector for the hybrid domain (spec 4.14, audit plan Appendix B). Run
    it once on any domain-joined Windows machine with RSAT, bring the output folder into the run with
    Import-PostureEvidence, and the hybrid checks evaluate from it. Nothing is installed, nothing is changed, nothing
    is scheduled. bundle.json lists every file with its SHA-256, which the import checks.
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
    Then, where the run lives: Import-PostureEvidence -Path C:\audit\ad-20261015 -Run <run folder>
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
$written = New-Object System.Collections.Generic.List[string]
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
        $written.Add("$Name.json")
        if ($Csv -and $items.Count -gt 0) { $items | Export-Csv -Path (Join-Path $out "$Name.csv") -NoTypeInformation -Encoding UTF8; $written.Add("$Name.csv") }
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
            # What this run covered: one domain. A forest with more is read one domain at a time, and the report says
            # which one it judged.
            ForestDomains = @($forest.Domains | ForEach-Object { [string]$_ }); DomainsCollected = @([string]$domain.DNSRoot)
            UpnSuffixes = @(@($forest.Domains) + @($forest.UPNSuffixes) | ForEach-Object { [string]$_ } | Where-Object { $_ } | Sort-Object -Unique)
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
        # Through the pipeline: each computer becomes its row and is counted as it arrives, so the directory's
        # objects are never held (a list of them is gigabytes in a large domain). The rows are what is kept.
        $dcNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        Get-ADDomainController -Filter * @srv | ForEach-Object { [void]$dcNames.Add([string]$_.Name) }
        $t = @{ n = 0; activeWindows = 0; workstations = 0; windowsLaps = 0; legacyLaps = 0; stale = 0; os = @{} }
        $rows = New-Object 'System.Collections.Generic.List[object]'
        Get-ADComputer -Filter 'Enabled -eq $true' -Properties (@('OperatingSystem', 'LastLogonTimestamp', 'PasswordLastSet') + @($lapsAttrs)) @srv | ForEach-Object {
            $last = $(if ($_.LastLogonTimestamp) { [DateTime]::FromFileTimeUtc($_.LastLogonTimestamp) } else { $null })
            $row = [ordered]@{ Name = $_.Name; OperatingSystem = $_.OperatingSystem; IsServer = ([string]$_.OperatingSystem -match 'Server'); IsDomainController = $dcNames.Contains([string]$_.Name); LastLogon = $(if ($last) { $last.ToString('o') } else { $null }); Stale = ($null -eq $last -or $last -lt $staleBefore); WindowsLaps = ($hasWindowsLaps -and $null -ne $_.'msLAPS-PasswordExpirationTime'); LegacyLaps = ($hasLegacyLaps -and $null -ne $_.'ms-Mcs-AdmPwdExpirationTime') }
            $rows.Add($row)
            $t.n++
            $osName = [string]$row.OperatingSystem
            if ($t.os.ContainsKey($osName)) { $t.os[$osName]++ } else { $t.os[$osName] = 1 }
            if ($row.Stale) { $t.stale++ }
            if (-not $row.IsDomainController -and -not $row.Stale -and $osName -match 'Windows') {
                $t.activeWindows++
                if (-not $row.IsServer) { $t.workstations++ }
                if ($row.WindowsLaps) { $t.windowsLaps++ } elseif ($row.LegacyLaps) { $t.legacyLaps++ }
            }
            if ($t.n % 5000 -eq 0) { Write-Progress -Activity 'Computers' -Status "$($t.n) read" }
        }
        Write-Progress -Activity 'Computers' -Completed
        $rows | Save-Evidence -Name 'ad-06-computers' -Csv
        [ordered]@{
            EnabledComputers = $t.n; ActiveWindowsNonDc = $t.activeWindows; ActiveWindowsWorkstations = $t.workstations
            WindowsLaps = $t.windowsLaps; LegacyLaps = $t.legacyLaps
            ByOperatingSystem = @($t.os.GetEnumerator() | ForEach-Object { [ordered]@{ Name = $_.Key; Count = $_.Value } } | Sort-Object { -$_.Count })
            StaleComputers = $t.stale; WindowsLapsSchema = $hasWindowsLaps; LegacyLapsSchema = $hasLegacyLaps
        } | Save-Evidence -Name 'ad-06-computers-summary' -Single
    }

    Invoke-Step 'Users: stale, password never expires' {
        $staleBefore = $now.AddDays(-$StaleDays)
        # One pass through the pipeline: every user is counted as it arrives and only the two short lists are kept.
        # Assigned to a variable, the users of a large domain are gigabytes of objects in Windows PowerShell.
        $t = @{ n = 0; enabled = 0 }
        $stale = New-Object 'System.Collections.Generic.List[object]'; $never = New-Object 'System.Collections.Generic.List[object]'
        Get-ADUser -Filter * -Properties Enabled, LastLogonTimestamp, PasswordNeverExpires, PasswordLastSet, ServicePrincipalName @srv | ForEach-Object {
            $t.n++
            if ($t.n % 5000 -eq 0) { Write-Progress -Activity 'Users' -Status "$($t.n) read" }
            if (-not $_.Enabled) { return }
            $t.enabled++
            $stamp = $_.LastLogonTimestamp
            if ((-not $stamp) -or [DateTime]::FromFileTimeUtc($stamp) -lt $staleBefore) { $stale.Add([ordered]@{ SamAccountName = $_.SamAccountName; LastLogon = (& $fileTime $stamp) }) }
            if ($_.PasswordNeverExpires -and @($_.ServicePrincipalName).Count -eq 0) { $never.Add([ordered]@{ SamAccountName = $_.SamAccountName; PasswordLastSet = (& $iso $_.PasswordLastSet) }) }
        }
        Write-Progress -Activity 'Users' -Completed
        [ordered]@{ Users = $t.n; Enabled = $t.enabled; Disabled = $t.n - $t.enabled; StaleEnabled = $stale.Count; PasswordNeverExpiresEnabledHumans = $never.Count; StaleDays = $StaleDays } | Save-Evidence -Name 'ad-07-users-summary' -Single
        $never | Save-Evidence -Name 'ad-07-password-never-expires' -Csv
        $stale | Save-Evidence -Name 'ad-07-stale-users' -Csv
    }

    Invoke-Step 'Group Policy inventory' {
        if (-not $hasGpo) { throw 'GroupPolicy module not available; GPO inventory skipped. On Windows Server: Install-WindowsFeature GPMC. On Windows 10 or 11: Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0. Then open a new PowerShell window and run this script again.' }
        $gpos = @(Get-GPO -All @srv)
        # Where each GPO is linked, from the gPLink attribute of the domain, its organizational units and the sites:
        # one directory query for all of them. (A report per GPO, as before, is hours in a domain with thousands.)
        $linksById = @{}
        $containers = @(Get-ADObject -LDAPFilter '(gPLink=*)' -SearchBase $domainDn -SearchScope Subtree -Properties gPLink, CanonicalName @srv) + @(Get-ADObject -LDAPFilter '(gPLink=*)' -SearchBase "CN=Sites,$configDn" -SearchScope Subtree -Properties gPLink, CanonicalName @srv)
        foreach ($c in $containers) {
            foreach ($m in [regex]::Matches([string]$c.gPLink, '\[LDAP://[cC][nN]=(\{[0-9A-Fa-f-]{36}\}),[^;\]]*;(\d+)\]')) {
                # Link options: bit 0 set means the link is disabled.
                if (([int]$m.Groups[2].Value -band 1) -ne 0) { continue }
                $id = $m.Groups[1].Value.Trim('{', '}').ToLowerInvariant()
                if (-not $linksById.ContainsKey($id)) { $linksById[$id] = New-Object 'System.Collections.Generic.List[string]' }
                $linksById[$id].Add([string]$c.CanonicalName)
            }
        }
        # Passwords stored in Group Policy Preferences (cpassword), from one pass over the preference files in SYSVOL.
        # When SYSVOL cannot be read the answer is unknown, never "none".
        $withPassword = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $sysvol = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies"
        $scanned = $false
        try {
            if (Test-Path -LiteralPath $sysvol) {
                Get-ChildItem -LiteralPath $sysvol -Recurse -Filter '*.xml' -File -ErrorAction Stop | Where-Object { $_.FullName -match '\\Preferences\\' } | ForEach-Object {
                    if (Select-String -LiteralPath $_.FullName -Pattern 'cpassword="[^"]' -Quiet) { if ($_.FullName -match '\{([0-9A-Fa-f-]{36})\}') { [void]$withPassword.Add($Matches[1].ToLowerInvariant()) } }
                }
                $scanned = $true
            }
        }
        catch { Add-Content -Path $errorsPath -Value "Group Policy preference files :: $((([string]$_.Exception.Message) -replace '\s*[\r\n]+\s*', ' ').Trim())" }
        $rows = foreach ($g in $gpos) {
            $id = ([string]$g.Id).ToLowerInvariant()
            $links = @($(if ($linksById.ContainsKey($id)) { $linksById[$id] }))
            [ordered]@{ Name = $g.DisplayName; Id = [string]$g.Id; Status = [string]$g.GpoStatus; Created = (& $iso $g.CreationTime); Modified = (& $iso $g.ModificationTime); Links = $links.Count; LinkedTo = ($links -join ' | '); HasCpassword = $(if ($scanned) { $withPassword.Contains($id) } else { $null }); UserVersion = $g.User.DSVersion; ComputerVersion = $g.Computer.DSVersion }
        }
        @($rows) | Save-Evidence -Name 'ad-08-gpos' -Csv
        [ordered]@{ Gpos = $gpos.Count; Linked = @($rows | Where-Object { $_.Links -gt 0 }).Count; SysvolScanned = $scanned; WithStoredPassword = $(if ($scanned) { $withPassword.Count } else { $null }) } | Save-Evidence -Name 'ad-08-gpos-summary' -Single
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
# bundle.json: what Import-PostureEvidence checks before it copies a file into a run.
$domainName = $(try { (Get-ADDomain @srv).DNSRoot } catch { '' })
$forestInfo = $(try { Get-ADForest @srv } catch { $null })
$forestDomains = @($(if ($forestInfo) { $forestInfo.Domains | ForEach-Object { [string]$_ } }))
$upnSuffixes = @($(if ($forestInfo) { @($forestInfo.Domains) + @($forestInfo.UPNSuffixes) | ForEach-Object { [string]$_ } | Where-Object { $_ } | Sort-Object -Unique }))
$files = @($written | Select-Object -Unique | ForEach-Object { [ordered]@{ name = $_; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $out $_)).Hash.ToLowerInvariant() } })
$bundle = [ordered]@{ kind = 'ad'; collector = 'Get-ADBaseline.ps1'; schema = 1; domain = $domainName; forest = $(if ($forestInfo) { [string]$forestInfo.Name } else { '' }); forestDomains = $forestDomains; upnSuffixes = $upnSuffixes; collectedUtc = $now.ToString('o'); account = [string]$env:USERNAME; powershell = [string]$PSVersionTable.PSVersion; files = $files }
[System.IO.File]::WriteAllText((Join-Path $out 'bundle.json'), (ConvertTo-Json -InputObject $bundle -Depth 5), [System.Text.UTF8Encoding]::new($false))
Write-Host "`nDone: $out. Bring it into the run: Import-PostureEvidence -Path '$out' -Run <run folder>"
if (Test-Path $errorsPath) { Write-Warning "Some steps failed; see $errorsPath" }
