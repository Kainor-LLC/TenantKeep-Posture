# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'Tenantkeep.Posture.psd1') -Force
    . (Join-Path $PSScriptRoot 'Fixtures' 'CollectionFixture.ps1')
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-ops-$([guid]::NewGuid().ToString('n'))"
    $script:Ev = Initialize-CollectionFixture -Root (Join-Path $script:Root 'evidence')
    $w = { param([string] $Name, $Data) ConvertTo-Json -InputObject $Data -Depth 10 | Set-Content -LiteralPath (Join-Path $script:Ev "$Name.json") }
    & $w '09-apple-push-cert' @{ Present = $true; AppleIdentifier = 'apple@contoso.example'; ExpirationDateTime = '2026-10-20T00:00:00Z' }
    & $w '09-apple-vpp-tokens' @(@{ OrganizationName = 'Contoso'; ExpirationDateTime = '2027-06-01T00:00:00Z' })
    & $w '10-service-principals' @(@{ DisplayName = 'Payroll SAML'; PreferredSingleSignOnMode = 'saml'; SamlCertExpiry = '2026-10-24T00:00:00Z'; IsEnterpriseAppListed = $true; AccountEnabled = $true }, @{ DisplayName = 'Gallery app'; PreferredSingleSignOnMode = 'oidc'; SamlCertExpiry = '2026-10-20T00:00:00Z'; IsEnterpriseAppListed = $true; AccountEnabled = $true })
    & $w 'def-06-secure-score' @{ Present = $true; CurrentScore = 412.5; MaxScore = 900; AverageComparativeScores = @(@{ Basis = 'AllTenants'; AverageScore = 390 }, @{ Basis = 'TotalSeats'; AverageScore = 420 }) }
    $script:AsOf = [datetime]::new(2026, 10, 14, 0, 0, 0, [System.DateTimeKind]::Utc)
    $script:ProfilePath = Join-Path $script:Root 'profile.json'
    $null = New-PostureProfile -Path $script:ProfilePath -NonInteractive -ClientName 'Contoso' -ThirdParty @{ siem = 'Sentinel'; backup = 'none' } -BreakGlassTestedUtc ([datetime]::new(2026, 9, 1, 0, 0, 0, [System.DateTimeKind]::Utc)) -MessageCenterOwner 'IT ops'
}

AfterAll { if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force } }

Describe 'Get-PostureOperationsFact' {
    It 'reads the operations answers, compares Secure Score and builds the expiry calendar soonest first' {
        InModuleScope Tenantkeep.Posture -Parameters @{ E = $script:Ev; P = $script:ProfilePath; AsOf = $script:AsOf } {
            $r = Get-PostureOperationsFact -Evidence $E -OrgProfile (Import-PostureProfile -Path $P) -Thresholds @{} -AsOf $AsOf
            $r.facts.siemInPlace | Should -BeTrue
            $r.facts.backupDecisionRecorded | Should -BeFalse
            $r.facts.breakGlassTestAgeDays | Should -Be 43
            $r.facts.breakGlassTestedRecently | Should -BeTrue
            $r.facts.messageCenterOwnerNamed | Should -BeTrue
            $r.facts.secureScoreAtOrAboveAverage | Should -BeTrue
            $r.facts.secureScoreAllTenantsAverage | Should -Be 390
            $r.facts.expiryCalendarSources | Should -Be 4
            @($r.facts.expiryCalendar)[0].kind | Should -Be 'Application credential' -Because 'Old App expired in 2024 and sorts first'
            @($r.facts.expiryCalendar | Where-Object { $_.kind -eq 'Apple push certificate' })[0].days | Should -Be 6
            $r.facts.expiringWithinWarning | Should -Be 4 -Because 'the expired credential, Soon App on 2026-10-25, the Apple certificate and the SAML certificate; the OIDC app does not count'
            $r.notEvaluated.ContainsKey('OP-007') | Should -BeTrue
        }
    }

    It 'leaves the answered checks not evaluated without a profile' {
        InModuleScope Tenantkeep.Posture -Parameters @{ E = $script:Ev; AsOf = $script:AsOf } {
            $r = Get-PostureOperationsFact -Evidence $E -OrgProfile (Import-PostureProfile) -Thresholds @{} -AsOf $AsOf
            $r.notEvaluated.Keys | Should -Contain 'OP-003'
            $r.facts.expiringWithinWarning | Should -Be 4
        }
    }
}

Describe 'Invoke-PostureChecks for operations' {
    It 'gives the expected statuses' {
        $run = Invoke-PostureChecks -Evidence $script:Ev -ProfilePath $script:ProfilePath -Domain operations -PassThru
        $by = @{}; foreach ($x in $run.results) { $by[$x.id] = $x }
        $by['OP-001'].status | Should -Be 'pass'
        $by['OP-002'].status | Should -Be 'fail'
        $by['OP-003'].status | Should -Be 'pass'
        $by['OP-004'].status | Should -Be 'pass'
        $by['OP-005'].status | Should -Be 'pass'
        $by['OP-006'].status | Should -Be 'fail'
        $by['OP-006'].affectedCount | Should -Be 4
        $by['OP-007'].status | Should -Be 'notApplicable' -Because 'the fixture profile is cloud-only'
    }
}
