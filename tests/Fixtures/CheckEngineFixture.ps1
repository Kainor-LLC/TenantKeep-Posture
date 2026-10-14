# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
function Initialize-CheckEngineFixture {
    <#
    .SYNOPSIS
        Writes a small 'test' domain catalog, baselines, a profile and exceptions under -Root for the engine tests.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Root)

    $checks = Join-Path $Root 'checks'
    $baselines = Join-Path $Root 'baselines'
    New-Item -ItemType Directory -Path $checks, $baselines -Force | Out-Null
    '{ "version": "test.1" }' | Set-Content (Join-Path $checks 'catalog.json')
    $catalog = @{
        domain = 'test'
        checks = @(
            @{ id = 'TS-001'; domain = 'test'; title = 'Count under limit'; severityDefault = 'High'; license = @(); applicableWhen = @{}; coveredBy = @(); thresholds = @{ max = 2 }; evidence = @('e.json'); pass = 'facts.count <= thresholds.max'; affected = 'facts.items'; remediation = 'r'; learn = 'https://learn.microsoft.com/'; deepLink = $null; narrative = 'n'; frameworks = @{} }
            @{ id = 'TS-002'; domain = 'test'; title = 'Needs P2'; severityDefault = 'Medium'; license = @('P2'); applicableWhen = @{}; coveredBy = @(); thresholds = @{}; evidence = @(); pass = 'facts.enabled'; remediation = 'r'; learn = 'https://learn.microsoft.com/'; deepLink = $null; narrative = 'n'; frameworks = @{} }
            @{ id = 'TS-003'; domain = 'test'; title = 'macOS only'; severityDefault = 'Low'; license = @(); applicableWhen = @{ platforms = @('macOS') }; coveredBy = @(); thresholds = @{}; evidence = @(); pass = 'facts.enabled'; remediation = 'r'; learn = 'https://learn.microsoft.com/'; deepLink = $null; narrative = 'n'; frameworks = @{} }
            @{ id = 'TS-004'; domain = 'test'; title = 'Covered by MFA vendor'; severityDefault = 'High'; license = @(); applicableWhen = @{}; coveredBy = @('mfa:*'); thresholds = @{}; evidence = @(); pass = 'facts.enabled'; remediation = 'r'; learn = 'https://learn.microsoft.com/'; deepLink = $null; narrative = 'n'; frameworks = @{} }
            @{ id = 'TS-005'; domain = 'test'; title = 'Missing fact'; severityDefault = 'Low'; license = @(); applicableWhen = @{}; coveredBy = @(); thresholds = @{}; evidence = @(); pass = 'facts.nope == 1'; remediation = 'r'; learn = 'https://learn.microsoft.com/'; deepLink = $null; narrative = 'n'; frameworks = @{} }
            @{ id = 'TS-006'; domain = 'test'; title = 'Always fails'; severityDefault = 'Critical'; license = @(); applicableWhen = @{}; coveredBy = @(); thresholds = @{}; evidence = @(); pass = 'facts.enabled == false'; remediation = 'r'; learn = 'https://learn.microsoft.com/'; deepLink = $null; narrative = 'n'; frameworks = @{} }
            @{ id = 'OT-001'; domain = 'other'; title = 'No provider'; severityDefault = 'Low'; license = @(); applicableWhen = @{}; coveredBy = @(); thresholds = @{}; evidence = @(); pass = 'facts.x == 1'; remediation = 'r'; learn = 'https://learn.microsoft.com/'; deepLink = $null; narrative = 'n'; frameworks = @{} }
        )
    }
    ConvertTo-Json -InputObject $catalog -Depth 10 | Set-Content (Join-Path $checks 'test.json')
    '{ "name": "standard", "checks": ["*"] }' | Set-Content (Join-Path $baselines 'standard.json')
    @{ name = 'strict'; checks = @('TS-001', 'TS-006'); thresholds = @{ 'TS-001' = @{ max = 5 } }; severity = @{ 'TS-006' = 'Low' } } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $baselines 'strict.json')
    @{ licenses = @('P1'); platforms = @('windows'); thirdParty = @{ mfa = 'duo' }; thresholds = @{ max = 3 } } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $Root 'profile.json')
    @(
        @{ check = 'TS-006'; justification = 'Known, scheduled'; owner = 'J. Smith'; approver = 'CISO'; expires = '2099-01-01' }
        @{ check = 'TS-001'; object = 'beta'; justification = 'Lab group'; owner = 'J. Smith'; approver = 'CISO'; expires = '2099-01-01' }
        @{ check = 'TS-001'; object = 'gamma'; justification = 'Expired one'; owner = 'J. Smith'; approver = 'CISO'; expires = '2020-01-01' }
    ) | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $Root 'exceptions.json')
    $provider = {
        param($Evidence, $OrgProfile, $Thresholds)
        @{ facts = @{ count = 3; enabled = $true; items = @(@{ name = 'alpha' }, @{ name = 'beta' }, @{ name = 'gamma' }) }; affected = @{ items = @(@{ name = 'alpha' }, @{ name = 'beta' }, @{ name = 'gamma' }) }; evidence = @('provider.json'); thresholdsSeen = $Thresholds }
    }
    return [pscustomobject]@{ Checks = $checks; Baselines = $baselines; Profile = (Join-Path $Root 'profile.json'); Exceptions = (Join-Path $Root 'exceptions.json'); Provider = $provider }
}
