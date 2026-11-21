# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# The two entry points for Azure reads under load: Resource Manager throttles per subscription and per tenant, and
# Resource Graph hands out a page token only when the rows carry an id. A run over hundreds of subscriptions meets
# both. The Az commands are stood in for, so these run where Az is not installed.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
}

Describe 'Azure requests under load' {
    BeforeAll {
        # Stand-ins for the Az commands, so the wrappers can be driven where Az is not installed.
        function global:Invoke-AzRestMethod { param($Method, $Path, $Uri, $Payload) $script:AzCalls++; & $script:AzAnswer $script:AzCalls }
        function global:Search-AzGraph { param($Query, $First, $SkipToken, $Skip, [switch] $UseTenantScope) $script:GraphAsked.Add(@{ Skip = $Skip; SkipToken = $SkipToken }); & $script:GraphAnswer $Skip }
        Mock -ModuleName TenantKeep.Posture Update-PostureServiceSession { }
        Mock -ModuleName TenantKeep.Posture Start-Sleep { }
    }
    AfterAll { Remove-Item Function:\Invoke-AzRestMethod, Function:\Search-AzGraph -ErrorAction SilentlyContinue }

    It 'waits out throttling and returns the answer that follows' {
        $script:AzCalls = 0
        $script:AzAnswer = { param($n) if ($n -lt 3) { [pscustomobject]@{ StatusCode = 429; Content = '{"error":{"code":"TooManyRequests"}}'; Headers = [pscustomobject]@{ RetryAfter = [pscustomobject]@{ Delta = [timespan]::FromSeconds(7) } } } } else { [pscustomobject]@{ StatusCode = 200; Content = '{"value":[{"name":"a"},{"name":"b"}]}' } } }
        $rows = InModuleScope TenantKeep.Posture { @(Invoke-PostureAzureRequest -Path '/subscriptions/s/providers/Microsoft.Security/pricings?api-version=2024-01-01') }
        @($rows | ForEach-Object { $_.name }) | Should -Be @('a', 'b')
        $script:AzCalls | Should -Be 3
        Should -Invoke -ModuleName TenantKeep.Posture Start-Sleep -Times 2 -Exactly -Scope It -ParameterFilter { $Seconds -ge 7 }
    }

    It 'gives up after the attempts the retry policy allows, with the status it stopped on' {
        $script:AzCalls = 0
        $script:AzAnswer = { param($n) [pscustomobject]@{ StatusCode = 429; Content = '{"error":{"code":"TooManyRequests","message":"slow down"}}' } }
        { InModuleScope TenantKeep.Posture { Invoke-PostureAzureRequest -Path '/subscriptions/s/x?api-version=1' } } | Should -Throw '*returned 429*'
        $script:AzCalls | Should -Be (InModuleScope TenantKeep.Posture { $script:PostureGraphRetry.maxAttempts })
    }

    It 'does not wait on a refusal' {
        $script:AzCalls = 0
        $script:AzAnswer = { param($n) [pscustomobject]@{ StatusCode = 403; Content = '{"error":{"code":"AuthorizationFailed"}}' } }
        { InModuleScope TenantKeep.Posture { Invoke-PostureAzureRequest -Path '/subscriptions/s/x?api-version=1' } } | Should -Throw '*returned 403*'
        $script:AzCalls | Should -Be 1
    }

    It 'pages Resource Graph by position when a full page comes with no token' {
        $script:GraphAsked = [System.Collections.Generic.List[object]]::new()
        $script:GraphAnswer = { param($skip) if (-not $skip) { @{ id = 1 }, @{ id = 2 } } elseif ($skip -eq 2) { @{ id = 3 }, @{ id = 4 } } else { , @(@{ id = 5 }) } }
        $rows = InModuleScope TenantKeep.Posture { @(Invoke-PostureAzureQuery -Query 'resources | project id' -PageSize 2) }
        @($rows | ForEach-Object { $_.id }) | Should -Be @(1, 2, 3, 4, 5)
        @($script:GraphAsked | ForEach-Object { [int]$_.Skip }) | Should -Be @(0, 2, 4)
    }

    It 'fails a query Resource Graph marks as cut short with no way to page it' {
        $script:GraphAsked = [System.Collections.Generic.List[object]]::new()
        $script:GraphAnswer = { param($skip) $page = [System.Collections.Generic.List[object]]::new(); $page.Add(@{ id = 1 }); $page | Add-Member -NotePropertyName ResultTruncated -NotePropertyValue 'true' -PassThru -Force }
        { InModuleScope TenantKeep.Posture { Invoke-PostureAzureQuery -Query 'resources | summarize count() by type' -PageSize 5 } } | Should -Throw '*cut the answer short*'
    }
}
