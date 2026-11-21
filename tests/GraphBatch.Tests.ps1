# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# Reads that Graph answers one object at a time go through $batch, twenty to a request.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
}

Describe 'Invoke-PostureGraphBatch' {
    It 'sends twenty requests to a batch, GET only, and returns one answer per URL in the order asked' {
        InModuleScope TenantKeep.Posture {
            $script:Sent = [System.Collections.Generic.List[object]]::new()
            Mock Invoke-PostureGraphRequest {
                $script:Sent.Add($Body)
                @{ responses = @($Body.requests | Sort-Object { [int]$_.id } -Descending | ForEach-Object { @{ id = $_.id; status = 200; body = @{ value = @(@{ asked = $_.url }) } } }) }
            }
            $urls = @(1..45 | ForEach-Object { "groups/g$_/owners?`$select=id" })
            $a = @(Invoke-PostureGraphBatch -Url $urls -ApiVersion 'v1.0')
            $a.Count | Should -Be 45
            $script:Sent.Count | Should -Be 3 -Because 'twenty, twenty and five'
            @($script:Sent | ForEach-Object { $_.requests } | Where-Object { $_.method -ne 'GET' }).Count | Should -Be 0
            $a[0].url | Should -Be $urls[0]
            $a[44].body.value[0].asked | Should -Be '/groups/g45/owners?$select=id' -Because 'an answer is matched to its request by id, whatever order Graph returns them in'
            Should -Invoke Invoke-PostureGraphRequest -Times 3 -Exactly -ParameterFilter { $Uri -eq '$batch' -and $Method -eq 'POST' -and $Single }
        }
    }

    It 'sends a throttled request again and keeps the answers that arrived' {
        InModuleScope TenantKeep.Posture {
            Mock Start-Sleep { }
            $script:Calls = 0
            Mock Invoke-PostureGraphRequest {
                $script:Calls++
                $first = $script:Calls -eq 1
                @{ responses = @($Body.requests | ForEach-Object { if ($first -and $_.id -eq '1') { @{ id = $_.id; status = 429; headers = @{ 'Retry-After' = '2' }; body = @{ error = @{ message = 'throttled' } } } } else { @{ id = $_.id; status = 200; body = @{ ok = $_.url } } } }) }
            }
            $a = @(Invoke-PostureGraphBatch -Url 'a', 'b', 'c' -ApiVersion 'beta')
            @($a | ForEach-Object { $_.status }) | Should -Be @(200, 200, 200)
            $script:Calls | Should -Be 2 -Because 'only the throttled request is sent again'
            Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter { $Seconds -ge 2 }
        }
    }

    It 'returns a refusal as an answer with Graph''s message, follows a next link, and marks a request that got no answer' {
        InModuleScope TenantKeep.Posture {
            Mock Invoke-PostureGraphRequest {
                if ($Uri -eq '$batch') {
                    return @{ responses = @(
                            @{ id = '0'; status = 403; body = @{ error = @{ code = 'Authorization_RequestDenied'; message = 'Insufficient privileges.' } } }
                            @{ id = '1'; status = 200; body = @{ value = @(@{ id = 'x1' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/more' } }
                        )
                    }
                }
                @(@{ id = 'x2' }, @{ id = 'x3' })
            }
            $a = @(Invoke-PostureGraphBatch -Url 'refused', 'paged', 'lost' -ApiVersion 'v1.0')
            $a[0].status | Should -Be 403
            $a[0].error | Should -Be 'Insufficient privileges.'
            @($a[1].body.value | ForEach-Object { $_.id }) | Should -Be @('x1', 'x2', 'x3')
            $a[2].status | Should -Be 0
            $a[2].error | Should -Match 'No answer'
        }
    }

    It 'asks nothing for an empty list' {
        InModuleScope TenantKeep.Posture {
            Mock Invoke-PostureGraphRequest { throw 'not expected' }
            @(Invoke-PostureGraphBatch -Url @() -ApiVersion 'v1.0').Count | Should -Be 0
        }
    }
}
