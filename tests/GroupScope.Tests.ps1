# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# The scope of a group a Conditional Access policy names: how many members, and a hash of who they are. The hash is
# taken without holding the members, and a very large group ("all users" in a large tenant) is counted in one
# request instead of read a page per 999 members on every run.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    $script:Sample = Join-Path $PSScriptRoot '..' 'samples' 'ca-snapshot'
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-scope-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    # A group of three members over two pages. TKP_SCOPE_COUNT is what Graph says the group's size is.
    Mock -ModuleName TenantKeep.Posture Invoke-MgGraphRequest {
        $path = [uri]::UnescapeDataString(([uri]$Uri).PathAndQuery) -replace '^/(v1\.0|beta)/', ''
        if ($path -match '\$count=true') {
            if ($env:TKP_SCOPE_COUNT -eq 'refused') { throw 'Request_UnsupportedQuery: the count is not available.' }
            if (-not $Headers -or $Headers['ConsistencyLevel'] -ne 'eventual') { throw 'Request_BadRequest: ConsistencyLevel: eventual is required for $count.' }
            return @{ '@odata.count' = [long]$env:TKP_SCOPE_COUNT; value = @(@{ id = 'm-b' }) }
        }
        if ($path -match 'skiptoken=2') { return @{ value = @(@{ '@odata.type' = '#microsoft.graph.user'; id = 'm-a'; displayName = 'Amy'; userPrincipalName = 'amy@contoso.example' }) } }
        return @{ value = @(@{ '@odata.type' = '#microsoft.graph.user'; id = 'm-c'; displayName = 'Cy' }, @{ '@odata.type' = '#microsoft.graph.group'; id = 'm-b'; displayName = 'Nested' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/groups/g1/transitiveMembers?$skiptoken=2' }
    }
    $script:Expected = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes("m-a`nm-b`nm-c"))).ToLowerInvariant()
    $script:Pages = { param([int] $Times) Should -Invoke -ModuleName TenantKeep.Posture Invoke-MgGraphRequest -Times $Times -Exactly -Scope It -ParameterFilter { $Uri -notmatch 'count=true' } }
}

AfterAll {
    Remove-Item Env:TKP_SCOPE_COUNT -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Get-PostureGroupScope' {
    It 'hashes the sorted member ids joined by a line feed, the hash earlier versions wrote' {
        $env:TKP_SCOPE_COUNT = '3'
        $s = InModuleScope TenantKeep.Posture { Get-PostureGroupScope -GroupId 'g1' }
        $s.memberCount | Should -Be 3
        $s.memberHash | Should -Be $script:Expected
        $s.Contains('members') | Should -BeFalse
        $s.Contains('hashSkipped') | Should -BeFalse
        & $script:Pages 2
    }

    It 'counts a group over the threshold in one request and does not read its members' {
        $env:TKP_SCOPE_COUNT = '300000'
        $s = InModuleScope TenantKeep.Posture { Get-PostureGroupScope -GroupId 'g1' }
        $s.memberCount | Should -Be 300000
        $s.memberHash | Should -BeNullOrEmpty
        $s.hashSkipped | Should -Match '^More than 50000 members: counted, not hashed'
        & $script:Pages 0
    }

    It 'hashes a large group all the same with -HashLargeGroups, and with -IncludeMembers lists who is in it' {
        $env:TKP_SCOPE_COUNT = '300000'
        $s = InModuleScope TenantKeep.Posture { Get-PostureGroupScope -GroupId 'g1' -HashLargeGroups }
        $s.memberHash | Should -Be $script:Expected
        $m = InModuleScope TenantKeep.Posture { Get-PostureGroupScope -GroupId 'g1' -IncludeMembers }
        $m.memberHash | Should -Be $script:Expected
        @($m.members | ForEach-Object { $_.id }) | Should -Be @('m-a', 'm-b', 'm-c')
        $m.members[0].userPrincipalName | Should -Be 'amy@contoso.example'
        Should -Invoke -ModuleName TenantKeep.Posture Invoke-MgGraphRequest -Times 0 -Exactly -Scope It -ParameterFilter { $Uri -match 'count=true' } -Because 'neither asks for the size first'
    }

    It 'reads the group as before when Graph does not answer the count' {
        $env:TKP_SCOPE_COUNT = 'refused'
        $s = InModuleScope TenantKeep.Posture { Get-PostureGroupScope -GroupId 'g1' }
        $s.memberCount | Should -Be 3
        $s.memberHash | Should -Be $script:Expected
    }

    It 'takes the threshold as a size, not a rule: a group at the threshold is hashed' {
        $env:TKP_SCOPE_COUNT = '3'
        (InModuleScope TenantKeep.Posture { Get-PostureGroupScope -GroupId 'g1' -LargeGroupThreshold 3 }).memberHash | Should -Be $script:Expected
        (InModuleScope TenantKeep.Posture { Get-PostureGroupScope -GroupId 'g1' -LargeGroupThreshold 2 }).memberHash | Should -BeNullOrEmpty
    }
}

Describe 'Scope drift for a group that is only counted' {
    BeforeAll {
        $script:Pair = {
            param([string] $Name, [scriptblock] $Change)
            $before = Join-Path $script:Root "$Name-before"; $after = Join-Path $script:Root "$Name-after"
            Copy-Item -Path $script:Sample -Destination $before -Recurse; Copy-Item -Path $script:Sample -Destination $after -Recurse
            $file = Join-Path $after 'group-scope.json'
            $g = Get-Content -Raw -LiteralPath $file | ConvertFrom-Json -AsHashtable -Depth 30
            & $Change ($g | Where-Object groupId -eq '22222222-2222-2222-2222-222222222202')
            ConvertTo-Json -InputObject $g -Depth 30 | Set-Content -LiteralPath $file
            $r = Compare-PostureCaSnapshot -Before $before -After $after -OutputPath (Join-Path $script:Root "$Name-out") -PassThru -WarningAction SilentlyContinue
            Get-Content -Raw -LiteralPath ($r.Files | Where-Object { $_ -like '*.md' })
        }
    }

    It 'reports nothing when the hash is no longer taken and the count is the same' {
        $md = & $script:Pair 'same' { param($group) $group.memberHash = $null; $group.hashSkipped = 'More than 50000 members: counted, not hashed.' }
        $md | Should -Not -Match 'CA-Exclude-MFA-Legacy \|' -Because 'a hash that was not taken is not a change in who is in the group'
    }

    It 'reports the change in count when the count moved' {
        $md = & $script:Pair 'moved' { param($group) $group.memberHash = $null; $group.memberCount = 350 }
        $md | Should -Match '\| CA-Exclude-MFA-Legacy \| 341 \| 350 \| \+9 \|' -Because 'one drifted group is one row of the table'
        $md | Should -Match '\| Before snapshot \| \S+moved-before \|' -Because 'the appendix names the folder in its own cell'
    }
}
