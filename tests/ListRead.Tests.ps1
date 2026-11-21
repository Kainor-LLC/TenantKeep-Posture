# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# A long Graph list that carries on where it stopped (Invoke-PostureListRead): the cursor, the files cut back to
# it, the tallies put back, and the cases where a cursor must not be used.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-listread-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    Mock -ModuleName TenantKeep.Posture Write-Host { }

    # A list of 95 accounts in pages of 10. The page a request asks for is in its link; $script:ListTest says which
    # page fails, how many times a page link is refused, and records every link asked for.
    $script:ListTest = @{ failAt = 0; refuse = 0; asked = [System.Collections.Generic.List[string]]::new() }
    Mock -ModuleName TenantKeep.Posture Invoke-PostureGraphPage {
        $script:ListTest.asked.Add($Url)
        $n = $(if ($Url -match 'skiptoken=p(\d+)') { [int]$Matches[1] } else { 1 })
        if ($script:ListTest.refuse -gt 0 -and $Url -match 'skiptoken') {
            $script:ListTest.refuse--
            # The words Invoke-PostureGraphPage throws for a 400: the SDK's status line, the request, Graph's message.
            throw "Response status code does not indicate success: BadRequest (Bad Request). [GET $Url] The skip token is no longer valid."
        }
        if ($script:ListTest.failAt -eq $n) { throw 'The operation has timed out.' }
        $first = ($n - 1) * 10 + 1; $last = [Math]::Min(95, $n * 10)
        $page = @{ value = @(foreach ($i in $first..$last) { @{ id = "id-$i"; userPrincipalName = "user$i@contoso.example"; kind = $(if ($i % 5 -eq 0) { 'Guest' } else { 'Member' }); seen = '2026-11-15T02:03:22Z' } }) }
        if ($last -lt 95) { $page['@odata.nextLink'] = "https://graph.microsoft.com/v1.0/users?`$top=10&`$skiptoken=p$($n + 1)" }
        $page
    }
    InModuleScope TenantKeep.Posture {
        # The step under test: two files and three kinds of tally (a dictionary, a list of rows, a set).
        $script:ListTestRead = {
            param([string] $Folder, [string] $Key = 'k1', [int] $Every = 2)
            $c = @{ total = 0; byKind = [ordered]@{} }
            $guests = [System.Collections.Generic.List[object]]::new()
            $names = [System.Collections.Generic.HashSet[string]]::new()
            $read = Invoke-PostureListRead -Folder $Folder -ListName 'users' -ListUri 'users?$top=10' -ListApi 'v1.0' -ListLabel 'Users' -ListStream 'users', 'users-guests' -ListKey $Key -ListEvery $Every -ListState @{ c = $c; guests = $guests; names = $names } -ListOnPage {
                param($page, $info, $streams)
                foreach ($u in $page) {
                    $row = [ordered]@{ Id = $u['id']; UserPrincipalName = $u['userPrincipalName']; Kind = $u['kind']; Seen = $u['seen'] }
                    Add-PostureEvidenceRow -Stream $streams['users'] -Row $row
                    $c.total++
                    $c.byKind[$row.Kind] = 1 + $(if ($c.byKind.Contains($row.Kind)) { $c.byKind[$row.Kind] } else { 0 })
                    $null = $names.Add([string]$row.UserPrincipalName)
                    if ($row.Kind -eq 'Guest') { Add-PostureEvidenceRow -Stream $streams['users-guests'] -Row $row; $guests.Add($row) }
                }
            }
            @{ read = $read; c = $c; guests = $guests; names = $names }
        }
    }
    # Runs the step in a folder, with the page that fails (0 for none); returns its result and the links it asked for.
    $script:Read = {
        param([string] $Folder, [int] $FailAt = 0, [string] $Key = 'k1', [int] $Refuse = 0)
        $script:ListTest.failAt = $FailAt; $script:ListTest.refuse = $Refuse; $script:ListTest.asked.Clear()
        try { $r = InModuleScope TenantKeep.Posture -Parameters @{ F = $Folder; K = $Key } { param($F, $K) & $script:ListTestRead $F $K 3>$null } }
        finally { $script:ListTest.failAt = 0; $script:ListTest.refuse = 0 }
        $r.asked = @($script:ListTest.asked)
        $r
    }

    # The answer every case is compared with: the list read once, start to finish.
    $script:Whole = Join-Path $script:Root 'whole'; New-Item -ItemType Directory -Path $script:Whole | Out-Null
    $script:WholeResult = & $script:Read $script:Whole
    $script:Same = {
        param([string] $Folder)
        foreach ($name in 'users.json', 'users.csv', 'users-guests.json', 'users-guests.csv') {
            (Get-FileHash -LiteralPath (Join-Path $Folder $name)).Hash | Should -Be (Get-FileHash -LiteralPath (Join-Path $script:Whole $name)).Hash -Because "$name is the same file as an uninterrupted read wrote"
        }
    }
}

AfterAll {
    Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue
    InModuleScope TenantKeep.Posture { Remove-Variable -Name ListTestRead -Scope Script -ErrorAction SilentlyContinue }
}

Describe 'A long list read in one go' {
    It 'writes every row once and leaves no cursor behind' {
        $script:WholeResult.read.pages | Should -Be 10
        $script:WholeResult.read.resumed | Should -BeFalse
        $script:WholeResult.c.total | Should -Be 95
        $script:WholeResult.guests.Count | Should -Be 19
        @(Get-Content -Raw (Join-Path $script:Whole 'users.json') | ConvertFrom-Json).Count | Should -Be 95
        @(Import-Csv (Join-Path $script:Whole 'users.csv')).Count | Should -Be 95
        Join-Path $script:Whole 'cursor-users.json' | Should -Not -Exist
        @(Get-ChildItem $script:Whole -Filter '*.part').Count | Should -Be 0
    }
}

Describe 'A long list that stopped part way' {
    It 'keeps what it read with a cursor, and the next attempt carries on from the page after it' {
        $f = Join-Path $script:Root 'stopped'; New-Item -ItemType Directory -Path $f | Out-Null
        { & $script:Read $f 8 } | Should -Throw '*timed out*'
        # Pages 1 to 7 were read; the cursor was saved after page 6 (every two pages) and points at page 7.
        Join-Path $f 'cursor-users.json' | Should -Exist
        Join-Path $f 'users.json.part' | Should -Exist
        Join-Path $f 'users.json' | Should -Not -Exist -Because 'an unfinished list reads as not collected'
        $cursor = Get-Content -Raw (Join-Path $f 'cursor-users.json') | ConvertFrom-Json -AsHashtable
        $cursor.pages | Should -Be 6
        $cursor.nextLink | Should -Match 'skiptoken=p7$'
        $cursor.state.c.total | Should -Be 60

        $again = & $script:Read $f
        $again.read.resumed | Should -BeTrue
        $again.asked[0] | Should -Match 'skiptoken=p7$' -Because 'the read carries on from the cursor, not from the first page'
        $again.asked.Count | Should -Be 4
        $again.read.pages | Should -Be 10
        # The rows of page 7, written before the failure and after the cursor, are there once.
        & $script:Same $f
        $again.c.total | Should -Be 95
        $again.c.byKind['Guest'] | Should -Be 19
        $again.c.byKind['Member'] | Should -Be 76
        $again.guests.Count | Should -Be 19
        $again.names.Count | Should -Be 95
        @($again.guests | ForEach-Object { [string]$_['Seen'] } | Sort-Object -Unique) | Should -Be @('2026-11-15T02:03:22Z') -Because 'a row kept in the cursor comes back as it went in: text that looks like a date stays text'
        Join-Path $f 'cursor-users.json' | Should -Not -Exist
        @(Get-ChildItem $f -Filter '*.part').Count | Should -Be 0
    }

    It 'removes the unfinished files when it stopped before any cursor was saved' {
        $f = Join-Path $script:Root 'early'; New-Item -ItemType Directory -Path $f | Out-Null
        { & $script:Read $f 2 } | Should -Throw '*timed out*'
        @(Get-ChildItem $f -Filter '*.part').Count | Should -Be 0
        Join-Path $f 'cursor-users.json' | Should -Not -Exist
    }

    It 'keeps the cursor when carrying on fails for any other reason, whatever numbers the link holds' {
        $f = Join-Path $script:Root 'still-down'; New-Item -ItemType Directory -Path $f | Out-Null
        { & $script:Read $f 8 } | Should -Throw
        $before = Get-Content -Raw (Join-Path $f 'cursor-users.json')
        # Page 7 is asked for again and the sign-in has ended. Nothing about that says the link is bad.
        { & $script:Read $f 7 } | Should -Throw '*timed out*'
        Join-Path $f 'cursor-users.json' | Should -Exist
        Get-Content -Raw (Join-Path $f 'cursor-users.json') | Should -Be $before
        $script:ListTest.asked.Count | Should -Be 1 -Because 'the list was not started over'
        $again = & $script:Read $f
        $again.read.resumed | Should -BeTrue
        & $script:Same $f
    }

    It 'starts the list over when Graph no longer accepts the page link' {
        $f = Join-Path $script:Root 'refused'; New-Item -ItemType Directory -Path $f | Out-Null
        { & $script:Read $f 8 } | Should -Throw
        # The link has expired: Graph answers 400 to it, once. The first page is asked for instead.
        $again = & $script:Read $f 0 'k1' 1
        $again.read.restarted | Should -BeTrue
        $again.read.resumed | Should -BeFalse
        $again.asked[0] | Should -Match 'skiptoken=p7$'
        $again.asked[1] | Should -Not -Match 'skiptoken'
        & $script:Same $f
        $again.c.total | Should -Be 95 -Because 'the tallies started over with the list'
        $again.guests.Count | Should -Be 19
    }
}

Describe 'A cursor that must not be used' {
    BeforeEach {
        $script:Case = Join-Path $script:Root "case-$([guid]::NewGuid().ToString('n'))"; New-Item -ItemType Directory -Path $script:Case | Out-Null
        { & $script:Read $script:Case 8 } | Should -Throw
    }

    It 'is one saved under other inputs: the list is read from the start' {
        $r = & $script:Read $script:Case 0 'k2'
        $r.read.resumed | Should -BeFalse
        $r.asked[0] | Should -Not -Match 'skiptoken'
        $r.asked.Count | Should -Be 10
        & $script:Same $script:Case
    }

    It 'is one more than a day old' {
        $p = Join-Path $script:Case 'cursor-users.json'
        $c = Get-Content -Raw $p | ConvertFrom-Json -AsHashtable
        $c.savedUtc = [datetime]::UtcNow.AddHours(-25).ToString('o')
        $c | ConvertTo-Json -Depth 20 | Set-Content $p
        $r = & $script:Read $script:Case
        $r.read.resumed | Should -BeFalse
        $r.asked.Count | Should -Be 10
        & $script:Same $script:Case
    }

    It 'is one whose file is shorter than it says' {
        [System.IO.File]::WriteAllText((Join-Path $script:Case 'users.csv.part'), 'Id')
        $r = & $script:Read $script:Case
        $r.read.resumed | Should -BeFalse
        $r.asked.Count | Should -Be 10
        & $script:Same $script:Case
    }

    It 'is one that does not parse' {
        Set-Content (Join-Path $script:Case 'cursor-users.json') -Value '{ "list": "users", "nextLink": '
        $r = & $script:Read $script:Case
        $r.read.resumed | Should -BeFalse
        & $script:Same $script:Case
    }
}

Describe 'What a cursor gives back' {
    It 'is what it was given: text stays text, whole numbers stay whole, order is kept' {
        InModuleScope TenantKeep.Posture {
            $back = ConvertFrom-PostureJsonExact -Json '{"b":"2026-11-15T02:03:22Z","a":3,"half":1.5,"big":9007199254740993,"yes":true,"none":null,"list":[1,"two",{"k":"v"}],"empty":[]}'
            @($back.get_Keys()) | Should -Be @('b', 'a', 'half', 'big', 'yes', 'none', 'list', 'empty')
            $back['b'] | Should -BeOfType [string]
            $back['b'] | Should -Be '2026-11-15T02:03:22Z'
            $back['a'] | Should -BeOfType [long]
            $back['half'] | Should -Be 1.5
            $back['big'] | Should -Be 9007199254740993
            $back['yes'] | Should -BeTrue
            $back['none'] | Should -BeNullOrEmpty
            $back['list'].Count | Should -Be 3
            $back['list'][2]['k'] | Should -Be 'v'
            $back['empty'].Count | Should -Be 0
        }
    }

    It 'gives the same key for the same set of names in any order or case, and another for another set' {
        InModuleScope TenantKeep.Posture {
            $a = Get-PostureSetKey -Value @('b@contoso.example', 'A@contoso.example')
            Get-PostureSetKey -Value @('a@contoso.example', 'B@CONTOSO.example', 'a@contoso.example') | Should -Be $a
            Get-PostureSetKey -Value @('a@contoso.example') | Should -Not -Be $a
            Get-PostureSetKey -Value @() | Should -Match '^0:'
            Get-PostureSetKey -Value $null | Should -Match '^0:'
        }
    }

    It 'refuses, before reading anything, a tally a cursor could not put back' {
        $f = Join-Path $script:Root 'badstate'; New-Item -ItemType Directory -Path $f | Out-Null
        $script:ListTest.asked.Clear()
        {
            InModuleScope TenantKeep.Posture -Parameters @{ F = $f } {
                param($F)
                # A plain number cannot be put back in place: after a restart the step would go on counting from 5.
                Invoke-PostureListRead -Folder $F -ListName 'users' -ListUri 'users?$top=10' -ListApi 'v1.0' -ListStream 'users' -ListState @{ n = 5 } -ListOnPage { param($page, $info, $streams) }
            }
        } | Should -Throw "*The tally 'n' of users is a Int32*"
        $script:ListTest.asked.Count | Should -Be 0
        @(Get-ChildItem $f).Count | Should -Be 0
    }
}
