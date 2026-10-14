# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeDiscovery {
    $script:ModuleRoot = Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture'
    $script:PublicNames = @(Get-ChildItem -Path (Join-Path $script:ModuleRoot 'Public') -Filter '*.ps1' -ErrorAction SilentlyContinue |
            ForEach-Object { @{ Name = $_.BaseName; Path = $_.FullName } })
    $script:SourceFiles = @(Get-ChildItem -Path (Join-Path $PSScriptRoot '..') -Recurse -Include '*.ps1', '*.psm1', '*.psd1' |
            Where-Object { $_.FullName -notmatch '[\\/](out|docs|\.git)[\\/]' } |
            ForEach-Object { @{ Name = $_.FullName.Substring((Resolve-Path (Join-Path $PSScriptRoot '..')).Path.Length + 1); Path = $_.FullName } })
}

BeforeAll {
    $script:ModuleRoot = Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture'
    $script:ManifestPath = Join-Path $script:ModuleRoot 'Tenantkeep.Posture.psd1'
    Import-Module $script:ManifestPath -Force
}

Describe 'Module manifest' {
    It 'passes Test-ModuleManifest' {
        { Test-ModuleManifest -Path $script:ManifestPath -ErrorAction Stop } | Should -Not -Throw
    }

    It 'requires Microsoft.Graph.Authentication' {
        $data = Import-PowerShellDataFile -Path $script:ManifestPath
        @($data.RequiredModules | ForEach-Object { $_.ModuleName }) | Should -Contain 'Microsoft.Graph.Authentication'
    }

    It 'exports exactly the Public/ basenames' {
        $expected = @(Get-ChildItem -Path (Join-Path $script:ModuleRoot 'Public') -Filter '*.ps1' | Select-Object -ExpandProperty BaseName | Sort-Object)
        $actual = @((Get-Module Tenantkeep.Posture).ExportedFunctions.Keys | Sort-Object)
        $actual | Should -Be $expected
        $manifestList = @((Import-PowerShellDataFile -Path $script:ManifestPath).FunctionsToExport | Sort-Object)
        $manifestList | Should -Be $expected -Because 'FunctionsToExport must match Public/ so Import-Module from the repo works'
    }

    It 'targets PowerShell 7.4 Core only' {
        $data = Import-PowerShellDataFile -Path $script:ManifestPath
        $data.PowerShellVersion | Should -Be '7.4'
        $data.CompatiblePSEditions | Should -Be @('Core')
    }
}

Describe 'Source file <Name>' -ForEach $script:SourceFiles {
    It 'carries the copyright header' {
        (Get-Content -Path $Path -TotalCount 3) -join "`n" | Should -Match 'Copyright \(c\) 2026 Kainor LLC\. Source-available, see LICENSE\.md\.'
    }

    It 'has no em dash in user-facing text' {
        Get-Content -Path $Path -Raw | Should -Not -Match ([char]0x2014)
    }
}

Describe 'Public cmdlet <Name>' -ForEach $script:PublicNames -AllowNullOrEmptyForEach {
    BeforeAll {
        $script:Help = Get-Help -Name $Name -Full
        $script:Source = Get-Content -Path $Path -Raw
    }

    It 'has a file name equal to its function name' {
        $script:Source | Should -Match "function\s+$([regex]::Escape($Name))\b"
    }

    It 'uses an approved verb and the Posture noun prefix' {
        $verb, $noun = $Name.Split('-', 2)
        (Get-Verb -Verb $verb) | Should -Not -BeNullOrEmpty
        $noun | Should -Match '^Posture[A-Z]'
    }

    It 'uses CmdletBinding, strict mode and Stop' {
        $script:Source | Should -Match '\[CmdletBinding\('
        $script:Source | Should -Match "\`$ErrorActionPreference\s*=\s*'Stop'"
    }

    It 'has a Synopsis' { $script:Help.Synopsis | Should -Not -BeNullOrEmpty }
    It 'has a Description' { $script:Help.Description | Should -Not -BeNullOrEmpty }
    It 'has at least one Example' { @($script:Help.Examples.Example).Count | Should -BeGreaterOrEqual 1 }

    It 'has a Pester file under tests/' {
        Join-Path $PSScriptRoot "$Name.Tests.ps1" | Should -Exist
    }

    It 'verifies Graph scopes before any Graph call, when it calls Graph' {
        $code = [regex]::Replace($script:Source, '(?s)<#.*?#>', '')
        $callsGraph = $code -match 'Invoke-PostureGraphRequest|Get-Mg[A-Z]|Invoke-PostureEntraCollection|Export-PostureCaSnapshot'
        if ($callsGraph) { $code | Should -Match 'Assert-PostureGraphScope' }
    }
}

Describe 'Read-only guard' {
    BeforeAll {
        # Guards look at code only: block comments (comment-based help carries Connect-MgGraph examples) and line comments are stripped.
        $script:ModuleFiles = Get-ChildItem -Path $script:ModuleRoot -Recurse -Filter '*.ps1'
        $script:CodeLines = foreach ($f in $script:ModuleFiles) {
            $code = [regex]::Replace((Get-Content -Path $f.FullName -Raw), '(?s)<#.*?#>', '')
            $n = 0
            foreach ($line in ($code -split "\r?\n")) {
                $n++
                $stripped = $line -replace '(?<![''"])#(?!\s*posture:).*$', ''
                [pscustomobject]@{ Filename = $f.Name; LineNumber = $n; Line = $line; Code = $stripped }
            }
        }
        function Find-Code([string] $Pattern, [string] $ExcludeFile) {
            $script:CodeLines | Where-Object { $_.Filename -ne $ExcludeFile -and $_.Code -match $Pattern }
        }
    }

    It 'never calls a Graph cmdlet that writes' {
        $hits = Find-Code '\b(New|Set|Remove|Update|Add|Confirm|Reset|Revoke|Restore|Start|Stop|Clear|Grant|Invoke)-Mg(?!GraphRequest\b|Context\b)[A-Za-z]+'
        $hits | ForEach-Object { "$($_.Filename):$($_.LineNumber) $($_.Line.Trim())" } | Should -BeNullOrEmpty
    }

    It 'calls Invoke-MgGraphRequest only inside the wrapper' {
        $hits = Find-Code 'Invoke-MgGraphRequest|Invoke-RestMethod|Invoke-WebRequest' 'Invoke-PostureGraphRequest.ps1'
        $hits | ForEach-Object { "$($_.Filename):$($_.LineNumber) $($_.Line.Trim())" } | Should -BeNullOrEmpty
    }

    It 'never issues a non-GET request except an annotated query-style POST' {
        $hits = Find-Code "-Method\s+['`"]?(POST|PATCH|PUT|DELETE)" 'Invoke-PostureGraphRequest.ps1' |
            Where-Object { $_.Code -match 'PATCH|PUT|DELETE' -or $_.Line -notmatch 'posture:read-only-post' }
        $hits | ForEach-Object { "$($_.Filename):$($_.LineNumber) $($_.Line.Trim())" } | Should -BeNullOrEmpty
    }

    It 'pins the API version on every wrapper call' {
        $hits = Find-Code 'Invoke-PostureGraphRequest\b' 'Invoke-PostureGraphRequest.ps1' |
            Where-Object { $_.Code -notmatch '-ApiVersion' }
        $hits | ForEach-Object { "$($_.Filename):$($_.LineNumber) $($_.Line.Trim())" } | Should -BeNullOrEmpty
    }

    It 'never connects or registers apps from module code' {
        # A call at statement position. Error text that tells the user how to reconnect is fine.
        $hits = Find-Code '(^|[;{|(&])\s*(Connect-(Mg|ExchangeOnline|IPPSSession|PnPOnline|MicrosoftTeams|AzAccount)|Register-PnP)'
        $hits | ForEach-Object { "$($_.Filename):$($_.LineNumber) $($_.Line.Trim())" } | Should -BeNullOrEmpty
    }

    It 'runs Exchange Online cmdlets only through Invoke-PostureExoCommand, which accepts Get- names only' {
        $hits = Find-Code '(^|[;{|(&])\s*(Get|Set|New|Remove|Enable|Disable|Search|Start|Stop|Export)-(EXO|Hosted|AntiPhish|Safe|Dkim|Accepted|Transport|Inbound|Outbound|Organization|Quarantine|Remote|Sharing|Owa|ActiveSync|Mobile|Role|Malware|Atp|ATP|EOP|Admin|Authentication|Mailbox|CAS|Unified|InboxRule)' 'Invoke-PostureExoCommand.ps1'
        $hits | ForEach-Object { "$($_.Filename):$($_.LineNumber) $($_.Line.Trim())" } | Should -BeNullOrEmpty
        $src = Get-Content -Raw (Join-Path $script:ModuleRoot 'Private' 'Invoke-PostureExoCommand.ps1')
        $src | Should -Match "ValidatePattern\('\^Get-"
    }
}
