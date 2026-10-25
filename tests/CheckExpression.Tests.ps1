# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    $script:Ctx = @{
        facts      = @{ count = 3; percent = 98.5; name = 'Contoso'; enabled = $true; missing = $null; nested = @{ deep = 7 } }
        thresholds = @{ max = 2; minPercent = 100; label = 'contoso' }
    }
}

Describe 'Invoke-PostureExpression' {
    It 'evaluates <Expr> to <Expected>' -ForEach @(
        @{ Expr = 'facts.count >= 1'; Expected = $true }
        @{ Expr = 'facts.count <= thresholds.max'; Expected = $false }
        @{ Expr = 'facts.percent >= thresholds.minPercent'; Expected = $false }
        @{ Expr = 'facts.percent > 98 && facts.percent < 99'; Expected = $true }
        @{ Expr = 'facts.enabled'; Expected = $true }
        @{ Expr = '!facts.enabled'; Expected = $false }
        @{ Expr = 'facts.name == thresholds.label'; Expected = $true }
        @{ Expr = "facts.name == 'Fabrikam' || facts.count == 3"; Expected = $true }
        @{ Expr = '(facts.count == 1 || facts.count == 3) && !(facts.percent == 0)'; Expected = $true }
        @{ Expr = 'facts.missing == null'; Expected = $true }
        @{ Expr = 'facts.missing >= 1'; Expected = $false }
        @{ Expr = 'facts.nested.deep == 7'; Expected = $true }
        @{ Expr = 'true && false'; Expected = $false }
        @{ Expr = "'a' < 'b'"; Expected = $true }
    ) {
        InModuleScope TenantKeep.Posture -Parameters @{ Expr = $Expr; Expected = $Expected; Ctx = $script:Ctx } {
            Invoke-PostureExpression -Expression $Expr -Context $Ctx | Should -Be $Expected
        }
    }

    It 'throws on an unknown reference so the engine can mark data missing' {
        InModuleScope TenantKeep.Posture -Parameters @{ Ctx = $script:Ctx } {
            { Invoke-PostureExpression -Expression 'facts.nope >= 1' -Context $Ctx } | Should -Throw "*Unknown reference 'facts.nope'*"
        }
    }

    It 'rejects anything that is not the grammar' {
        InModuleScope TenantKeep.Posture -Parameters @{ Ctx = $script:Ctx } {
            { Invoke-PostureExpression -Expression 'facts.count; Remove-Item /' -Context $Ctx } | Should -Throw '*Cannot parse*'
            { Invoke-PostureExpression -Expression '$(Get-Date)' -Context $Ctx } | Should -Throw '*Cannot parse*'
            { Invoke-PostureExpression -Expression '(facts.count == 1' -Context $Ctx } | Should -Throw "*Expected ')'*"
            { Invoke-PostureExpression -Expression 'facts.count == 1 2' -Context $Ctx } | Should -Throw '*Unexpected token*'
        }
    }
}
