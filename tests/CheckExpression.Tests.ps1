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
        @{ Expr = 'facts.missing != null'; Expected = $false }
        @{ Expr = 'facts.count == 3 || facts.missing'; Expected = $true }
        @{ Expr = 'facts.count == 3 || facts.nope >= 1'; Expected = $true }
        @{ Expr = 'facts.count == 1 && facts.missing'; Expected = $false }
        @{ Expr = 'facts.count == 1 && (facts.missing || facts.nope > 2)'; Expected = $false }
        @{ Expr = 'facts.missing || facts.count == 3'; Expected = $true }
        @{ Expr = 'facts.nope > 2 || facts.enabled'; Expected = $true }
        @{ Expr = 'facts.missing && facts.count == 1'; Expected = $false }
        @{ Expr = '!facts.missing || facts.enabled'; Expected = $true }
        @{ Expr = '(facts.count == 3 || facts.missing) && facts.enabled'; Expected = $true }
        @{ Expr = 'facts.nested.deep == 7'; Expected = $true }
        @{ Expr = 'true && false'; Expected = $false }
        @{ Expr = "'a' < 'b'"; Expected = $true }
    ) {
        InModuleScope TenantKeep.Posture -Parameters @{ Expr = $Expr; Expected = $Expected; Ctx = $script:Ctx } {
            Invoke-PostureExpression -Expression $Expr -Context $Ctx | Should -Be $Expected
        }
    }

    It 'throws on a fact with no value wherever the answer depends on it: <Expr>' -ForEach @(
        @{ Expr = 'facts.missing >= 1' }
        @{ Expr = 'facts.missing == 0' }
        @{ Expr = 'facts.missing != 0' }
        @{ Expr = '!facts.missing' }
        @{ Expr = 'facts.missing' }
        @{ Expr = 'facts.count == 1 || facts.missing' }
        @{ Expr = 'facts.count == 3 && facts.missing' }
        @{ Expr = 'facts.missing && facts.count == 3' }
        @{ Expr = 'facts.missing || facts.count == 1' }
        @{ Expr = '!(facts.missing || facts.count == 1)' }
    ) {
        # Missing data must never read as pass or fail: "!facts.x" on a null used to be a pass.
        InModuleScope TenantKeep.Posture -Parameters @{ Expr = $Expr; Ctx = $script:Ctx } {
            { Invoke-PostureExpression -Expression $Expr -Context $Ctx } | Should -Throw '*facts.missing has no value in the evidence*'
        }
    }

    It 'names the first unknown when two stand in the way, and treats a reference that is not there the same as one with no value' {
        InModuleScope TenantKeep.Posture -Parameters @{ Ctx = $script:Ctx } {
            { Invoke-PostureExpression -Expression 'facts.nope >= 1 && facts.missing' -Context $Ctx } | Should -Throw "*Unknown reference 'facts.nope'*"
            { Invoke-PostureExpression -Expression 'facts.missing || facts.nope >= 1' -Context $Ctx } | Should -Throw '*facts.missing has no value*'
            { Invoke-PostureExpression -Expression 'facts.nope == null' -Context $Ctx } | Should -Throw "*Unknown reference 'facts.nope'*"
        }
    }

    It 'still checks the shape of a side that does not decide' {
        InModuleScope TenantKeep.Posture -Parameters @{ Ctx = $script:Ctx } {
            { Invoke-PostureExpression -Expression 'facts.count == 3 || (facts.count == 1' -Context $Ctx } | Should -Throw "*Expected ')'*"
            { Invoke-PostureExpression -Expression 'facts.count == 1 && facts.count ==' -Context $Ctx } | Should -Throw '*Unexpected end*'
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
