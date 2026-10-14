# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
@{
    Severity            = @('Error', 'Warning')
    IncludeDefaultRules = $true
    ExcludeRules        = @(
        # Pester test files legitimately use positional and unused parameters in mocks.
        'PSReviewUnusedParameter'
    )
    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('7.0')
        }
        PSPlaceOpenBrace      = @{ Enable = $true; OnSameLine = $true; NewLineAfter = $true; IgnoreOneLineBlock = $true }
        PSPlaceCloseBrace     = @{ Enable = $true; NewLineAfter = $true; IgnoreOneLineBlock = $true; NoEmptyLineBefore = $false }
        PSUseConsistentIndentation = @{ Enable = $true; IndentationSize = 4; PipelineIndentation = 'IncreaseIndentationForFirstPipeline'; Kind = 'space' }
        PSUseConsistentWhitespace  = @{ Enable = $true; CheckInnerBrace = $true; CheckOpenBrace = $true; CheckOpenParen = $true; CheckOperator = $false; CheckSeparator = $true; CheckPipe = $true }
        PSAvoidUsingCmdletAliases  = @{ Enable = $true }
    }
}
