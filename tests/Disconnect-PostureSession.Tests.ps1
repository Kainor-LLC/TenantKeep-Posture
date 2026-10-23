# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# Disconnect-PostureSession is covered beside Connect-PostureSession in Connect-PostureSession.Tests.ps1; this file keeps the
# one-test-file-per-public-cmdlet rule honest with the cheap check.
BeforeAll { Import-Module (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'Tenantkeep.Posture.psd1') -Force }
AfterAll { Remove-Module Tenantkeep.Posture -Force -ErrorAction SilentlyContinue }

Describe 'Disconnect-PostureSession' {
    It 'is a no-op without a session' {
        InModuleScope Tenantkeep.Posture {
            Mock Disconnect-PostureService { }
            $script:PostureSession = $null
            { Disconnect-PostureSession } | Should -Not -Throw
            Should -Invoke Disconnect-PostureService -Times 1 -Exactly
        }
    }
}
