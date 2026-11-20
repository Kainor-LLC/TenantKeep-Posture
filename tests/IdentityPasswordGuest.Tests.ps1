# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-idpw-$([guid]::NewGuid().ToString('n'))"
    $script:Write = { param([string] $Dir, [string] $Name, $Data) New-Item -ItemType Directory -Path $Dir -Force | Out-Null; ConvertTo-Json -InputObject $Data -Depth 10 | Set-Content -LiteralPath (Join-Path $Dir "$Name.json") }
    $script:Checks = { param([string] $Dir) InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache }; $r = Invoke-PostureChecks -Evidence $Dir -Domain identity -PassThru; $by = @{}; foreach ($x in $r.results) { $by[$x.id] = $x }; $by }
}

AfterAll { if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force } }

Describe 'Passwords to NIST and guest settings' {
    It 'fails an open tenant: expiring passwords, no banned list, guests inviting guests with member access, outbound open' {
        $d = Join-Path $script:Root 'open'
        & $script:Write $d '01-domains' @(@{ Id = 'contoso.example'; IsVerified = $true; AuthenticationType = 'Managed'; PasswordValidityPeriodInDays = 90 }, @{ Id = 'fed.example'; IsVerified = $true; AuthenticationType = 'Federated'; PasswordValidityPeriodInDays = 30 })
        & $script:Write $d '02-directory-settings' @()
        & $script:Write $d '02-authorization-policy' @{ allowInvitesFrom = 'everyone'; guestUserRoleId = 'a0b1b346-4d3e-4e8b-98f8-753987be4970' }
        & $script:Write $d '02-cross-tenant-access-defaults' @{ b2bCollaborationOutbound = @{ usersAndGroups = @{ accessType = 'allowed'; targets = @(@{ target = 'AllUsers' }) }; applications = @{ accessType = 'allowed'; targets = @(@{ target = 'AllApplications' }) } } }
        $by = & $script:Checks $d
        $by['ID-017'].affected.name | Should -Be @('contoso.example') -Because 'a federated domain''s passwords are set on-premises'
        $by['ID-018'].status | Should -Be 'fail' -Because 'no Password Rule Settings object means the defaults: no custom list'
        $by['ID-020'].status | Should -Be 'fail'
        $by['ID-021'].status | Should -Be 'fail'
        $by['ID-022'].status | Should -Be 'fail'
    }

    It 'passes a tidy tenant and reads Password Protection on-premises' {
        $d = Join-Path $script:Root 'tidy'
        & $script:Write $d '01-domains' @(@{ Id = 'contoso.example'; IsVerified = $true; AuthenticationType = 'Managed'; PasswordValidityPeriodInDays = 2147483647 })
        & $script:Write $d '02-directory-settings' @(@{ DisplayName = 'Password Rule Settings'; TemplateId = '5cf42378-d67d-4f36-ba46-e8b86229381d'; Values = @{ EnableBannedPasswordCheck = 'True'; BannedPasswordCount = 12; EnableBannedPasswordCheckOnPremises = 'True'; BannedPasswordCheckOnPremisesMode = 'Enforce' } })
        & $script:Write $d '02-authorization-policy' @{ allowInvitesFrom = 'adminsAndGuestInviters'; guestUserRoleId = '2af84b1e-32c8-42b7-82bc-daa82404023b' }
        & $script:Write $d '02-cross-tenant-access-defaults' @{ b2bCollaborationOutbound = @{ usersAndGroups = @{ accessType = 'blocked'; targets = @(@{ target = 'AllUsers' }) }; applications = @{ accessType = 'blocked'; targets = @(@{ target = 'AllApplications' }) } } }
        $by = & $script:Checks $d
        foreach ($id in 'ID-017', 'ID-018', 'ID-020', 'ID-021', 'ID-022') { $by[$id].status | Should -Be 'pass' -Because $id }
        InModuleScope TenantKeep.Posture -Parameters @{ D = $d } { param($D) Clear-PostureEvidenceCache; (Get-PostureIdentityFact -Evidence $D).facts.bannedPasswordOnPremEnforced | Should -BeTrue }
    }

    It 'asks for a fresh collection when the domains were read before password expiry was' {
        $d = Join-Path $script:Root 'old'
        & $script:Write $d '01-domains' @(@{ Id = 'contoso.example'; IsVerified = $true; AuthenticationType = 'Managed' })
        (& $script:Checks $d)['ID-017'].reason | Should -Match 'collected before'
    }
}
