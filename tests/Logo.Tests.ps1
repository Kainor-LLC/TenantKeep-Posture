# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# The logo at the top of the report and the icon on the browser tab: a logo in brand.json first, then the
# organisation's own from its Entra company branding (a paid tier, never a redacted copy), then the TenantKeep mark.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'TenantKeep.Posture' 'TenantKeep.Posture.psd1') -Force
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } }
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-logo-$([guid]::NewGuid().ToString('n'))"
    New-Item -ItemType Directory -Path $script:Root | Out-Null
    . (Join-Path $PSScriptRoot 'Fixtures' 'CollectionFixture.ps1')
    $script:Png = [byte[]](0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 11, 22, 33, 44, 55, 66)
    $script:Ico = [byte[]](0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 9, 8, 7, 6)
    $script:Banner = [System.Convert]::ToBase64String($script:Png)
    $script:Icon = [System.Convert]::ToBase64String($script:Ico)
    $script:Mark = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes((Join-Path $PSScriptRoot '..' 'templates' 'tenantkeep-mark.png')))
    $script:NewEvidence = {
        param([string] $Name, $Logos)
        $folder = Join-Path $script:Root $Name
        $null = Initialize-CollectionFixture -Root $folder
        if ($null -ne $Logos) { ConvertTo-Json -InputObject $Logos -Depth 5 | Set-Content (Join-Path $folder '01-company-branding-logos.json') }
        InModuleScope TenantKeep.Posture { Clear-PostureEvidenceCache -Confirm:$false }
        $folder
    }
    $script:Both = @{ BannerLogo = @{ ContentType = 'image/png'; Bytes = 14; Base64 = $script:Banner }; Favicon = @{ ContentType = 'image/x-icon'; Bytes = 10; Base64 = $script:Icon } }
    $script:Page = { param($Report) Get-Content -Raw (@($Report.Files) -like '*report.html')[0] }
}

AfterAll {
    Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue
    InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = $null }
}

Describe 'The image read' {
    It 'returns the bytes, pins and records the version, counts the call, and leaves no file behind' {
        InModuleScope TenantKeep.Posture {
            Mock Invoke-MgGraphRequest { [System.IO.File]::WriteAllBytes($OutputFilePath, [byte[]](1, 2, 3)); $script:StreamFile = $OutputFilePath }
            Mock Add-PostureCallRecord { }
            $bytes = Invoke-PostureGraphStream -Uri 'organization/o1/branding/localizations/default/bannerLogo' -ApiVersion 'v1.0'
            , $bytes | Should -BeOfType ([byte[]])
            $bytes.Length | Should -Be 3
            $script:StreamFile | Should -Not -Exist
            Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter { $Method -eq 'GET' -and $Uri -eq 'https://graph.microsoft.com/v1.0/organization/o1/branding/localizations/default/bannerLogo' }
            Should -Invoke Add-PostureCallRecord -Times 1 -Exactly -ParameterFilter { $Service -eq 'graph' -and $Method -eq 'GET' }
            $script:GraphApiVersionsUsed | Should -Contain 'v1.0'
        }
    }

    It 'draws no progress bar of the Graph module''s own' {
        # Seen on a live run: three bars named WriteRequestProgressActivity stayed on the screen under the run's.
        $text = InModuleScope TenantKeep.Posture { (Get-Command Invoke-PostureGraphStream).Definition }
        $text.IndexOf("`$ProgressPreference = 'SilentlyContinue'") | Should -BeGreaterThan -1
        $text.IndexOf("`$ProgressPreference = 'SilentlyContinue'") | Should -BeLessThan $text.IndexOf('Invoke-MgGraphRequest') -Because 'it is set before the request is made'
    }

    It 'answers nothing for a picture that is not there, and refuses one that is too large' {
        InModuleScope TenantKeep.Posture {
            Mock Add-PostureCallRecord { }
            Mock Invoke-MgGraphRequest { throw 'Response status code does not indicate success: NotFound (Not Found).' }
            Invoke-PostureGraphStream -Uri 'organization/o1/branding/localizations/default/squareLogo' -ApiVersion 'v1.0' | Should -BeNullOrEmpty
            Mock Invoke-MgGraphRequest { [System.IO.File]::WriteAllBytes($OutputFilePath, [byte[]]::new(0)) }
            Invoke-PostureGraphStream -Uri 'organization/o1/branding/localizations/default/squareLogo' -ApiVersion 'v1.0' | Should -BeNullOrEmpty -Because 'an empty answer is no picture'
            Mock Invoke-MgGraphRequest { [System.IO.File]::WriteAllBytes($OutputFilePath, [byte[]]::new(2000)) }
            { Invoke-PostureGraphStream -Uri 'organization/o1/branding/localizations/default/bannerLogo' -ApiVersion 'v1.0' -MaxBytes 1000 } | Should -Throw '*more than the 1000*'
            Mock Invoke-MgGraphRequest { throw 'Response status code does not indicate success: Forbidden (Forbidden).' }
            { Invoke-PostureGraphStream -Uri 'organization/o1/branding/localizations/default/bannerLogo' -ApiVersion 'v1.0' } | Should -Throw '*Forbidden*' -Because 'a refusal is not "no picture"'
        }
    }
}

Describe 'Which logo the report shows' {
    It 'shows the organisation''s own logo and icon in a paid tier' {
        $r = New-PostureReport -Evidence (& $script:NewEvidence 'own' $script:Both) -Format Html -PassThru 6>$null
        $html = & $script:Page $r
        $html | Should -Match ('<img class="logo plate" alt="[^"]* logo" src="data:image/png;base64,' + [regex]::Escape($script:Banner) + '">')
        $html | Should -Match ('<link rel="icon" href="data:image/x-icon;base64,' + [regex]::Escape($script:Icon) + '">')
        $html | Should -Not -Match ([regex]::Escape($script:Mark.Substring(0, 60))) -Because 'the TenantKeep mark stands in only when there is no other'
    }

    It 'shows the TenantKeep mark when the tenant has no logo, and in the free tier whatever the tenant has' {
        $none = & $script:Page (New-PostureReport -Evidence (& $script:NewEvidence 'none' $null) -Format Html -PassThru 6>$null)
        $none | Should -Match ('<img class="logo mark" alt="TenantKeep" src="data:image/png;base64,' + [regex]::Escape($script:Mark) + '">')
        $none | Should -Match ('<link rel="icon" href="data:image/png;base64,' + [regex]::Escape($script:Mark) + '">')
        $evidence = & $script:NewEvidence 'free' $script:Both
        InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = $null }
        try { $free = & $script:Page (New-PostureReport -Evidence $evidence -Format Html -PassThru 6>$null 3>$null) }
        finally { InModuleScope TenantKeep.Posture { $script:PostureEntitlementOverride = @{ tier = 'full'; source = 'test fixtures carry no licence' } } }
        $free | Should -Not -Match ([regex]::Escape($script:Banner))
        $free | Should -Match '<img class="logo mark" alt="TenantKeep"'
    }

    It 'lets a logo in brand.json win, for the page and for the tab' {
        $evidence = & $script:NewEvidence 'brand' $script:Both
        $logo = Join-Path $script:Root 'msp.gif'
        [System.IO.File]::WriteAllBytes($logo, [byte[]](0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 1, 0, 1, 0))
        $brand = Join-Path $script:Root 'brand.json'
        @{ preparedBy = @{ name = 'Example MSP'; logo = $logo } } | ConvertTo-Json | Set-Content $brand
        $html = & $script:Page (New-PostureReport -Evidence $evidence -Brand $brand -Format Html -PassThru 6>$null)
        $own = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($logo))
        $html | Should -Match ('<img class="logo plate" alt="Example MSP logo" src="data:image/gif;base64,' + [regex]::Escape($own) + '">')
        $html | Should -Match ('<link rel="icon" href="data:image/gif;base64,' + [regex]::Escape($own) + '">')
        $html | Should -Not -Match ([regex]::Escape($script:Banner)) -Because 'an MSP''s choice is not overridden by the tenant''s logo'
    }

    It 'shows no TenantKeep mark on a report prepared under another name with no logo of its own' {
        $brand = Join-Path $script:Root 'brand-name-only.json'
        @{ preparedBy = @{ name = 'Example MSP' } } | ConvertTo-Json | Set-Content $brand
        $html = & $script:Page (New-PostureReport -Evidence (& $script:NewEvidence 'name-only' $null) -Brand $brand -Format Html -PassThru 6>$null)
        $html | Should -Not -Match '<img class="logo'
        $html | Should -Not -Match 'rel="icon"'
    }

    It 'leaves the organisation''s logo out of a redacted copy' {
        $r = New-PostureReport -Evidence (& $script:NewEvidence 'redact' $script:Both) -Format Html -Redact -PassThru 6>$null
        $shared = Get-Content -Raw (@($r.Files) -like '*share*report.html')[0]
        $shared | Should -Not -Match ([regex]::Escape($script:Banner)) -Because 'a logo names the customer as surely as its name does'
        $shared | Should -Not -Match ([regex]::Escape($script:Icon))
        $shared | Should -Match '<img class="logo mark" alt="TenantKeep"'
        (& $script:Page $r) | Should -Match ([regex]::Escape($script:Banner)) -Because 'the copy that stays with the customer keeps it'
    }

    It 'takes nothing from the evidence that is not a picture in base64' -ForEach @(
        @{ Why = 'a page, not a picture'; Logos = @{ BannerLogo = @{ ContentType = 'text/html'; Base64 = 'PHNjcmlwdD4=' } } }
        @{ Why = 'markup where base64 should be'; Logos = @{ BannerLogo = @{ ContentType = 'image/png'; Base64 = '"><script>alert(1)</script>' } } }
        @{ Why = 'a vector picture, which can carry script'; Logos = @{ BannerLogo = @{ ContentType = 'image/svg+xml'; Base64 = 'PHN2Zz48L3N2Zz4=' } } }
    ) {
        $html = & $script:Page (New-PostureReport -Evidence (& $script:NewEvidence "bad-$([guid]::NewGuid().ToString('n'))" $Logos) -Format Html -PassThru 6>$null)
        $html | Should -Match '<img class="logo mark" alt="TenantKeep"' -Because $Why
        $html | Should -Not -Match 'alert\(1\)</script>"'
    }
}
