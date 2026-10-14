# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'Tenantkeep.Posture' 'Tenantkeep.Posture.psd1') -Force
    . (Join-Path $PSScriptRoot 'Fixtures' 'CaDiffFixture.ps1')
    . (Join-Path $PSScriptRoot '..' 'deploy' 'schedules' 'ca-notifications.ps1')
    $script:Sample = Join-Path $PSScriptRoot '..' 'samples' 'ca-snapshot'
    $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) "tkp-notify-$([guid]::NewGuid().ToString('n'))"
    $script:Fx = Initialize-CaDiffFixture -Root $script:Root -Sample $script:Sample
    $script:Cmp = Compare-PostureCaSnapshot -Before $script:Fx.Before -After $script:Fx.After -OutputPath (Join-Path $script:Root 'out') -PassThru -WarningAction SilentlyContinue
    $script:Html = $script:Cmp.Files | Where-Object { $_ -like '*.html' }
}

AfterAll {
    if (Test-Path $script:Root) { Remove-Item -LiteralPath $script:Root -Recurse -Force }
}

Describe 'Get-CaChangeNotificationContent' {
    It 'builds a subject with the count and a body with the risk table' {
        $c = Get-CaChangeNotificationContent -Comparison $script:Cmp -BeforeName 'a' -AfterName 'b' -TenantLabel 'Contoso Ltd'
        $c.Subject | Should -Be 'Conditional Access: 9 risk-relevant change(s) (Contoso Ltd)'
        $c.Body | Should -Match '<td[^>]*>breakGlassExclusionRemoved</td>'
        $c.Body | Should -Match 'Between <strong>a</strong> and <strong>b</strong>'
        $c.Body | Should -Not -Match '<script'
    }

    It 'says so when nothing is risk-relevant' {
        $same = Compare-PostureCaSnapshot -Before $script:Fx.Before -After $script:Fx.Before -OutputPath (Join-Path $script:Root 'same') -PassThru
        $c = Get-CaChangeNotificationContent -Comparison $same -BeforeName 'a' -AfterName 'b'
        $c.Subject | Should -Be 'Conditional Access: no risk-relevant changes'
        $c.Body | Should -Match 'No risk-relevant changes\.'
    }
}

Describe 'Send-CaChangeEmail' {
    Context 'Graph' {
        It 'refuses without Mail.Send and names the fix' {
            Mock Get-MgContext { [pscustomobject]@{ Scopes = @('Policy.Read.All') } }
            { Send-CaChangeEmail -To 'a@contoso.example' -From 'm@contoso.example' -Subject 's' -HtmlBody '<p/>' } | Should -Throw '*needs the Mail.Send permission*'
        }

        It 'posts sendMail as the From mailbox with the report attached and saveToSentItems false' {
            Mock Get-MgContext { [pscustomobject]@{ Scopes = @('Policy.Read.All', 'Mail.Send') } }
            Mock Invoke-MgGraphRequest { $env:TKP_TEST_MAIL = "$Uri`n$Body"; $null }
            Send-CaChangeEmail -To 'a@contoso.example', 'b@contoso.example' -From 'ca-monitor@contoso.example' -Subject 'Subject here' -HtmlBody '<p>hi</p>' -AttachmentPath $script:Html
            Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter { $Method -eq 'POST' -and $Uri -eq 'https://graph.microsoft.com/v1.0/users/ca-monitor%40contoso.example/sendMail' }
            $uri, $json = $env:TKP_TEST_MAIL -split "`n", 2
            $payload = $json | ConvertFrom-Json
            $payload.saveToSentItems | Should -BeFalse
            $payload.message.subject | Should -Be 'Subject here'
            $payload.message.body.contentType | Should -Be 'HTML'
            @($payload.message.toRecipients | ForEach-Object { $_.emailAddress.address }) | Should -Be @('a@contoso.example', 'b@contoso.example')
            $payload.message.attachments[0].name | Should -Be 'ca-changes.html'
            $payload.message.attachments[0].contentType | Should -Be 'text/html'
            [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload.message.attachments[0].contentBytes)) | Should -Match '^<!DOCTYPE html>'
            Remove-Item Env:TKP_TEST_MAIL -ErrorAction SilentlyContinue
        }

        It 'honours -WhatIf' {
            Mock Get-MgContext { [pscustomobject]@{ Scopes = @('Mail.Send') } }
            Mock Invoke-MgGraphRequest { throw 'must not be called' }
            Send-CaChangeEmail -To 'a@contoso.example' -From 'm@contoso.example' -Subject 's' -HtmlBody '<p/>' -WhatIf
            Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly
        }
    }

    Context 'Smtp' {
        It 'builds the message without sending with -PassThru' {
            $m = Send-CaChangeEmail -To 'a@contoso.example' -From 'm@contoso.example' -Subject 's' -HtmlBody '<p/>' -AttachmentPath $script:Html -Method Smtp -SmtpServer 'smtp.contoso.example' -PassThru
            $m.Method | Should -Be 'Smtp'
            $m.Attachments[0].name | Should -Be 'ca-changes.html'
            $m.Attachments[0].bytes.Length | Should -BeGreaterThan 1000
        }

        It 'requires a server' {
            { Send-CaChangeEmail -To 'a@contoso.example' -From 'm@contoso.example' -Subject 's' -HtmlBody '<p/>' -Method Smtp } | Should -Throw '*-SmtpServer is required*'
        }

        It 'fails an attachment path that does not exist' {
            { Send-CaChangeEmail -To 'a@contoso.example' -From 'm@contoso.example' -Subject 's' -HtmlBody '<p/>' -AttachmentPath '/nope.html' -Method Smtp -SmtpServer x -PassThru } | Should -Throw '*Attachment not found*'
        }
    }
}
