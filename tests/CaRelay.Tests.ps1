# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'deploy' 'schedules' 'ca-relay.ps1')
    function script:FromHex([string] $Hex) { , [Convert]::FromHexString($Hex) }
    function script:ToHex([byte[]] $Bytes) { [Convert]::ToHexString($Bytes).ToLowerInvariant() }
    $script:Tenant = 'c0ffee00-1111-2222-3333-444455556666'
}

Describe 'The embedded HPKE' {
    # CFRG test vector: mode 2 (auth), DHKEM(P-256), HKDF-SHA256, AES-256-GCM, first encryption. The same code is checked
    # against every encryption by relay/sender/Test-Hpke.ps1 in the On-Call repository; this catches a copy that drifts.
    It 'matches the CFRG vector' {
        $skE = [TenantKeep.Relay.Hpke]::Key((FromHex '04a7aeac79fda402674ef247c12d6f5fdfd21498d896b67ff04ec181382d4516b7662be32b4a2ae817c2d57104ecb6fcaa527438939810612d1b3d0af36ffc66ce'), (FromHex '7a6cb29fab4e249d1796f95645288a6504d2167c7ff463bc447ab6022462af42'))
        $skS = [TenantKeep.Relay.Hpke]::Key((FromHex '04ece9b48cc98ee03ba742fe1218a3fbec960cc34b6e1defdcd3285276f39028e95b90f9526607565888766a1101f429dc3ec87364b5c8c613f0a081881950427f'), (FromHex '6e7b14befe49443dc501def1cc2f0f293d9c5cfa045a23e9a2e0e7703b42705d'))
        $pkR = FromHex '04cd38ef80923e26f157e06c9887f80177c97e1005a41104127271237f946df22eda13d40801bce6184f1a631c44b0807a1a5e8d039975ed0f6079fcbd2dfe6652'
        $ctx = [TenantKeep.Relay.Hpke]::SetupAuthSender($pkR, $skS, (FromHex '4f6465206f6e2061204772656369616e2055726e'), 2, $skE)
        ToHex $ctx.Key | Should -Be '640064834667025be3ce7abf1eb42ccc0dea2db9782b9823519f474e054524e7'
        ToHex $ctx.BaseNonce | Should -Be '29240057274f71e55bfcca28'
        ToHex ($ctx.Seal((FromHex '436f756e742d30'), (FromHex '4265617574792069732074727574682c20747275746820626561757479'))) |
            Should -Be '59b9890aabf94c1d502c39d8d356989ab0880ed43e984255db7b32a8d7b0ad5beba799a4ec326a0ddca3dd5e5d'
    }
}

Describe 'ConvertTo-CaRelayRequest' {
    BeforeAll {
        $script:Sender = New-CaRelaySenderKey -TenantId $script:Tenant
        $script:Phone = [System.Security.Cryptography.ECDiffieHellman]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
        $script:Token = -join (0..31 | ForEach-Object { '{0:x2}' -f $_ })
        $pair = [ordered]@{ v = 1; deviceToken = $script:Token; environment = 'production'; publicKey = (ConvertTo-CaRelayBase64Url ([TenantKeep.Relay.Hpke]::PublicBytes($script:Phone))) } | ConvertTo-Json -Compress
        $script:Pairing = 'tkrelay1:' + (ConvertTo-CaRelayBase64Url ([Text.Encoding]::UTF8.GetBytes($pair)))
        $script:Json = ConvertTo-CaRelayRequest -PairingCode $script:Pairing -SenderPrivateKey $script:Sender.PrivateKey -TenantId $script:Tenant `
            -Entitlement 'a.b.c' -Kind conditionalAccessChange -Title 'Contoso Ltd: Conditional Access changed' -Body '3 risk-relevant change(s).' -Link 'tenantkeep://conditionalAccess'
    }

    It 'carries the contract fields and nothing else' {
        $req = $script:Json | ConvertFrom-Json
        ($req.PSObject.Properties.Name | Sort-Object) -join ',' | Should -Be 'deviceToken,entitlement,envelope,environment,urgency,v'
        $req.envelope.mode | Should -Be 'auth'
    }

    It 'never carries the alert in the clear' {
        $script:Json | Should -Not -Match 'Contoso'
        $script:Json | Should -Not -Match 'Conditional Access'
        $script:Json | Should -Not -Match $script:Tenant
    }

    It 'opens on the phone with the pinned sender' {
        $req = $script:Json | ConvertFrom-Json
        $senderPublic = ConvertFrom-CaRelayBase64Url (([Text.Encoding]::UTF8.GetString((ConvertFrom-CaRelayBase64Url $script:Sender.SenderCode.Substring(10))) | ConvertFrom-Json).senderKey)
        $open = [TenantKeep.Relay.Hpke]::SetupAuthRecipient((ConvertFrom-CaRelayBase64Url $req.envelope.enc), $script:Phone, $senderPublic, [Text.Encoding]::ASCII.GetBytes('TenantKeep relay v1'), 2)
        $alert = [Text.Encoding]::UTF8.GetString($open.Open([Text.Encoding]::ASCII.GetBytes($script:Token), (ConvertFrom-CaRelayBase64Url $req.envelope.ct))) | ConvertFrom-Json
        $alert.title | Should -Be 'Contoso Ltd: Conditional Access changed'
        $alert.tenant | Should -Be $script:Tenant
    }

    It 'refuses something that is not a pairing code' {
        { ConvertTo-CaRelayRequest -PairingCode 'hello' -SenderPrivateKey $script:Sender.PrivateKey -TenantId $script:Tenant -Entitlement 'a.b.c' -Kind k -Title t -Body b } |
            Should -Throw '*tkrelay1:*'
    }
}

Describe 'Get-CaRelayRetryDelay' {
    It 'tries a busy relay, a rate limit or no answer again, twice at most' {
        Get-CaRelayRetryDelay -Status 503 -Attempt 0 | Should -Be 2
        Get-CaRelayRetryDelay -Status 429 -Attempt 1 | Should -Be 5
        Get-CaRelayRetryDelay -Status 0 -Attempt 0 | Should -Be 2
        Get-CaRelayRetryDelay -Status 503 -Attempt 2 | Should -BeNullOrEmpty
    }

    It 'never repeats an answer a retry cannot change' {
        foreach ($status in 400, 401, 402, 410, 413, 502) {
            Get-CaRelayRetryDelay -Status $status -Attempt 0 | Should -BeNullOrEmpty -Because "a $status is final"
        }
    }

    It 'honours Retry-After up to 30 seconds' {
        Get-CaRelayRetryDelay -Status 503 -RetryAfter 4 -Attempt 0 | Should -Be 4
        Get-CaRelayRetryDelay -Status 429 -RetryAfter 120 -Attempt 0 | Should -Be 30
    }
}

Describe 'Send-CaRelayAlert' {
    BeforeAll {
        # As the Automation run: the cycle sets StrictMode before it dot-sources the relay script.
        Set-StrictMode -Version Latest
        $senderKey = New-CaRelaySenderKey -TenantId $script:Tenant
        $phone = [System.Security.Cryptography.ECDiffieHellman]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
        $pair = [ordered]@{ v = 1; deviceToken = (-join (0..31 | ForEach-Object { '{0:x2}' -f $_ })); environment = 'production'; publicKey = (ConvertTo-CaRelayBase64Url ([TenantKeep.Relay.Hpke]::PublicBytes($phone))) } | ConvertTo-Json -Compress
        $script:Send = @{
            PairingCode = 'tkrelay1:' + (ConvertTo-CaRelayBase64Url ([Text.Encoding]::UTF8.GetBytes($pair)))
            SenderPrivateKey = $senderKey.PrivateKey; TenantId = $script:Tenant; Entitlement = 'a.b.c'
            Kind = 'conditionalAccessChange'; Title = 'Conditional Access changed'; Body = '1 risk-relevant change.'
        }
        function script:Refusal([int] $Status) {
            [Microsoft.PowerShell.Commands.HttpResponseException]::new('refused', [System.Net.Http.HttpResponseMessage]::new($Status))
        }
    }

    BeforeEach {
        Mock Start-Sleep {}
        $script:Calls = 0
    }

    It 'sends again after a busy relay, with a timeout and one connection' {
        Mock Invoke-RestMethod {
            $script:Calls++
            if ($script:Calls -lt 3) { throw (Refusal 503) }
            [pscustomobject]@{ apnsId = 'apns-1' }
        }
        Send-CaRelayAlert @script:Send | Should -Be 'apns-1'
        $script:Calls | Should -Be 3
        Should -Invoke Start-Sleep -Times 2 -Exactly
        Should -Invoke Invoke-RestMethod -Times 3 -Exactly -ParameterFilter { $TimeoutSec -eq 15 -and $null -ne $WebSession }
    }

    It 'sends again after no answer at all' {
        Mock Invoke-RestMethod {
            $script:Calls++
            if ($script:Calls -lt 2) { throw [System.Threading.Tasks.TaskCanceledException]::new('timed out') }
            [pscustomobject]@{ apnsId = 'apns-2' }
        }
        Send-CaRelayAlert @script:Send | Should -Be 'apns-2'
        $script:Calls | Should -Be 2
    }

    It 'stops after the third refusal, naming the code only' {
        Mock Invoke-RestMethod { $script:Calls++; throw (Refusal 503) }
        { Send-CaRelayAlert @script:Send } | Should -Throw 'The relay refused the alert (no answer).'
        $script:Calls | Should -Be 3
    }

    It 'does not repeat a final answer' {
        Mock Invoke-RestMethod { $script:Calls++; throw (Refusal 410) }
        { Send-CaRelayAlert @script:Send } | Should -Throw 'The relay refused the alert*'
        $script:Calls | Should -Be 1
        Should -Invoke Start-Sleep -Times 0 -Exactly
    }
}
