#Requires -Version 7.4
# Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
<#
.SYNOPSIS
    Relayed alerts for TenantKeep On-Call: Watch's opt-in delivery to an administrator's phone through the
    TenantKeep relay. Dot-sourced by ca-snapshot-cycle.ps1.
.DESCRIPTION
    The one exception to "nothing leaves the customer's environment", opt-in and off unless the customer sets it up
    (CLAUDE.md, decided 2026-10-27). What crosses, and only when a risk-relevant change is found:
      - to kainor-relay-prod-func.azurewebsites.net: an alert encrypted for one phone (HPKE, RFC 9180, authenticated
        mode, with a sender key that stays in this Automation account), the phone's push token, the urgency, and the
        tenant's TenantKeep On-Call entitlement token, which names the tenant ID;
      - to kainor-lapslock-prod-func.azurewebsites.net: the tenant ID, once per run, to get that entitlement token.
    Kainor cannot read the alert and keeps nothing (the relay contract, docs/RELAY-API.md in the On-Call repository,
    whose source is published there under relay/). The HPKE code below is a copy of relay/sender/Hpke.cs from that
    repository; tests/CaRelay.Tests.ps1 checks it against the CFRG test vector so a copy that drifts fails.
#>

# Compiled once per session, and loudly: a compile failure must stop the run here, not surface later as a missing type
# when the first alert is sealed.
if (-not ('TenantKeep.Relay.Hpke' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Security.Cryptography;
using System.Text;

namespace TenantKeep.Relay
{
    public sealed class HpkeContext
    {
        public byte[] Key;
        public byte[] BaseNonce;
        public ulong Sequence;
        public byte[] Enc;

        byte[] Nonce()
        {
            var nonce = (byte[])BaseNonce.Clone();
            for (int i = 0; i < 8; i++) nonce[nonce.Length - 1 - i] ^= (byte)(Sequence >> (8 * i));
            return nonce;
        }

        public byte[] Seal(byte[] aad, byte[] plaintext)
        {
            var ct = new byte[plaintext.Length];
            var tag = new byte[16];
            using (var gcm = new AesGcm(Key, 16)) gcm.Encrypt(Nonce(), plaintext, ct, tag, aad);
            Sequence++;
            var output = new byte[ct.Length + 16];
            Buffer.BlockCopy(ct, 0, output, 0, ct.Length);
            Buffer.BlockCopy(tag, 0, output, ct.Length, 16);
            return output;
        }

        public byte[] Open(byte[] aad, byte[] ciphertext)
        {
            var ct = new byte[ciphertext.Length - 16];
            var tag = new byte[16];
            Buffer.BlockCopy(ciphertext, 0, ct, 0, ct.Length);
            Buffer.BlockCopy(ciphertext, ct.Length, tag, 0, 16);
            var pt = new byte[ct.Length];
            using (var gcm = new AesGcm(Key, 16)) gcm.Decrypt(Nonce(), ct, tag, pt, aad);
            Sequence++;
            return pt;
        }
    }

    public static class Hpke
    {
        public const ushort KemId = 0x0010, KdfId = 0x0001;
        public const byte ModeBase = 0x00, ModeAuth = 0x02;

        static byte[] I2Osp(int value, int length)
        {
            var b = new byte[length];
            for (int i = 0; i < length; i++) b[length - 1 - i] = (byte)(value >> (8 * i));
            return b;
        }

        static byte[] Concat(params byte[][] parts)
        {
            int n = 0; foreach (var p in parts) n += p.Length;
            var o = new byte[n]; int at = 0;
            foreach (var p in parts) { Buffer.BlockCopy(p, 0, o, at, p.Length); at += p.Length; }
            return o;
        }

        static readonly byte[] Version = Encoding.ASCII.GetBytes("HPKE-v1");

        static byte[] LabeledExtract(byte[] suiteId, byte[] salt, string label, byte[] ikm) =>
            HKDF.Extract(HashAlgorithmName.SHA256, Concat(Version, suiteId, Encoding.ASCII.GetBytes(label), ikm), salt);

        static byte[] LabeledExpand(byte[] suiteId, byte[] prk, string label, byte[] info, int length) =>
            HKDF.Expand(HashAlgorithmName.SHA256, prk, length, Concat(I2Osp(length, 2), Version, suiteId, Encoding.ASCII.GetBytes(label), info));

        static byte[] KemSuite => Concat(Encoding.ASCII.GetBytes("KEM"), I2Osp(KemId, 2));

        static byte[] HpkeSuite(ushort aeadId) => Concat(Encoding.ASCII.GetBytes("HPKE"), I2Osp(KemId, 2), I2Osp(KdfId, 2), I2Osp(aeadId, 2));

        static int KeyLength(ushort aeadId) => aeadId == 0x0001 ? 16 : aeadId == 0x0002 ? 32 : throw new ArgumentException("AES-GCM only");

        /// A P-256 key from a 65-byte uncompressed point, optionally with its private scalar.
        public static ECDiffieHellman Key(byte[] publicUncompressed, byte[] privateScalar = null)
        {
            if (publicUncompressed == null || publicUncompressed.Length != 65 || publicUncompressed[0] != 0x04)
                throw new ArgumentException("expected a 65-byte uncompressed P-256 point");
            var p = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = publicUncompressed[1..33], Y = publicUncompressed[33..65] },
                D = privateScalar
            };
            return ECDiffieHellman.Create(p);
        }

        public static byte[] PublicBytes(ECDiffieHellman key)
        {
            var q = key.ExportParameters(false).Q;
            return Concat(new byte[] { 0x04 }, q.X, q.Y);
        }

        static byte[] Dh(ECDiffieHellman priv, ECDiffieHellman pub) => priv.DeriveRawSecretAgreement(pub.PublicKey);

        static byte[] ExtractAndExpand(byte[] dh, byte[] kemContext)
        {
            var prk = LabeledExtract(KemSuite, Array.Empty<byte>(), "eae_prk", dh);
            return LabeledExpand(KemSuite, prk, "shared_secret", kemContext, 32);
        }

        static HpkeContext KeySchedule(byte mode, byte[] sharedSecret, byte[] info, ushort aeadId, byte[] enc)
        {
            var suite = HpkeSuite(aeadId);
            var pskIdHash = LabeledExtract(suite, Array.Empty<byte>(), "psk_id_hash", Array.Empty<byte>());
            var infoHash = LabeledExtract(suite, Array.Empty<byte>(), "info_hash", info);
            var context = Concat(new[] { mode }, pskIdHash, infoHash);
            var secret = LabeledExtract(suite, sharedSecret, "secret", Array.Empty<byte>());
            return new HpkeContext
            {
                Key = LabeledExpand(suite, secret, "key", context, KeyLength(aeadId)),
                BaseNonce = LabeledExpand(suite, secret, "base_nonce", context, 12),
                Sequence = 0,
                Enc = enc
            };
        }

        /// Sender, authenticated mode. `ephemeral` is for test vectors only; pass null.
        public static HpkeContext SetupAuthSender(byte[] recipientPublic, ECDiffieHellman sender, byte[] info, ushort aeadId, ECDiffieHellman ephemeral = null)
        {
            using var pkR = Key(recipientPublic);
            var skE = ephemeral ?? ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var enc = PublicBytes(skE);
            var dh = Concat(Dh(skE, pkR), Dh(sender, pkR));
            var kemContext = Concat(enc, recipientPublic, PublicBytes(sender));
            return KeySchedule(ModeAuth, ExtractAndExpand(dh, kemContext), info, aeadId, enc);
        }

        /// Recipient, authenticated mode, for the tests.
        public static HpkeContext SetupAuthRecipient(byte[] enc, ECDiffieHellman recipient, byte[] senderPublic, byte[] info, ushort aeadId)
        {
            using var pkE = Key(enc);
            using var pkS = Key(senderPublic);
            var dh = Concat(Dh(recipient, pkE), Dh(recipient, pkS));
            var kemContext = Concat(enc, PublicBytes(recipient), senderPublic);
            return KeySchedule(ModeAuth, ExtractAndExpand(dh, kemContext), info, aeadId, enc);
        }
    }
}
'@ -ErrorAction Stop
}

$script:RelayUri = 'https://kainor-relay-prod-func.azurewebsites.net/relay'
$script:EntitlementUri = 'https://kainor-lapslock-prod-func.azurewebsites.net/entitlement'
# One connection for the run's alerts, and no call waits more than 15 seconds: with no timeout, a relay or entitlement
# endpoint that never answered would stall the whole cycle.
$script:RelaySession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
$script:TimeoutSec = 15

function ConvertTo-CaRelayBase64Url {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [byte[]] $Bytes)
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-CaRelayBase64Url {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)] [string] $Text)
    $s = $Text.Replace('-', '+').Replace('_', '/')
    while ($s.Length % 4) { $s += '=' }
    , [Convert]::FromBase64String($s)
}

function New-CaRelaySenderKey {
    <#
    .SYNOPSIS
        A relay sender key for one tenant.
    .DESCRIPTION
        PrivateKey goes into the Automation account as the encrypted variable RELAY_SENDER_KEY. SenderCode is pasted
        into TenantKeep On-Call on each phone that should trust this tenant's alerts (Settings, Relayed Alerts).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [Guid] $TenantId)
    if (-not $PSCmdlet.ShouldProcess("tenant $TenantId", 'Create a relay sender key')) { return }
    $key = [System.Security.Cryptography.ECDiffieHellman]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $pin = [ordered]@{ v = 1; tenant = $TenantId.ToString().ToLowerInvariant(); senderKey = (ConvertTo-CaRelayBase64Url ([TenantKeep.Relay.Hpke]::PublicBytes($key))) }
    [pscustomobject]@{
        TenantId   = $pin.tenant
        PrivateKey = [Convert]::ToBase64String($key.ExportPkcs8PrivateKey())
        SenderCode = 'tksender1:' + (ConvertTo-CaRelayBase64Url ([Text.Encoding]::UTF8.GetBytes(($pin | ConvertTo-Json -Compress))))
    }
}

function Get-CaRelayEntitlement {
    <#
    .SYNOPSIS
        The tenant's TenantKeep On-Call entitlement token, which the relay checks offline. Sends the tenant ID only.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [Guid] $TenantId, [string] $Uri = $script:EntitlementUri)
    $ErrorActionPreference = 'Stop'
    $body = @{ version = 1; tenantId = $TenantId.ToString().ToLowerInvariant() } | ConvertTo-Json -Compress
    (Invoke-RestMethod -Method Post -Uri $Uri -Body $body -ContentType 'application/json; charset=utf-8' -TimeoutSec $script:TimeoutSec).token
}

function ConvertTo-CaRelayRequest {
    <#
    .SYNOPSIS
        Converts one alert into the relay request for one phone, encrypted, without sending it.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $PairingCode,
        [Parameter(Mandatory)] [string] $SenderPrivateKey,
        [Parameter(Mandatory)] [Guid] $TenantId,
        [Parameter(Mandatory)] [string] $Entitlement,
        [Parameter(Mandatory)] [string] $Kind,
        [Parameter(Mandatory)] [ValidateLength(1, 80)] [string] $Title,
        [Parameter(Mandatory)] [ValidateLength(1, 400)] [string] $Body,
        [string] $Link,
        [ValidateSet('normal', 'time-sensitive')] [string] $Urgency = 'normal'
    )
    $ErrorActionPreference = 'Stop'
    if (-not $PairingCode.StartsWith('tkrelay1:')) { throw 'Not a pairing code from TenantKeep On-Call. It starts tkrelay1:.' }
    $phone = [Text.Encoding]::UTF8.GetString((ConvertFrom-CaRelayBase64Url $PairingCode.Substring(9))) | ConvertFrom-Json
    if ($phone.v -ne 1 -or $phone.deviceToken -notmatch '^[0-9a-f]{64,200}$') { throw 'The pairing code is not version 1 or its token is malformed.' }
    $senderKey = [System.Security.Cryptography.ECDiffieHellman]::Create()
    [int] $read = 0
    $senderKey.ImportPkcs8PrivateKey([Convert]::FromBase64String($SenderPrivateKey), [ref] $read)
    $alert = [ordered]@{
        v = 1; id = [Guid]::NewGuid().ToString(); at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        tenant = $TenantId.ToString().ToLowerInvariant(); kind = $Kind; title = $Title; body = $Body
    }
    if ($Link) { $alert.link = $Link }
    $plaintext = [Text.Encoding]::UTF8.GetBytes(($alert | ConvertTo-Json -Compress))
    if ($plaintext.Length -gt 2700) { throw 'The alert is over 2,700 bytes.' }
    $context = [TenantKeep.Relay.Hpke]::SetupAuthSender((ConvertFrom-CaRelayBase64Url $phone.publicKey), $senderKey, [Text.Encoding]::ASCII.GetBytes('TenantKeep relay v1'), 2, $null)
    $ct = $context.Seal([Text.Encoding]::ASCII.GetBytes($phone.deviceToken), $plaintext)
    [ordered]@{
        v = 1; deviceToken = $phone.deviceToken; environment = $phone.environment; urgency = $Urgency; entitlement = $Entitlement
        envelope = [ordered]@{ suite = 'DHKEM-P256-HKDF-SHA256/HKDF-SHA256/AES-256-GCM'; mode = 'auth'; enc = (ConvertTo-CaRelayBase64Url $context.Enc); ct = (ConvertTo-CaRelayBase64Url $ct) }
    } | ConvertTo-Json -Compress
}

function Get-CaRelayRetryDelay {
    <#
    .SYNOPSIS
        Seconds to wait before sending the same alert again, or nothing to stop.
    .DESCRIPTION
        Only a 503 (Apple or the relay busy, "try again later" in the relay contract) or a 429 (the relay's rate limit)
        is tried again, at most twice; so is no answer at all, a timeout, which is safe to repeat because the phone
        drops an alert id it has already shown. Every other answer means something a retry cannot change. Retry-After
        is honoured up to 30 seconds; otherwise the waits are 2 and then 5 seconds.
    #>
    [CmdletBinding()]
    [OutputType([double])]
    param([int] $Status, [Nullable[double]] $RetryAfter, [int] $Attempt)
    if ($Attempt -ge 2 -or $Status -notin 0, 429, 503) { return $null }
    if ($null -ne $RetryAfter -and $RetryAfter -gt 0) { return [Math]::Min([double] $RetryAfter, 30) }
    [double] @(2, 5)[$Attempt]
}

function Send-CaRelayAlert {
    <#
    .SYNOPSIS
        Sends one encrypted alert to one paired phone through the TenantKeep relay. Returns Apple's apns-id.
    .DESCRIPTION
        A failure names the relay's error code only; nothing from the request is written to the output.
        A 410 (device_unregistered) means the phone was reset or the app removed: pair it again.
        A busy relay or Apple, a rate limit, or no answer is tried twice more first (Get-CaRelayRetryDelay).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $PairingCode,
        [Parameter(Mandatory)] [string] $SenderPrivateKey,
        [Parameter(Mandatory)] [Guid] $TenantId,
        [Parameter(Mandatory)] [string] $Entitlement,
        [Parameter(Mandatory)] [string] $Kind,
        [Parameter(Mandatory)] [string] $Title,
        [Parameter(Mandatory)] [string] $Body,
        [string] $Link,
        [ValidateSet('normal', 'time-sensitive')] [string] $Urgency = 'normal',
        [string] $Uri = $script:RelayUri
    )
    $ErrorActionPreference = 'Stop'
    $request = ConvertTo-CaRelayRequest -PairingCode $PairingCode -SenderPrivateKey $SenderPrivateKey -TenantId $TenantId -Entitlement $Entitlement `
        -Kind $Kind -Title $Title -Body $Body -Link $Link -Urgency $Urgency
    if (-not $PSCmdlet.ShouldProcess('the paired phone', 'Send an encrypted relayed alert')) { return }
    for ($attempt = 0; ; $attempt++) {
        try {
            return (Invoke-RestMethod -Method Post -Uri $Uri -Body $request -ContentType 'application/json; charset=utf-8' `
                    -TimeoutSec $script:TimeoutSec -WebSession $script:RelaySession).apnsId
        }
        catch {
            # A timeout's exception has no Response, and StrictMode makes reading a missing property an error.
            $response = if ($_.Exception.PSObject.Properties['Response']) { $_.Exception.Response } else { $null }
            $status = if ($response) { [int] $response.StatusCode } else { 0 }
            $retryAfter = $null
            if ($response -and $response.Headers.RetryAfter -and $response.Headers.RetryAfter.Delta) {
                $retryAfter = $response.Headers.RetryAfter.Delta.TotalSeconds
            }
            $wait = Get-CaRelayRetryDelay -Status $status -RetryAfter $retryAfter -Attempt $attempt
            if ($null -eq $wait) {
                $code = try { ($_.ErrorDetails.Message | ConvertFrom-Json).error } catch { $null }
                throw ('The relay refused the alert (' + ($code ?? 'no answer') + ').')
            }
            # Up to a second of jitter, so many runs refused at once do not all return at once.
            Start-Sleep -Milliseconds ([int] ($wait * 1000) + (Get-Random -Minimum 0 -Maximum 1000))
        }
    }
}
