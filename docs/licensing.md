# Licensing: how the licence file works

Tenantkeep Posture is source-available (LICENSE.md) and its entitlement is a signed file, verified offline. Nothing is
sent anywhere to check it. This page is for the customer who received one and for the reviewer who wants to know what
the module does with it.

## Tiers

| Tier | What it covers | Licence needed |
|---|---|---|
| Free | `Export-PostureCaSnapshot`, `New-PostureCaDocument`, `Compare-PostureCaSnapshot`, the Conditional Access domain in any report, any number of tenants | none |
| Tenantkeep CA | The scheduled CA cycle (nightly snapshot, diff, alerts) in the customer's own automation | `ca` |
| Tenantkeep Posture | Every domain in the report, the findings register, the trend, the framework crosswalks | `full` |

Without a valid Full licence the report still generates: the Conditional Access domain is evaluated, every other
check reads as not evaluated with the licence reason, and the report's header says so.

## The file

`tenantkeep.lic` is JSON: the licence fields, the id of the key that signed them, and an ECDSA P-256 signature over
the canonical form of those fields (SHA-256, IEEE P1363). The fields are readable on purpose; the signature means none
of them can change. Example shape:

```json
{
  "format": "tenantkeep-licence/1",
  "licence": {
    "licenceId": "…", "product": "tenantkeep", "tenantId": "<tenant guid>", "tier": "full",
    "customer": "Contoso Ltd", "issuedUtc": "2026-10-15T00:00:00Z", "expiresUtc": "2027-11-15T00:00:00Z",
    "keyId": "kainor-2026-10"
  },
  "algorithm": "ES256",
  "signature": "<base64>"
}
```

## What the module checks

1. The key id names a public key built into the module (`Tenantkeep.Posture/Private/Test-PostureLicense.ps1`).
   The private keys live in Kainor's Azure Key Vault and never leave it.
2. The signature verifies against the canonical fields. Any edit, including the tenant id, tier or expiry, fails here.
3. The product is Tenantkeep and the tier is one the module knows.
4. The tenant id matches the tenant recorded in the evidence folder (`collection.json`, else `metadata.json`), which
   the collector wrote from the signed-in Graph session. A licence for one tenant does nothing against another.
5. The licence is not expired at the later of the current clock and the collection time, so a rolled-back clock does
   not revive it.

Where the file is looked for, in order: `-LicensePath`, the `TENANTKEEP_LICENSE` environment variable, the client
folder's `tenantkeep.lic` (next to profile.json), then `~/tenantkeep/tenantkeep.lic`. `Get-PostureLicense` shows the
state of a file in plain words.

## What it does not do

The module's source is published and it runs on your machine, so someone with the files can edit the verifier out.
That is true of any published code, and it is what the licence terms, not the code, forbid. Signed releases make an
edited module visibly unsigned; that is the detection, not a lock. There is no telemetry, no callback and no hidden
check. What the signature guarantees is narrower and exact: a licence file cannot be forged, altered, or moved to a
tenant it was not issued for.

## Issuing (Kainor side)

`deploy/licensing/New-PostureLicense.ps1` signs a licence with a local PEM (development) or through `az keyvault key
sign` against the Key Vault key (production). The planned automation is an Azure Function in the Kainor tenant on the
Stripe webhook: checkout completed and each renewal invoice paid produce a licence for the tenant id on the order and
email it to the customer. Key rotation is a new key id in the module's table and a release; both keys verify for one
release cycle.
