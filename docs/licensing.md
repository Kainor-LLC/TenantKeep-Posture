# Licensing: how the licence file works

TenantKeep Posture is source-available (PolyForm Shield 1.0.0, LICENSE.md) and its entitlement is a signed file, verified offline. Nothing is
sent anywhere to check it. This page is for the customer who received one and for the reviewer who wants to know what
the module does with it.

## Tiers

| Tier | What it covers | Licence needed |
|---|---|---|
| Free | `Export-PostureCaSnapshot`, `New-PostureCaDocument`, `Compare-PostureCaSnapshot`, the Conditional Access domain in any report, any number of tenants | none |
| TenantKeep CA | The scheduled CA cycle (nightly snapshot, diff, alerts) in the customer's own automation | `ca` |
| TenantKeep Posture | Every domain in the report, the findings register, the trend, the framework crosswalks | `full` |

Without a valid Full licence the report still generates: the Conditional Access domain is evaluated, every other
check reads as not evaluated with the licence reason, and the report's header says so.


### Trial

Thirty days of the Full tier for one tenant, once, from https://tenantkeep.app/trial/. `Start-PostureRun` prints that
link with the tenant id filled in when the tenant has no Full licence; the module itself never contacts Kainor, so
nothing is sent unless the admin opens the page and submits it. The page asks for the tenant id, a work email and
the organisation name. The licence goes to that email only if its domain is one the tenant has verified (Microsoft's
public sign-in discovery maps the domain to its tenant), which is how a trial for someone else's tenant is refused.
The trial licence is an ordinary signed licence; a report run under one says "Trial licence, ends <date>".
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

1. The key id names a public key built into the module (`TenantKeep.Posture/Private/Test-PostureLicense.ps1`).
   The private keys live in Kainor's Azure Key Vault and never leave it.
2. The signature verifies against the canonical fields. Any edit, including the tenant id, tier or expiry, fails here.
3. The product is TenantKeep and the tier is one the module knows.
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

## Hardening

Published source cannot stop someone editing the files on their own machine. What it can do is make every bypass cost
more edits, make the result visibly tampered, and make the deliverable say so. Four layers:

1. **Signed release manifest.** `build.ps1 -Task Integrity` writes `integrity.json`: the SHA-256 of every file in the
   module, signed with the licence key family. At import the module hashes itself and records one of three build
   states, printed in every report header and appendix:
   `Signed release <version>` (manifest present, trusted signature, every file matches);
   `Development build` (no manifest: a source checkout, including this repository as cloned);
   `Modified build` (a file was changed, added or removed, or the manifest signature fails). A modified build also
   shows a banner on the report cover. The label is a label, not a lock.
2. **Authenticode and execution policy.** Releases are Authenticode-signed. Where the module runs unattended (the
   Automation runbook, an MSP's jump host) set the execution policy to `AllSigned`: Windows then refuses to run an edited
   file at all. That enforcement is the operating system's, not ours, and it costs nothing.
3. **Attribution.** The licence id, customer and tier are in the report header and appendix, and every row of the
   findings register carries the licence id. A report that surfaces where it should not is attributable to one licence.
4. **Verification where it is consumed.** The engine, the report model and the findings export each verify the licence
   from its file rather than trusting a record made earlier, so a single edit is not enough.

To produce a report that reads as a signed release while developing: `./build.ps1 -Task Build, Integrity
-LicenseKeyPath <pem>` then `Import-Module ./out/TenantKeep.Posture/<version>/TenantKeep.Posture.psd1`.

## Issuing (Kainor side)

`deploy/licensing/New-PostureLicense.ps1` signs a licence with a local PEM (development) or through `az keyvault key
sign` against the Key Vault key (production). The planned automation is an Azure Function in the Kainor tenant on the
Stripe webhook: checkout completed and each renewal invoice paid produce a licence for the tenant id on the order and
email it to the customer. Key rotation is a new key id in the module's table and a release; both keys verify for one
release cycle.
