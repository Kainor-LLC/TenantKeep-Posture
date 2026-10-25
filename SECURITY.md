# Security

TenantKeep Posture reads a tenant and writes nothing back to it. If you find a way to make it do otherwise, a way
to make it send data outside the customer's environment, a way around the licence check that matters to you, or any
other security problem, tell Kainor privately first.

## Reporting

Email security@kainor.com with the module version (`Get-Module Tenantkeep.Posture`), the PowerShell version and
operating system, what you ran and what happened. Do not attach evidence folders or reports from a real tenant;
describe the shape of the data instead. Once the repository is public, GitHub's private vulnerability reporting on
this repository works too.

You will get an acknowledgement within three business days and a fix or a reasoned answer within thirty. Credit
goes in the changelog unless you ask otherwise.

## What is in scope

- The module, the collectors, the check catalog and the report it produces.
- The deployment templates and setup scripts under `deploy/`.
- The signed licence and integrity mechanism described in [docs/licensing.md](docs/licensing.md).

## What is not

- Findings about your own tenant. The report is the place for those.
- Microsoft services and modules the module depends on. Report those to Microsoft.
- Denial of service against Graph or the other APIs through the module; every call is paged and read-only by design.

## How releases are protected

Every release is Authenticode-signed by Kainor LLC and carries a signed integrity manifest; the report header says
whether the running build is a release, a development copy or a modified one. The signing certificate and the
licence signing key never enter this repository or its CI.
