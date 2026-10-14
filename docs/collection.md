# Evidence collection

`Invoke-PostureCollection` writes one run folder, `<OutRoot>/<yyyyMMdd-HHmm>/`, with the audit plan's file names
(Appendix A) so findings and checks reference the same evidence whether it came from the module or from the
original scripts. Read-only. Every step is independent: a permission failure is one line in `errors.txt` and the
run continues.

## What the Entra collector writes

| File | Source | Notes |
|---|---|---|
| `01-organization`, `01-subscribed-skus` (+csv), `01-onprem-sync-features` | organization, subscribedSkus, directory sync | SKUs feed `New-PostureProfile -Evidence`; sync features need OnPremDirectorySynchronization.Read.All |
| `02-*` tenant policies | authorization, security defaults, authentication methods, strengths, admin consent, cross-tenant access | |
| `04-role-definitions`, `04-role-assignments-active` (+csv), `04-role-assignments-pim-eligible` (+csv), `04-role-assignments-summary` | PIM schedule instances; plain role assignments when PIM is unavailable | Needs RoleManagement.Read.Directory for PIM |
| `04-pim-role-policies` (+csv) | roleManagementPolicyAssignments with rules | Activation MFA, justification, max duration, approval per role; feeds ID-006 |
| `05-auth-registration` (+csv), `05-auth-registration-summary` | userRegistrationDetails report | Needs AuditLog.Read.All and UserAuthenticationMethod.Read.All |
| `05-per-user-mfa` (+csv), `05-per-user-mfa-summary` | users/{id}/authentication/requirements, batched 20 per request | Legacy per-user MFA state; feeds AU-009. `-SkipPerUserMfa` on very large tenants |
| `08-entra-devices` (+csv), `08-entra-devices-by-join-os`, `08-entra-devices-stale` | devices | Join type and staleness against StaleDays; feeds the devices domain |
| `06-users` (+csv), `06-users-summary` | users with signInActivity; retried without it when AuditLog.Read.All is missing | `SignInActivityAvailable` in the summary says which |
| `07-groups` (+csv) | groups with Kind and Dynamic | |
| `10-app-registrations`, `10-service-principals`, `10-graph-app-permissions`, `10-oauth2-delegated-grants` (+csv) | applications, servicePrincipals, Graph appRoleAssignedTo, oauth2PermissionGrants | Credential expiry and SAML certificate expiry computed |
| `11-risky-users`, `11-risk-detections-30d` (+csv) | Identity Protection | P2; denied without it and logged |
| `policies`, `named-locations`, `auth-strengths`, `auth-context`, `resolved-names`, `group-scope`, `metadata` | Export-PostureCaSnapshot into the same folder | The CA checks and documents read these |
| `collection` | run manifest: tenant, account, scopes, API versions, files, errors | `metadata.json` stays the CA snapshot's own |

## What the Intune collector writes

| File | Source | Notes |
|---|---|---|
| `09-intune-managed-devices` (+csv), `09-intune-summary-os-agent-join`, `09-intune-summary-compliance`, `09-intune-summary-windows-builds` | managedDevices (beta, for joinType and autopilotEnrolled) | |
| `09-autopilot-devices` (+csv) | windowsAutopilotDeviceIdentities | |
| `09-intune-compliance-policies`, `09-intune-config-profiles-templates`, `09-intune-config-profiles-settings-catalog`, `09-intune-apps` (+csv) | compliance policies, device configurations, configurationPolicies (beta) with template family and assignment counts, mobile apps | Endpoint security policies are settings catalog policies with a `TemplateFamily` |
| `09-apple-push-cert`, `09-apple-vpp-tokens` (+csv) | APNs certificate, VPP tokens | Expiry feeds DEV-008 |
| `09-intune-enrollment-restrictions` (+csv) | deviceEnrollmentConfigurations (beta) | Per-platform personal enrollment blocked (verify the newer per-platform shape) |
| `09-intune-mde-connector` (+csv) | mobileThreatDefenseConnectors (beta) | (verify) partner identification |
| `09-intune-device-cleanup` | managedDeviceCleanupSettings (beta) | (verify) endpoint |
| `08-bitlocker-keys-by-device` (+csv), `08-bitlocker-keys-summary` | informationProtection/bitlocker/recoveryKeys, ids only | Key presence per device; the key material is never read |
| `09-intune-policy-settings` (+csv) | configurationPolicies/{id}/settings (beta) for every assigned settings catalog policy | One row per setting instance, recursed through choice children and groups; the endpoint facts match on the definition ids |
| `09-intune-config-profile-settings` (+csv), `09-intune-compliance-policy-settings` (+csv) | scalar properties of assigned template profiles and compliance policies | Update ring deadlines, jailbreak detection, SIP, SmartScreen in classic profiles |
| `09-intune-windows-hello` | the tenant-wide windowsHelloForBusinessConfiguration | |
| `09-intune-app-protection-policies` (+csv) | managedAppPolicies | iOS and Android, with IsAssigned |
| `09-intune-feature-update-profiles` (+csv) | windowsFeatureUpdateProfiles (beta) | |

Scopes: DeviceManagementManagedDevices.Read.All, DeviceManagementConfiguration.Read.All,
DeviceManagementServiceConfig.Read.All, DeviceManagementApps.Read.All, BitLockerKey.ReadBasic.All.

## What the Exchange collector writes

Needs a connected Exchange Online PowerShell session (ExchangeOnlineManagement 3.x, `Connect-ExchangeOnline`), with
View-Only Organization Management or an equivalent read-only role. The module never connects; with no session the
collector is skipped with a warning, or refused when `-Collector Exchange` was asked for by name. Every cmdlet goes
through one `Get-` only entry point, so a write is impossible by construction. Rich cmdlet objects are projected to
scalars and string lists before they are written.

| File | Source | Notes |
|---|---|---|
| `exo-01-orgconfig`, `exo-01-transport-config`, `exo-01-auth-policies`, `exo-01-audit-config` | organization, transport and audit config, authentication policies | SMTP AUTH, ARC sealers, mailbox audit default, unified audit log |
| `exo-02-accepted-domains`, `exo-02-dkim` | accepted domains, DKIM signing config | |
| `exo-03-inbound-connectors`, `exo-03-outbound-connectors`, `exo-03-transport-rules` | connectors, mail flow rules | Enhanced Filtering fields, SCL -1 rules with their scope |
| `exo-04-eop-content-filter`, `exo-04-eop-connection-filter`, `exo-04-eop-malware`, `exo-04-antiphish`, `exo-04-outbound-spam` | EOP policies | Full property set |
| `exo-04-preset-rules-eop`, `exo-04-preset-rules-mdo` | preset security policy rules | The scope columns say whether Standard or Strict reaches everyone |
| `exo-05-mdo-safelinks`, `exo-05-mdo-safeattachments`, `exo-05-mdo-global`, `exo-05-quarantine-policies` | Defender for Office 365 policies | Absent or denied without MDO; logged |
| `exo-06-remote-domains`, `exo-06-sharing-policies`, `exo-06-owa-policies` | remote domains, sharing, OWA policies | |
| `exo-07-eas-org-settings`, `exo-07-mobile-device-policies` | ActiveSync | |
| `exo-08-role-groups` | role groups with members | |
| `exo-09-mailboxes` (+csv), `exo-09-mailboxes-by-type`, `exo-09-mailboxes-with-forwarding` | Get-EXOMailbox, unlimited | Forwarding, holds, audit flag, the Entra object id for the shared mailbox join. `-SkipMailboxEnumeration` at very large sizes |
| `exo-10-cas-mailboxes` (+csv), `exo-10-cas-summary` | Get-EXOCASMailbox, unlimited | POP, IMAP, ActiveSync, SMTP AUTH override per mailbox |
| `exo-11-attack-simulations` (+csv) | Graph security/attackSimulation/simulations | Only with AttackSimulation.Read.All; skipped quietly otherwise |
| `dns-01-mail-records` (+csv) | public DNS through dig (Resolve-DnsName on Windows) | MX, SPF, DMARC, MTA-STS and TLS-RPT per custom authoritative domain; the initial onmicrosoft.com domain is left out |

```powershell
Connect-ExchangeOnline -UserPrincipalName reader@contoso.example -ShowBanner:$false
Invoke-PostureCollection -OutRoot ~/audit/evidence        # Entra, Intune and Exchange into one folder
```

Not yet collected: legacy sign-ins (section 12), inbox rules forwarding externally (spec 4.10, needs an audit search
at scale), Purview (A.2), SharePoint and Teams (A.3), Maester (A.4), Defender effective state (spec 4.11).

## Scopes

Required: Policy.Read.All, Directory.Read.All, Group.Read.All. Optional, each unlocking the steps named above:
User.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All, RoleManagement.Read.Directory,
OnPremDirectorySynchronization.Read.All, IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All. All delegated, all read-only.

```powershell
Connect-MgGraph -Scopes Policy.Read.All, Directory.Read.All, Group.Read.All, User.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All, RoleManagement.Read.Directory, OnPremDirectorySynchronization.Read.All, IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All -NoWelcome
Invoke-PostureCollection -OutRoot ~/audit/evidence
```

At 20k users the users and registration pulls dominate; expect 20 to 40 minutes, as the audit plan says.
