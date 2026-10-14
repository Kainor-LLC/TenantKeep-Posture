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

Scopes: DeviceManagementManagedDevices.Read.All, DeviceManagementConfiguration.Read.All,
DeviceManagementServiceConfig.Read.All, DeviceManagementApps.Read.All, BitLockerKey.ReadBasic.All.

Not yet collected: legacy sign-ins (section 12), Exchange and Purview (A.2), SharePoint and Teams (A.3), Maester
(A.4), Defender effective state (spec 4.11).

## Scopes

Required: Policy.Read.All, Directory.Read.All, Group.Read.All. Optional, each unlocking the steps named above:
User.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All, RoleManagement.Read.Directory,
OnPremDirectorySynchronization.Read.All, IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All. All delegated, all read-only.

```powershell
Connect-MgGraph -Scopes Policy.Read.All, Directory.Read.All, Group.Read.All, User.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All, RoleManagement.Read.Directory, OnPremDirectorySynchronization.Read.All, IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All -NoWelcome
Invoke-PostureCollection -OutRoot ~/audit/evidence
```

At 20k users the users and registration pulls dominate; expect 20 to 40 minutes, as the audit plan says.
