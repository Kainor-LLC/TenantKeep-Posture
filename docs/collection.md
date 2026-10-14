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
| `05-auth-registration` (+csv), `05-auth-registration-summary` | userRegistrationDetails report | Needs AuditLog.Read.All and UserAuthenticationMethod.Read.All |
| `06-users` (+csv), `06-users-summary` | users with signInActivity; retried without it when AuditLog.Read.All is missing | `SignInActivityAvailable` in the summary says which |
| `07-groups` (+csv) | groups with Kind and Dynamic | |
| `10-app-registrations`, `10-service-principals`, `10-graph-app-permissions`, `10-oauth2-delegated-grants` (+csv) | applications, servicePrincipals, Graph appRoleAssignedTo, oauth2PermissionGrants | Credential expiry and SAML certificate expiry computed |
| `11-risky-users`, `11-risk-detections-30d` (+csv) | Identity Protection | P2; denied without it and logged |
| `policies`, `named-locations`, `auth-strengths`, `auth-context`, `resolved-names`, `group-scope`, `metadata` | Export-PostureCaSnapshot into the same folder | The CA checks and documents read these |
| `collection` | run manifest: tenant, account, scopes, API versions, files, errors | `metadata.json` stays the CA snapshot's own |

Not yet collected here: Entra devices and Intune (A.1 sections 8 and 9, with the devices domain), legacy sign-ins
(section 12), Exchange and Purview (A.2), SharePoint and Teams (A.3), Maester (A.4).

## Scopes

Required: Policy.Read.All, Directory.Read.All, Group.Read.All. Optional, each unlocking the steps named above:
User.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All, RoleManagement.Read.Directory,
OnPremDirectorySynchronization.Read.All, IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All. All delegated, all read-only.

```powershell
Connect-MgGraph -Scopes Policy.Read.All, Directory.Read.All, Group.Read.All, User.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All, RoleManagement.Read.Directory, OnPremDirectorySynchronization.Read.All, IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All -NoWelcome
Invoke-PostureCollection -OutRoot ~/audit/evidence
```

At 20k users the users and registration pulls dominate; expect 20 to 40 minutes, as the audit plan says.
