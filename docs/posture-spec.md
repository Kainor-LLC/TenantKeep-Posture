# Tenantkeep Posture: the Microsoft security posture report, with Conditional Access documentation and diff

| | |
|---|---|
| Owner | Connor Johnson, Kainor LLC |
| Version | v0.12 draft, 2026-10-13 |
| Status | Concept, pre-build. First deployment target: the first customer audit (m365-environment-audit-plan.md v0.3) |
| Form | PowerShell 7 module, read-only. Runs locally or as a customer-hosted Azure Automation runbook (section 11). Renders HTML / Markdown / PDF |
| Changelog | v0.2: customization model (10), deployment options (11), Endpoint security domain (4.11), Email security promoted to a full domain (4.10), scores and recommendations (4.12). v0.3: interactive output (7), Marketplace listing (11.1), feature backlog (12), decisions D15 to D19. v0.4: Azure domain (4.13); profile gains Azure footprint; D20 and D21. v0.5: decisions resolved (14), working name Posture, pricing both periods, Hybrid domain (4.14), baselines shipped (10.6), deployment A and B with Marketplace from day one and opt-in report site, MVP re-cut (9). v0.6: Tenantlock Posture proposed, D1 and D6 updated, scope confirmed as full v1. v0.7: Tenantlock dropped (live competitor at tenantlock.com), Realmlock proposed, TenantLock added to the competitor table, positioning sharpened, golden-tenant compare added to the backlog (12.8). v0.8: TenantLock row updated from its terms of service, open-core decision D22 added. v0.9: name decided, Tenantkeep Posture. v0.10: Tenantkeep CA standalone SKU (5.5, 8, 9, 11), government baselines settled and GCC High marked not planned (10.6), D6 and D11 closed. v0.11: D22 decided proprietary; licensing and distribution written into section 6, free tier reworded, readable-code risk added. v0.12: D22 revised to source-available with a public repo; section 6, positioning and risks updated |
| Inputs | The evidence folder produced by the audit plan's Appendix A scripts (A.1 Entra/Intune, A.2 EXO/Purview, A.3 SPO/Teams, A.4 Maester), plus SAM report CSV imports |

Anything marked **(verify)** is something I'm not certain about as of this writing. The audit plan uses the same convention.

---

## 0. The pitch

Not another test engine. Maester, ScubaGear and Microsoft's own tools already tell an engineer what's wrong. Nobody hands those to a client or a board. This is the deliverable: a branded, evidence-backed posture report with a findings register, a Copilot readiness section, and a "what changed since last quarter" page, generated from a read-only collection an MSP or internal team already knows how to run. Plus the piece everyone wants and nobody has: Conditional Access documented in plain English, and a diff of every CA change between two dates.

It runs on the customer's machine or in their automation account. Nothing leaves. The licence is a signed file verified offline (docs/licensing.md, decided 2026-10-15).

---

## 1. Where it sits against what exists

| Tool | What it is | What it isn't |
|---|---|---|
| Maester | Free, Pester-based pass/fail tests for Entra, Intune, EXO, with EIDSCA. Great engine | Not client-facing, no branding, no risk register, no trend narrative, no Copilot/oversharing story **(verify current coverage, it grows monthly)** |
| ScubaGear (CISA) | Free baseline conformance for M365 | Government baseline, config-only, technical output |
| Microsoft Zero Trust Assessment | Free, scored, Microsoft-branded | Microsoft's framing and branding, limited customization |
| Secure Score | Built in | Moves when Microsoft changes scoring; nobody can explain a drop to a CFO |
| CIPP | MSP operations platform, OSS, hosted option | Ops console, not a report; another platform to run |
| TenantLock (tenantlock.com) | Browser-based multi-tenant M365 console: GDAP switcher, dashboard, short security checklist, Intune config compare and merge, CA policy matrix with gap analyzer, Word/Excel/PowerPoint exports, free with premium white-label. Same no-backend trust story as ours, same three buyers. Live in 2026. Solo developer, Norway; terms say MIT and open source, but no public GitHub repo was findable on 2026-10-10 **(verify; may be private or renamed)** | No persistence by design (the cache dies with the tab), so no history, no trend, no CA diff between dates, no drift alerts, no scheduled runs. Browser-only, so no hybrid AD. No Copilot readiness, Defender effective state, Azure, frameworks, risk register, exceptions or interactive report. Nothing on a phone |
| Consultant deliverable | What an MSP charges $3k to $10k for today | Hand-built in Word every time |

Position: **the deliverable and the time dimension, not the console.** TenantLock proves the buyers and the trust story are real; its architecture cannot add time, hybrid or depth without becoming a different product. It claims "free, open source" (with no visible repo); this product is source-published under a source-available license, read-only, and runs inside the customer's tenant, with signed releases. That comparison is won on the website in one line. The CA policy matrix and gap check are now table stakes; the CA diff between two dates is the differentiator and leads the website. **Consume the free engines where it helps, don't rebuild them.** Maester's JSON results and the Zero Trust Assessment output can be inputs to the report **(verify output formats and license terms; Maester is MIT)**. Add what they don't have: the client narrative, risk and effort scoring, Copilot readiness and oversharing, governance (access reviews, access packages, lifecycle), CA documentation and diff, trend over time, white label.

---

## 2. Who buys it and what they hand over

| Buyer | Deliverable | Cadence |
|---|---|---|
| MSP | Branded posture report per client; CA change report | Monthly or quarterly, often as part of a vCISO or security add-on they already charge for |
| Internal security engineer (you, in three weeks) | Board or sponsor report; audit evidence; E5 business case backed by "not evaluated, requires P2" rows | Quarterly, plus the initial baseline |
| Consultant | Assessment deliverable at the end of an engagement | Per engagement |

The report is also the marketing. Every free-tier report carries a footer; every paid report that lands on a CIO's desk is a reference.

---

## 3. Report structure

1. **Cover.** Client name and logo, prepared-by (MSP name and logo), tenant display name, collection date and window, report version, confidentiality line.
2. **Executive summary (one page).** Overall posture score with the method stated in one sentence. Six headline numbers: MFA registered %, admins on phishing-resistant auth %, permanent Global Admin count, Intune compliance %, external sharing exposure (sites with Everyone / anonymous links), Copilot readiness %. Top five risks. What changed since the last report. What we recommend this quarter, in three buckets.
3. **Microsoft scores page.** Secure Score by category, Identity Secure Score, Compliance Manager, Exposure Management where licensed, Intune compliance, Maester pass rate, with 30 and 90 day trend. Context for the reader, not the grade (section 4.12).
4. **Domain scorecards (one page each).** Identity and privileged access; Authentication methods; Conditional Access; Devices (Windows, macOS, Linux, mobile); Endpoint security (Defender, ASR, BitLocker, FileVault, baselines); Email security; Data protection (Purview); Collaboration and oversharing (SharePoint, OneDrive, Teams); Copilot readiness; Governance and lifecycle; Operations and monitoring; Azure (when the profile says there is one); Hybrid identity and on-prem AD (when the identity model is hybrid). Each scorecard: status table (check, result, target, severity, license), one paragraph of narrative, trend arrows against the previous run, evidence file references. Which scorecards appear, and with what targets, comes from the org profile and baseline (section 10).
5. **Findings register.** Same schema as the audit plan's Appendix E so `findings.csv` flows in and out: ID, workstream, finding, evidence, likelihood 1 to 5, impact 1 to 5, risk, effort S/M/L/XL, dependency, quick win, bucket, owner, status.
6. **Recommendations.** Every failed check's remediation, effort, user impact, license needed and Learn link, grouped by bucket: Stop the bleeding, Foundations, Program workstreams, Later. Same buckets as the audit plan section 5. Microsoft's own Secure Score recommendations sit alongside, sorted by score impact (4.12), and Defender for Cloud's Azure recommendations the same way (4.13).
7. **Conditional Access documentation.** Per-policy pages and the policy matrix (section 5). Can also be delivered standalone.
8. **Conditional Access change report.** Diff since the previous snapshot (section 5).
9. **Appendix.** Methodology, baseline and profile used, roles and scopes, collection timestamps, checks not evaluated and why (license, permission, data missing, not applicable per profile), accepted-risk exceptions with expiry, evidence index, tool and API versions, optional framework crosswalk (10.4).

Two templates: **Executive** (cover, summary, scorecards, roadmap; about 12 pages) and **Full** (everything).

---

## 4. Check catalog by domain

Every check is data, not code in the renderer: ID, domain, title, severity, license required, evidence source, pass condition, remediation text, Microsoft doc link. The catalog grows without touching the report engine, and the public catalog page tells buyers exactly what they get.

License gating is a feature, not a limitation. A check that needs P2 on an E3 tenant renders as **Not evaluated (requires Entra ID P2)** with an "E5 would unlock" tag. Count those rows and you have the E5 business case for free.

Source column refers to the audit plan's evidence file names.

### 4.1 Identity and privileged access

| Check | Pass condition | Source | License |
|---|---|---|---|
| Global Admin count | 2 to 5 including break-glass | 04-role-assignments-active | none |
| Permanent vs eligible privileged assignments | 0 permanent outside break-glass | 04-role-assignments-active, 04-role-assignments-pim-eligible | P2 for eligible |
| Admins synced from on-prem | 0 | 04-role-assignments-active joined to 06-users | none |
| Admins with mailboxes or E3/E5 licenses | 0 | 06-users | none |
| Break-glass accounts exist, cloud-only, excluded from CA, alerted on | all four | 06-users, 03-ca-policies-full | none |
| PIM settings on GA, PA, SA, CAA | MFA on activation, approval on GA, max duration 8h or less | role management policies **(add to A.1)** | P2 |
| Service principals holding directory roles | reviewed list, none with GA | 04-role-assignments-active | none |
| User consent setting | Admin consent required, or verified-publisher low-impact only | 02-authorization-policy | none |
| Admin consent workflow | enabled with reviewers | 02-admin-consent-request-policy | none |
| App credentials expiring in 30 / 90 days | 0 unowned, all with owners | 10-app-registrations | none |
| High-privilege application permissions | each one justified | 10-graph-app-permissions | none |
| Inactive guests over 90 days | 0, or review scheduled | 06-users with signInActivity | P1 |
| Cross-tenant access defaults | inbound trust settings reviewed, not default-open | 02-cross-tenant-access-defaults | none |
| Log retention and export | diagnostic settings to Log Analytics or SIEM | Azure diagnostic settings **(add)** | none |
| Risky users unaddressed | 0 high-risk users older than 7 days | 11-risky-users | P2 |

### 4.2 Authentication methods

| Check | Pass condition | Source | License |
|---|---|---|---|
| SMS and voice | disabled, or scoped to a migration group | 02-authentication-methods-policy | none |
| Authenticator number matching and app context | enabled | same | none |
| Passkeys (FIDO2 and Authenticator passkeys) | enabled, admin profile restricted to known AAGUIDs where used | same | none |
| Legacy MFA/SSPR policy migration | Migration complete | same | none |
| Temporary Access Pass | enabled, one-time use default | same | none |
| MFA registered % | target 100%, report the number | 05-auth-registration-summary | none |
| Passwordless-capable % | trend up; target set by client | same | none |
| Admins without a phishing-resistant method | 0 | 05-auth-registration joined to 04-role-assignments | none |
| Per-user MFA enforced | 0 users | legacy per-user state **(add)** | none |

### 4.3 Conditional Access

| Check | Pass condition | Source | License |
|---|---|---|---|
| Legacy authentication blocked | enabled policy, all users, no broad exclusion | 03-ca-policies-full | P1 |
| MFA for all users | enabled, all cloud apps, break-glass excluded only | same | P1 |
| Phishing-resistant auth strength for admin roles | enabled, all privileged roles | same, 02-authentication-strengths | P1 |
| Risk-based policies | sign-in and user risk policies enabled | same | P2 |
| Device compliance required for M365 on Windows and macOS | enabled | same | P1 + Intune |
| Report-only pileup | no policy in report-only over 90 days | same, modifiedDateTime | P1 |
| Exclusion group size | no exclusion group over N members (default 25), listed | same, 07-groups | P1 |
| Trusted-location MFA bypass | none, or justified and documented | same, 03-named-locations | P1 |
| Sign-in frequency and persistent browser for admins | set | same | P1 |
| Token protection | enabled or report-only with a date | same | P1 |
| Microsoft-managed policies | state recorded, none silently disabled | same | P1 |
| Break-glass excluded from every blocking policy | yes | same | P1 |
| Policies referencing deleted objects | 0 | same, resolved-names | P1 |
| Disabled policies older than 90 days | 0, or documented | same | P1 |
| Naming convention compliance | all policies match the configured pattern | same | P1 |

### 4.4 Devices

| Check | Pass condition | Source | License |
|---|---|---|---|
| Intune compliance % by platform | report, target set by client | 09-intune-summary-compliance | Intune |
| Stale Entra devices over 90 days | 0, or cleanup rule enabled | 08-entra-devices-stale | none |
| Join type mix | Entra joined trend up; hybrid and registered counted | 08-entra-devices-by-join-os | none |
| Autopilot registered % of Windows fleet | report | 09-autopilot-devices vs 09-intune-managed-devices | Intune |
| BitLocker keys escrowed % | 100% of Windows | 08-entra-devices **(add key presence)** | none |
| FileVault escrowed % | 100% of Macs | 09-intune-managed-devices **(verify field)** | Intune |
| Windows 10 without ESU | 0 | 09-intune-summary-windows-builds | Intune |
| Apple push cert and VPP tokens | over 60 days from expiry | 09-apple-push-cert, 09-apple-vpp-tokens | Intune |
| Enrollment restrictions | personal Windows blocked unless BYOD policy says otherwise | restrictions **(add to A.1)** | Intune |
| Endpoint security baseline present | AV, EDR, ASR, firewall, disk encryption policies exist and assigned | 09-intune-config-profiles-* **(extend to endpoint security)** | Intune |
| Windows LAPS enabled | policy assigned to all Windows | same | Intune |
| MDE connector | enabled | **(add)** | Intune |
| Device cleanup rule | enabled | **(add)** | Intune |
| Linux endpoints enrolled | report count; usually 0, and that's a finding at scale | 09-intune-summary-os-agent-join | Intune |

### 4.5 Data protection (Purview)

| Check | Pass condition | Source | License |
|---|---|---|---|
| Unified audit log on, retention | on; 180 days E3, 1 year with E5 Premium; policy for longer where required | exo-01-audit-config, pv-05-audit-retention-policies | none / E5 |
| Sensitivity labels defined and published | at least one policy, scoped to all users | pv-01-sensitivity-labels, pv-01-label-policies | E3 |
| Auto-labeling | at least one policy in enforcement | pv-01-autolabel-policies | E5 |
| Container labels (sites, teams, groups) | enabled and in use | pv-01-sensitivity-labels, spo-sites | E3 |
| DLP by workload | EXO, SPO, OneDrive, Teams, Endpoint, each with at least one enforced policy | pv-02-dlp-policies, pv-02-dlp-rules | E3 / E5 for Endpoint |
| Endpoint DLP devices onboarded | % of Windows and macOS | **(add)** | E5 |
| Retention policies vs schedule | policies exist; Legal sign-off recorded | pv-03-retention-* | E3 |
| Insider Risk Management | at least one policy; HR connector | pv-04-insider-risk-policies | E5 |
| DSPM for AI | enabled, reports reviewed | portal evidence **(verify any API)** | E5 / Copilot |
| Purview role assignments | reviewed, no standing Compliance Admin outside a group | pv-08-role-groups | none |

### 4.6 Collaboration and oversharing

| Check | Pass condition | Source | License |
|---|---|---|---|
| Tenant external sharing level | Existing guests or New and existing guests, not Anyone | spo-tenant-settings | none |
| Anonymous links | disabled, or expire within 30 days | same | none |
| Default link type and permission | Specific people, View | same | none |
| Domain restrictions | allow or block list in place where policy requires | same | none |
| Everyone and Everyone except external users claims | hidden from people picker | same | none |
| Guest expiration | enabled, 60 days or less | same | none |
| Sites with Everyone except external users permissions | count, trend down; 0 on labeled sites | SAM DAG report import **(no Graph API as far as I know, verify)** | SAM |
| Sites with active anonymous links | count, trend down | SAM DAG import | SAM |
| Ownerless sites and teams | 0, ownership policy enabled | spo-sites, SAM site ownership policy | SAM |
| Inactive sites | lifecycle policy enabled | SAM | SAM |
| Restricted Access Control enabled on tenant | enabled | spo-tenant-settings | SAM |
| M365 group expiration policy | enabled | groupLifecyclePolicies **(add to A.1)** | P1 |
| Teams federation | not open to all domains, or justified | teams-federation | none |
| Teams guest access | enabled with governance, or disabled | teams-client-config | none |
| Anonymous meeting join and lobby | lobby for external, anonymous join reviewed | teams-meeting-policy-global | none |
| Third-party Teams app consent | restricted | teams-app-permission-policies | none |

### 4.7 Copilot readiness

This is the section the client reads first. It answers one question: can we turn on (or expand) Microsoft 365 Copilot without it surfacing things people shouldn't see. The gates follow the order that works: baseline the exposure, apply stopgaps, clean up with the people who own the content, keep it clean with governance.

| # | Gate | Pass condition | Hard gate | Source | License |
|---|---|---|---|---|---|
| C1 | Audit log on, Copilot interactions retained | on; Copilot activity in audit | yes | exo-01-audit-config | E3 |
| C2 | SharePoint Advanced Management available | licensed (included tenant-wide with any Copilot license **(verify current bundling)**) | yes | 01-subscribed-skus | SAM |
| C3 | Oversharing baseline run | DAG reports (EEEU, broad links, external) run within 90 days | yes | SAM DAG import | SAM |
| C4 | Default sharing link | Specific people | yes | spo-tenant-settings | none |
| C5 | Anonymous links | disabled or expiring | no | spo-tenant-settings, DAG | none |
| C6 | Sensitivity labels published, container labels in use | yes, with at least one encrypting label for the top tier | yes | pv-01-*, spo-sites | E3 |
| C7 | Restricted Access Control on high-sensitivity sites | applied to every site in the top tier until its review completes (stopgap, not the end state) | no | spo-sites RestrictedAccessControl | SAM |
| C8 | Restricted Content Discovery on sites pending review | applied to sites flagged by C3 and not yet reviewed | no | **(verify PnP support)** | SAM |
| C9 | Restricted SharePoint Search | off (end state), or on with an allow list and a sunset date | no | **(verify PnP cmdlet; SPO module is Windows-only)** | none |
| C10 | Site access reviews initiated from DAG | initiated for all C3-flagged sites; completion % reported | no | SAM | SAM |
| C11 | Entra access reviews recurring | site owners, guests, privileged roles, PIM groups, quarterly | no | identityGovernance accessReviews definitions **(add to A.1)** | P2 |
| C12 | Access packages for standard access | at least the top 10 shared resources delivered by package, not ad hoc sharing | no | entitlementManagement accessPackages **(add)** | P2 |
| C13 | DLP policy for the Copilot location | sensitive labels excluded from Copilot processing, enforced | no | pv-02-dlp-policies | E5 |
| C14 | DSPM for AI reviewed | enabled; oversharing recommendations actioned or scheduled | no | portal evidence | E5 / Copilot |
| C15 | Copilot settings governed | web grounding decision recorded; agents and Copilot Studio governance; Graph connectors reviewed | no | admin center evidence **(verify API)** | Copilot |
| C16 | Label inheritance verified | test documented: Copilot output inherits the most restrictive source label | no | test evidence | E3 |
| C17 | Copilot deployed ahead of C3 | licensed count vs C3 date; flag if deployed before baseline | status, not pass/fail | 01-subscribed-skus | Copilot |
| C18 | Ownerless sites | 0, ownership policy enabled | no | spo-sites, SAM | SAM |

Scoring: hard gates must all pass for the section to show anything other than **Blocked**. Once unblocked, readiness % = passed gates / evaluated gates, with "not evaluated" rows excluded and listed. Keep it that simple so an MSP can explain it in one breath.

The narrative for this page should say plainly that RAC, RCD and Restricted SharePoint Search are stopgaps. They let you turn Copilot on while site owners clean up. The end state is correct permissions, labels that encrypt the top tier, and reviews that keep it that way.

### 4.8 Governance and lifecycle

| Check | Pass condition | Source | License |
|---|---|---|---|
| Source of truth for accounts | HRIS-driven (API-driven provisioning or connector), not manual | interview plus provisioning config | P1 |
| Deprovisioning SLA | documented, measured | interview, 06-users disabled dates | none |
| Inactive users over 90 days | 0 enabled, or policy | 06-users signInActivity | P1 |
| Orphan accounts | enabled users with no HR record: 0 | HRIS extract join | none |
| Access reviews on privileged roles | recurring, quarterly or better | accessReviews **(add)** | P2 |
| Access reviews on guests | recurring | same | P2 |
| Access reviews on PIM groups and app roles | recurring | same | Entra ID Governance |
| Access packages in use | count, catalogs, connected orgs | entitlementManagement **(add)** | P2 |
| Lifecycle workflows | joiner, mover, leaver workflows active | lifecycleWorkflows **(add)** | Entra ID Governance |
| PIM for Groups | eligible, not permanent, for admin groups | 04-role-assignments-pim-eligible | P2 |
| SSO protocol mix | % SAML/OIDC vs password/linked; ADFS relying parties 0 | 10-service-principals, ADFS export (jump box) | none |
| SAML signing certs expiring in 90 days | 0 without owner | 10-service-principals | none |
| SCIM provisioning | enabled for top apps; errors reviewed | provisioning status **(add)** | P1 |
| Administrative units and RBAC | in use at multi-BU scale | admin units **(add)** | P1 |
| App owners assigned | 100% of enterprise apps | 10-service-principals | none |

### 4.9 Operations and monitoring

| Check | Pass condition | Source | License |
|---|---|---|---|
| SIEM in place with M365, Entra, Intune, Defender sources | yes | interview, diagnostic settings | varies |
| M365 backup decision | documented (Microsoft 365 Backup, third party, or accepted risk) | interview | varies |
| Expiry calendar | app secrets, SAML certs, Apple push, VPP, Entra Connect, domains all tracked | this report's expiry table | none |
| Break-glass tested | within 6 months, documented | interview | none |
| Message Center triage | owner named | interview | none |
| Entra Connect Health | enabled, alerts routed | Azure | P1 |

### 4.10 Email security

A full domain. The data is already in the A.2 folder, and every MSP asks. When the profile names a third-party gateway (Proofpoint, Mimecast, Abnormal), the MDO delivery checks render as "Covered by third party" with the vendor named; the DNS, forwarding, auth and audit checks are evaluated regardless, because the gateway doesn't fix those.

| Check | Pass condition | Source | License |
|---|---|---|---|
| Preset security policies | Standard or Strict assigned to all users and domains | exo-04-preset-rules-eop, exo-04-preset-rules-mdo | EOP / MDO |
| Anti-phishing | impersonation protection for executives and owned domains, mailbox intelligence on, spoof intelligence on, DMARC honored | exo-04-antiphish | EOP; impersonation needs MDO |
| Safe Links and Safe Attachments | enabled for mail, Teams, Office apps; Safe Documents on | exo-05-mdo-safelinks, exo-05-mdo-safeattachments, exo-05-mdo-global | MDO P1 / P2 |
| Zero-hour auto purge | enabled for spam, phish, malware | exo-04-eop-content-filter | EOP |
| Quarantine policies and user notifications | reviewed; admin-only release for high-confidence phish | exo-05-quarantine-policies | EOP |
| Automatic external forwarding | blocked by outbound spam policy | exo-04-outbound-spam | EOP |
| Connection filter IP allow list | empty, or each entry justified | exo-04-eop-connection-filter | EOP |
| SCL -1 transport rules | 0, or scoped to an authenticated connector | exo-03-transport-rules | none |
| Enhanced Filtering for Connectors | on when a gateway is in front | exo-03-inbound-connectors | EOP |
| DKIM | enabled and rotated on every accepted domain | exo-02-dkim | none |
| DMARC | p=reject, or p=quarantine with a dated plan; rua reporting set | dns-01-mail-records | none |
| SPF | valid, under 10 lookups, hard fail | dns-01-mail-records | none |
| MTA-STS and TLS-RPT | published **(add to A.2 DNS checks)** | dns-01 | none |
| Mailboxes with external forwarding | 0 unexplained | exo-09-mailboxes-with-forwarding | none |
| Inbox rules forwarding externally | 0 **(add; use audit search, not Get-InboxRule, at 20k)** | audit | none |
| Legacy protocols per mailbox | POP, IMAP, SMTP AUTH disabled org-wide and per mailbox | exo-01-auth-policies, exo-10-cas-summary | none |
| Shared mailbox sign-in | blocked on 100% | exo-09-mailboxes-by-type joined to 06-users | none |
| Mailbox auditing | on by default, not disabled anywhere | exo-01-audit-config | none |
| Attack simulation training | at least one campaign in 90 days | Graph attackSimulation **(add)** | MDO P2 |
| Outbound DKIM / ARC for the gateway | ARC trusted sealers configured when a gateway is in front | exo-01-orgconfig | EOP |

### 4.11 Endpoint security

Defender, attack surface, encryption and OS hardening across Windows, macOS, Linux and mobile. Two sources matter here and they disagree often: **policy state** from Intune (what you told devices to do) and **effective state** from Defender (what devices are actually doing). Report both, flag the gap. The gap is the finding.

Defender data needs the Defender for Endpoint API or Graph advanced hunting, which are separate consents from the Graph scopes in A.1 **(verify current scopes: `Machine.Read.All` on the WindowsDefenderATP app, `ThreatHunting.Read.All` on Graph)**. Add a `Get-DefenderBaseline.ps1` collector to the kit.

**Defender for Endpoint**

| Check | Pass condition | Source | License |
|---|---|---|---|
| MDE onboarded % by platform | 100% of Intune-managed Windows, macOS, Linux | Defender machines list vs 09-intune-managed-devices | MDE P1 / P2 |
| Sensor health | 0 inactive or impaired over 7 days | Defender machines | MDE |
| Tamper protection | on, tenant-wide, no exclusions | Intune AV policy, Defender settings | MDE |
| AV mode | active; passive only where the profile names a third-party EDR, and then with a dated migration plan | Defender machines | MDE |
| Cloud-delivered protection, real-time protection, PUA, sample submission, scan schedule | configured per Microsoft baseline | Intune AV policy (settings catalog) | Intune |
| Network protection and web protection | block on Windows and macOS | Intune AV / ASR policy | MDE P1 / P2 |
| Attack surface reduction rules, every rule | block where supported; audit only with a dated plan; never off. Policy state from Intune, effective state per device from `DeviceTvmSecureConfigurationAssessment` | Intune ASR policy; advanced hunting **(verify table and permissions)** | MDE P2 for hunting |
| ASR exclusions | reviewed, documented | Intune ASR policy | Intune |
| EDR in block mode | on | Defender advanced features **(verify API)** | MDE P2 |
| Automated investigation and response | full remediation for all device groups | Defender settings **(verify API)** | MDE P2 |
| Device discovery | standard mode | Defender settings **(verify)** | MDE P2 |
| Defender Vulnerability Management | exposure score reported; 0 critical CVEs open over 30 days | Defender vulnerabilities API **(verify)** | MDVM |
| Defender for Identity (hybrid only) | sensors on every DC and ADFS server, 0 health alerts | MDI **(verify API)** | E5 |
| Defender for Cloud Apps | app governance on, OAuth app policies in place | MDA **(verify API)** | E5 |
| Defender XDR hygiene | 0 incidents open over 7 days without assignment | Graph security/incidents | E5 |

**Windows**

| Check | Pass condition | Source | License |
|---|---|---|---|
| Security baselines | MDM, Defender, Edge baselines deployed on the current version | Intune baselines **(add to A.1)** | Intune |
| BitLocker policy | XTS-AES 256, TPM required, silent enablement, recovery keys escrowed to Entra | Intune disk encryption policy | Intune |
| BitLocker effective | % encrypted (Intune encryption report), % keys escrowed, 0 devices encrypted with no key in Entra | encryption report **(add)**, 08-entra-devices | Intune |
| Recovery key access audited | key reads reviewed; LAPS/BitLocker reveals in audit | audit log | none |
| Windows Firewall | on for domain, private, public | Intune firewall policy | Intune |
| Windows LAPS | policy on all Windows; % with a current password; rotation after use | Intune account protection policy | Intune |
| Credential Guard, HVCI, Secure Boot, TPM 2.0 | enabled; % eligible | device health attestation, hardware inventory | Intune |
| SmartScreen and Smart App Control | SmartScreen on; SAC state recorded | Intune | Intune |
| Office macros from the internet | blocked | Intune or Office cloud policy | M365 Apps |
| Windows Hello for Business | enabled, cloud Kerberos trust configured when hybrid | Intune | Intune |
| Local admin population | count of users holding local admin; target: 0 standing, elevation via EPM or equivalent | Intune EPM report or jump box | Intune Suite for EPM |
| Update compliance | % current within 30 days; feature update deadline set | Intune update reports, Autopatch | Intune |

**macOS**

| Check | Pass condition | Source | License |
|---|---|---|---|
| FileVault | policy deployed; % enabled; personal recovery key escrowed and rotated after reveal | Intune encryption report | Intune |
| Gatekeeper, SIP, XProtect, firewall | enforced via settings catalog and compliance | Intune | Intune |
| Platform SSO | deployed; Secure Enclave or password sync mode recorded | Intune | Intune |
| MDE on macOS | onboarded, network protection on | Defender machines | MDE |
| Users admin by default | 0, or a managed elevation tool named in the profile | compliance / inventory | Intune |

**Linux and mobile**

| Check | Pass condition | Source | License |
|---|---|---|---|
| MDE on Linux | onboarded, tamper protection on | Defender machines | MDE |
| Disk encryption (LUKS) | enforced; custom compliance script reports it | Intune custom compliance | Intune |
| Sudo baseline | no NOPASSWD, logging shipped | custom compliance | Intune |
| Mobile | app protection policies for BYOD; MDM compliance for corporate; jailbreak/root detection on | Intune | Intune |

### 4.12 Microsoft scores and recommendations

Microsoft already publishes a score and a recommendation list for every tenant. Use them, don't fight them, and don't let them be the grade.

- **Secure Score**: overall and by category (Identity, Devices, Apps, Data), 30 and 90 day trend. Graph `security/secureScores` with `SecurityEvents.Read.All`.
- **Secure Score control profiles**: every control with implementation status, score impact, Microsoft's remediation text, implementation cost and user impact. Graph `security/secureScoreControlProfiles`. The not-implemented controls sorted by score impact become the "Microsoft recommends" list in the Recommendations section, with Microsoft's text attributed as theirs **(verify terms for rendering that text in a report for the same tenant)**.
- **Identity Secure Score**, **Compliance Manager** score (portal export; no clean API as far as I know **(verify)**), **Exposure Management** score on E5 **(verify API)**, **Intune compliance %**, **Maester pass rate**, **Zero Trust Assessment** score if run.
- **Where Microsoft and this report disagree, say why.** Secure Score penalizes a tenant for missing MDO controls when Proofpoint is in front; this report marks them covered. Secure Score moves when Microsoft changes weights; this report's grade only moves when the tenant changes. That paragraph is the thing a CFO needs when the two numbers don't match.

Recommendations engine, for every failed or partially passed check: remediation steps in plain language, Learn link, effort S/M/L/XL, user impact low/medium/high, license needed, bucket. Checks declare these in the catalog. The MSP can override the text per check in the narrative layer (10.1) when they have a house way of doing it.

### 4.13 Azure

Most M365 tenants have some Azure: the Automation account this product deploys into, a few VMs, a storage account someone made in 2019, sometimes a real estate of workloads. The profile asks **Azure footprint: none / platform only / workloads**. "None" hides the domain. "Platform only" runs the subscription hygiene and IAM checks. "Workloads" runs everything.

**Lean on Microsoft here, not on a hand-written catalog.** Defender for Cloud already evaluates every subscription against the Microsoft cloud security benchmark (MCSB), produces recommendations with severity, remediation text and affected resources, and scores them. Foundational CSPM is free on every subscription **(verify current free-tier scope)**. The report reads those assessments through the Security REST API and Azure Resource Graph (`securityresources` table) and renders them the way it renders Secure Score control profiles for M365: Microsoft's findings, attributed, sorted by impact. Our layer on top is IAM and the subscription hygiene Defender for Cloud only covers with a paid plan.

Background for the engineer building this, since it's the least familiar domain. Read in this order **(verify links at build time)**:

1. Microsoft cloud security benchmark overview and the control families: `learn.microsoft.com/security/benchmark/azure/`
2. Defender for Cloud security recommendations reference, the full list with policy definitions: `learn.microsoft.com/azure/defender-for-cloud/recommendations-reference`
3. How Azure Secure Score and security controls work: `learn.microsoft.com/azure/defender-for-cloud/secure-score-security-controls`
4. Per-service Azure security baselines (Key Vault, Storage, VMs, SQL, AKS), each mapped to MCSB
5. Well-Architected Framework, security pillar: design guidance, not checks
6. CIS Microsoft Azure Foundations Benchmark: numbered controls for the crosswalk; reference numbers only, same licensing note as 10.4

Collector: `Get-AzureBaseline.ps1` using `Az.Accounts`, `Az.ResourceGraph`, `Az.Security`, `Az.Resources`, `Az.Monitor`, `Az.PolicyInsights`, all cross-platform on PowerShell 7. Roles: Reader at the management group or on each subscription, plus Security Reader for Defender for Cloud. Resource Graph scales to thousands of subscriptions in one query; never loop `Get-AzRoleAssignment` per subscription at scale. MSPs read client tenants through Azure Lighthouse delegations **(verify Lighthouse support for `Microsoft.Security` reads)**.

**Tenant and subscription hygiene**

| Check | Pass condition | Source | License |
|---|---|---|---|
| Management group hierarchy | exists; subscriptions not sitting at tenant root | Resource Graph | none |
| Defender for Cloud enabled, MCSB initiative assigned | on every subscription, no MCSB policies disabled | `Az.Security`, `Az.PolicyInsights` | none |
| Azure Secure Score | reported per subscription with trend; Microsoft's recommendations listed by severity and resource count | `Microsoft.Security/secureScores`, `assessments` | none |
| Defender plans | Servers, Storage, Key Vault, Databases, Containers, App Service, Resource Manager, APIs: on for subscriptions that hold those resource types; off elsewhere is fine and noted | `Az.Security` pricing | paid per plan |
| Defender CSPM | on where attack paths and CIEM are wanted; "not evaluated, requires Defender CSPM" otherwise | pricing | paid |
| Security contact email and alert notifications | set, severity high or above | `Az.Security` contacts | none |
| Activity log export | diagnostic setting to Log Analytics or Sentinel on every subscription, 365 days or more | `Az.Monitor` | consumption |
| Azure Policy coverage | at least one assignment per subscription beyond MCSB; deny on public IP, public storage, unencrypted disks where the org has decided | `Az.PolicyInsights` | none |
| Resource locks | CanNotDelete on production resource groups, Key Vaults, Recovery Services vaults | Resource Graph | none |
| Tagging | owner and environment tags on 95% of resources | Resource Graph | none |
| Orphaned resources | unattached disks, unused public IPs, empty resource groups, NICs with no VM | Resource Graph | none |
| Cost anomalies | optional: Cost Management anomaly alerts configured | `Az.CostManagement` | none |

**IAM and privileged access** (the layer Defender for Cloud only gives you with Defender CSPM)

| Check | Pass condition | Source | License |
|---|---|---|---|
| Owners per subscription | 3 or fewer, all named, none synced from AD | role assignments via Resource Graph `authorizationresources` | none |
| Owner or User Access Administrator at root or management group | 0 standing; eligible via PIM only | same | P2 for PIM |
| PIM for Azure resources | privileged Azure roles eligible, not permanent | PIM for Azure resources API | P2 |
| Guest users with Azure role assignments | 0, or each justified | role assignments joined to 06-users | none |
| Service principals with Owner or Contributor | each justified; managed identities preferred over app secrets | role assignments joined to 10-service-principals | none |
| Orphaned role assignments | 0 assignments pointing at deleted principals | role assignments where principal unresolved | none |
| Custom roles with wildcard actions | 0 (`*` on Actions or DataActions) | `Get-AzRoleDefinition -Custom` | none |
| Classic administrators | 0 (the role type was retired in 2024; anything left is a finding) | `Az.Resources` | none |
| Role assignments to individual users at resource scope | counted, trend down; groups preferred | Resource Graph | none |
| Key Vault access model | RBAC, not access policies; purge protection and soft delete on; no public network | Resource Graph | none |
| Storage account IAM | shared key access disabled where possible; no anonymous blob access; SAS tokens reviewed | Resource Graph | none |
| Permissions creep index and unused permissions | reported when Defender CSPM is licensed; "not evaluated" otherwise. Entra Permissions Management retired 2025-10-01; these features continue inside Defender CSPM | Defender CSPM CIEM | Defender CSPM |
| Azure AD authentication for data planes | SQL, Storage, Service Bus, Event Hubs using Entra auth, local auth disabled where supported | Resource Graph | none |
| Management plane CA | MFA and compliant device for Microsoft Azure Management in a CA policy (cross-reference 4.3) | 03-ca-policies-full | P1 |

**Workload posture** (rendered from Defender for Cloud assessments, grouped by MCSB control family; the catalog adds nothing here except the grouping and the narrative)

| Family | Examples Defender for Cloud already reports |
|---|---|
| Network | NSGs allowing any-to-any, management ports open to the internet, missing DDoS, no private endpoints on PaaS |
| Data protection | storage without encryption or secure transfer, SQL TDE off, no customer-managed keys where required |
| Logging | diagnostic settings missing on resources, NSG flow logs off |
| Posture and vulnerability | VMs missing endpoint protection, missing updates, vulnerability findings, container image findings |
| Identity | MFA on subscription owners, guest accounts, deprecated accounts (basic set without Defender CSPM) |
| Backup and recovery | VMs without backup, vaults without soft delete |
| Attack paths | internet-exposed VM with high-privilege managed identity, and the like; only with Defender CSPM |

Scoring: Azure contributes to the overall grade through the IAM and hygiene tables, which the catalog owns. The workload table reports Microsoft's Secure Score and findings as context, the same rule as 4.12. Azure Secure Score moves when Microsoft adds recommendations; the report's grade only moves when the tenant changes.

Not in scope, by design: AWS and GCP. Single-cloud Microsoft is the whole point of the company.

### 4.14 Hybrid identity and on-premises Active Directory

Most tenants over a few hundred users are hybrid, and the on-prem side is where the worst findings live: the Entra Connect server nobody patches, Domain Admins with mailboxes, a krbtgt password from 2014, an AD CS template that hands out domain admin. The cloud half of this domain is collectable from Graph. The on-prem half has no cloud API, so it needs code running inside the customer's network. Three ways to do that, none of them an agent of ours:

| Path | How | When |
|---|---|---|
| **Jump-box collector** (default) | `Get-ADBaseline.ps1` runs on any domain-joined Windows machine with RSAT (ActiveDirectory, GroupPolicy, ADCS modules). Read-only, mostly Domain Users rights; a handful of checks need elevated read and render "not evaluated" without it. Writes JSON and CSV into the evidence folder. Windows PowerShell 5.1 or PS7 | Local run; one-off assessments; the first customer (the audit plan already has a jump box) |
| **Hybrid Runbook Worker** (option B) | The Automation account's own on-prem worker, which the customer installs on a server they own. Same collector on the same schedule as the cloud runbooks. It's Azure's agent, in their estate, under their control | Customers on the Automation deployment who want hybrid on the monthly run |
| **Imports** | PingCastle **(verify licensing for consultant and MSP use)**, Purple Knight (free), ADRecon output. Scores and findings rendered as context, like Secure Score, never as the grade | Customers who already run one; MSPs who standardised on one |

This is also why a hosted SaaS version of the product would need an agent, and why it isn't planned: hybrid is in, agents are out, so hybrid stays on paths A and B.

The collector detects what's present (AD CS, ADFS, SCCM, Entra Connect vs Cloud Sync) and the profile's identity model switches the tables below on or off.

**Entra Connect and Cloud Sync** (cloud side, Graph and Entra Connect Health)

| Check | Pass condition | Source | License |
|---|---|---|---|
| Sync tool and version | Entra Connect under 6 months old with auto-upgrade on, or Cloud Sync | organization object, Connect Health | none |
| Connect Health | agents installed, 0 open alerts, sync errors 0 (duplicate attributes, quarantined objects) | Connect Health API **(verify)** | P1 |
| Staging server | present and patched | Connect Health | P1 |
| Password hash sync | on, even with PTA or federation, for leaked credential detection and failover | organization object | none |
| PTA agents | 3 or more on separate servers | Connect Health | P1 |
| Seamless SSO | AZUREADSSOACC computer account key rotated within 30 days | jump box | none |
| Federation | ADFS absent, or a dated migration plan to PHS or PTA | domains | none |
| OU filtering | admin and service OUs excluded from sync | jump box: `Get-ADSyncRule`, connector config | none |
| Hard and soft match protection | BlockSoftMatch and BlockCloudObjectTakeoverThroughHardMatch on | onPremisesDirectorySynchronization settings | none |
| Writeback features | password, device, group writeback each on or off by decision, documented | Connect config | P1 for password writeback |
| Connect server as Tier 0 | no other roles, LAPS, MDE onboarded, RDP restricted, local admins reviewed, gMSA for the sync service, full SQL if over 100k objects | jump box, Defender machines | none |
| Synced admins | 0 (cross-reference 4.1) | 04-role-assignments joined to 06-users | none |

**On-prem privileged access** (jump box)

| Check | Pass condition | Source |
|---|---|---|
| Domain Admins | 5 or fewer, all named, separate admin accounts | `Get-ADGroupMember -Recursive` |
| Enterprise Admins and Schema Admins | empty day to day | same |
| Account, Server, Print, Backup Operators; DnsAdmins; Group Policy Creator Owners | empty or each member justified | same |
| Nested privileged groups | none hiding membership | same |
| Admin accounts hygiene | no mailbox or license (cross-reference 06-users), in Protected Users, "sensitive and cannot be delegated", no SPNs, password set within 365 days | user objects |
| AdminSDHolder | ACL unmodified; orphaned `adminCount=1` accounts cleaned | ACL read |
| krbtgt password age | under 180 days, rotated twice in sequence | user object |
| Built-in Administrator (RID 500) and Guest | RID 500 disabled or monitored; Guest disabled | user objects |
| ms-DS-MachineAccountQuota | 0 | domain object |
| Unconstrained delegation | 0 on anything that isn't a DC | computer objects |
| Constrained and resource-based delegation | reviewed, documented | same |
| Kerberoastable accounts | 0 user accounts with SPNs and RC4 or old passwords; gMSA for services | user objects |
| AS-REP roastable accounts | 0 with pre-authentication disabled | user objects |
| LAPS | Windows LAPS (not legacy) on all workstations and member servers, password age policy set | computer objects, GPO or Intune |
| Local admin membership | controlled by Restricted Groups or Intune, no standing user admins | GPO |
| Tiering and admin workstations | PAWs or at minimum dedicated admin workstations for Tier 0 | interview, GPO |

**AD hygiene** (jump box)

| Check | Pass condition |
|---|---|
| Functional levels | 2016 or higher |
| Domain controllers | supported OS only, 2 or more per domain, FSMO documented, replication healthy, SYSVOL on DFSR, time source correct, Print Spooler off, backed up daily with a tested restore |
| AD Recycle Bin | enabled |
| Stale accounts | users and computers inactive over 90 days disabled; disabled over 180 days moved and reviewed |
| Password policy | 14 characters or longer, lockout set, reversible encryption off; fine-grained policy for admins and service accounts |
| Password never expires | reviewed, none on humans |
| Trusts | SID filtering on, selective authentication for external trusts, each trust justified |
| Protocols | SMBv1 off; SMB signing required on DCs and clients; LDAP signing required and channel binding on; NTLMv1 off; LM hash storage off; NTLM audited; LLMNR and NBT-NS off; WDigest off |
| DNS | scavenging on, zone transfers restricted |
| Credential protection | Credential Guard on (GPO or Intune), RDP with NLA, DSRM password rotated |
| Logging | advanced audit policy set per Microsoft baseline; PowerShell script block, module and transcription logging; DC events forwarded to the SIEM |

**AD CS** (when present)

| Check | Pass condition |
|---|---|
| Vulnerable templates | 0 templates matching ESC1, ESC2, ESC3; template ACLs reviewed (ESC4); CA ACLs reviewed (ESC7) |
| CA flags | EDITF_ATTRIBUTESUBJECTALTNAME2 off (ESC6) |
| Web enrollment | off, or NTLM disabled and EPA required (ESC8) |
| CA hygiene | SHA-256, 2048-bit or longer keys, offline root, CRL and AIA reachable, CA backed up |

**GPO** (when GPO is still the management plane)

| Check | Pass condition |
|---|---|
| Default Domain and Default Domain Controllers policies | unmodified beyond Microsoft baseline, or changes documented |
| Credentials in SYSVOL | 0 (`cpassword`, scripts with embedded secrets, drive maps with credentials) |
| GPO permissions | Authenticated Users can read; edit rights limited to admins; no GPO editable by non-admins |
| Unlinked and disabled GPOs | cleaned up |
| Security baseline | Microsoft Security Compliance Toolkit baselines applied to DCs and member servers |
| Conflicts with Intune | MDMWinsOverGP set on co-managed devices; overlapping settings listed |

**ADFS** (when present)

| Check | Pass condition |
|---|---|
| Relying parties | count, each with an owner and a migration status to Entra |
| Certificates | token-signing and decrypting certs over 90 days from expiry |
| Extranet smart lockout | on |
| Servers | ADFS and WAP patched, treated as Tier 0, audit logging on |
| Plan | dated decommission plan |

**Endpoint management, hybrid**

| Check | Pass condition | Source |
|---|---|---|
| Join type | hybrid-joined vs Entra-joined %, trend toward Entra join for new devices | 08-entra-devices-by-join-os |
| SCCM co-management | enabled; workloads moved to Intune listed (compliance, device configuration, endpoint protection, updates, apps) | SCCM export |
| Auto-enrollment | GPO-based Intune auto-enrollment on for hybrid devices | GPO |

Scoring: privileged access and hygiene feed the grade. AD CS, GPO and ADFS tables count only when present. Imported PingCastle or Purple Knight scores are context.

---

## 5. Conditional Access documentation and diff generator

Worth building first. It's useful on the first customer tenant in week one, it sells on its own, and the posture report's CA pages are just its output.

### 5.1 Snapshot: `Export-PostureCaSnapshot`

Writes one folder per run:

| File | Contents |
|---|---|
| `policies.json` | Full policy objects, untouched |
| `named-locations.json` | All named locations |
| `auth-strengths.json` | Built-in and custom strengths |
| `auth-context.json` | Authentication context class references |
| `resolved-names.json` | Every ID referenced by any policy mapped to display name and type: users, groups, roles, apps, locations, strengths. Deleted objects flagged |
| `group-scope.json` | For every included or excluded group: member count, and a hash of the sorted member list (member UPNs stored only with `-IncludeMembers`) |
| `metadata.json` | Tenant, timestamp, account, scopes, module version, policy count |

Scopes: `Policy.Read.All`, `Directory.Read.All`, `Group.Read.All`. Read-only.

### 5.2 Documentation: `New-PostureCaDocument`

Output in Markdown, HTML, or PDF. Per policy, one page:

- Name, ID, state, created, last modified.
- One-line plain-English summary generated from the policy: "Require phishing-resistant MFA for users in Global Administrator and 11 other roles, all cloud apps, any platform. Excludes BreakGlass-01, BreakGlass-02."
- Assignments: users, groups, roles, guest types, external tenants, included and excluded, resolved to names, with group member counts.
- Target resources: apps, user actions, authentication context, resolved.
- Conditions: platforms, locations (resolved), client apps, sign-in and user risk, device filter (rendered readably), insider risk if present.
- Grant controls: operator, controls, authentication strength with its allowed methods listed.
- Session controls: sign-in frequency, persistent browser, app-enforced restrictions, CAE, token protection, disable resilience defaults.
- Health flags: report-only age, disabled age, references to deleted objects, exclusion groups over the size threshold, empty included groups, naming pattern mismatch.

Plus the tenant-level pages:

- **Policy matrix**: policies as rows, personas or app groups as columns, with the control applied in each cell. Configurable column set (default: All users, Admin roles, Guests, Workload identities; All apps, Office 365, Admin portals, Register security info).
- **Coverage findings**: the section 4.3 checks, rendered here as well.
- **Naming convention report**: pattern from `brand.json` or a `-NamePattern` parameter; list of non-conforming policies and a proposed name for each (you're working on conventions; this makes the cleanup list for you).

### 5.3 Diff: `Compare-PostureCaSnapshot -Before <folder> -After <folder>`

Produces a change report, Markdown and HTML, email-ready:

- Policies added, removed, renamed, state changed (enabled, disabled, report-only), modified.
- Field-level before and after for every modified policy, using the resolved names, not IDs.
- Named location, auth strength and auth context changes.
- Scope drift: group member count deltas for every group a policy references, member-level diff when both snapshots were taken with `-IncludeMembers`.
- **Risk-relevant changes called out at the top**: an exclusion added to an MFA or legacy-auth policy, a policy moved from enabled to report-only or disabled, a break-glass account removed from an exclusion, a trusted location added, an auth strength weakened, a device-compliance requirement removed, a policy now referencing a deleted object.
- Exit code non-zero when risk-relevant changes exist, so a runbook can alert on it.

### 5.4 Scheduling in the customer's tenant

No Kainor server, so the schedule runs where the customer already runs things: an Azure Automation runbook with a managed identity (the first customer is getting one), a GitHub Action, or a Mac launchd job for a solo admin. Nightly snapshot to a storage account or a git repo, diff against the previous, Teams or email notification on risk-relevant changes. Document all three; ship the runbook as a sample.

### 5.5 Standalone product: Tenantkeep CA

Decided 2026-10-13. The CA tooling ships as its own product, in two tiers (the module is source-available throughout, D22):

- **Free:** `Export-PostureCaSnapshot`, `New-PostureCaDocument`, `Compare-PostureCaSnapshot`, run locally, any number of tenants, free-tier license. This is the lead magnet and the thing people post screenshots of.
- **Tenantkeep CA (licensed, CA only):** the Automation deployment scoped to CA: nightly snapshots in the customer's tenant, diff against the previous, risk-relevant change alerts to Teams or email, white-label change reports, history across runs, the Static Web App opt-in. One tenant. Priced as an entry SKU (section 8) with an upgrade path to Posture; the MSP tier includes it for every client tenant.
- **Marketplace:** the same template, with a "Conditional Access only" plan next to "Full posture" in `createUiDefinition.json`. One listing, two plans.

Ships in weeks 11 to 12 with option B (section 9), because everything licensed in it is the scheduling and delivery layer B provides.

---

## 6. Module design

PowerShell 7, Mac first, Windows and Linux supported. Read-only everywhere. Roles per the audit plan section 2.1: Global Reader, Security Reader, View-Only Organization Management, Purview view-only role group, Reports Reader. PnP needs its app registration, documented with a consent URL for MSPs.

| Command | Does |
|---|---|
| `Connect-Posture` | Graph, EXO, IPPS, PnP, Teams sessions with the read scopes; records context |
| `New-PostureProfile` | Interactive wizard, about 12 questions, writes `profile.json` (section 10); auto-detects licenses from 01-subscribed-skus and asks you to confirm |
| `Invoke-PostureCollection` | Wraps the A.1, A.2, A.3 and A.4 collectors plus the Defender, Azure and jump-box AD collectors, same output file names, or points at an existing evidence folder |
| `Import-PostureSamReport` | Imports SAM DAG CSVs (EEEU, sharing links, external, ownerless) and the Microsoft 365 Assessment tool output |
| `Invoke-PostureChecks` | Runs the catalog against the evidence folder, filtered and targeted by `-Baseline` and `-Profile`, honoring `exceptions.json`; outputs `checks.json` with pass, fail, not evaluated, not applicable, accepted risk, evidence refs |
| `Deploy-PostureAutomation` | Emits or applies the Bicep template for the customer-hosted runbook deployment (section 11); same module code runs inside the runbook |
| `New-PostureReport` | Renders Executive or Full template, HTML and Markdown; PDF via Edge or Chrome headless (`--print-to-pdf`), present on Mac, Windows and Linux; no wkhtmltopdf |
| `Compare-PostureRuns` | Trend against the previous `checks.json`: arrows, deltas, headline numbers over time |
| `Export-PostureFindings` | `findings.csv` in the Appendix E schema; re-imports owners and statuses on the next run |
| `Export-PostureCaSnapshot`, `New-PostureCaDocument`, `Compare-PostureCaSnapshot` | Section 5 |
| `Set-PostureBrand` | Writes or validates `brand.json` |
| `Get-PostureCheckCatalog` | Lists checks with IDs, licenses, sources; also published on kainor.com |

Collection and rendering are separate on purpose. At 20k users A.1 takes 20 to 40 minutes; render as many times as you like from one folder.

**Licensing and distribution (D22, decided: source-available, not open source).** The repository is public, like LAPSlock's: anyone can read every line, which is the trust story. The license is a short custom source-available license (model: the view-and-run licenses other PowerShell vendors use; one lawyer pass before the first release): read, audit and run under a valid license tier; private patches for your own use; no redistribution, no derivative works, no competing products, no circumventing the entitlement check. PolyForm Shield 1.0.0 is the standard alternative if a recognizable license matters more than the no-redistribution clause. Use is governed by a per-tenant EULA on top. Copyright is asserted on the catalog's text, logic and baseline mappings, which is the part worth protecting. Releases are Authenticode-signed. Distribution: the public PowerShell Gallery with the license URI set **(verify Gallery terms for non-open-source modules)**, plus signed zips from the website; the Marketplace template pulls the module into the customer's Automation account from the release URL **(verify the Automation module contentLink flow in Bicep)**. Issues are welcome; external pull requests are not accepted (a CLA would be needed; skip it for now). Verbatim copies on GitHub are a DMCA takedown, which GitHub processes in days. Be clear-eyed: a PowerShell module is readable by every customer anyway, so public source costs nothing in secrecy and buys the trust comparison; protection is the license and the catalog's copyright. The website line: source published, not open source; read every line, you can't fork it.

Hybrid AD, GPO, AD CS, ADFS and SCCM are the v1.1 domain (4.14). The collector is the only part of the product that must run on Windows; everything else is cross-platform.

---

## 7. Output: an interactive report, not a PDF

The deliverable is a self-contained HTML application. One file, no server, no CDN calls, works offline, opens in any browser, and holds the full results, the catalog text, the evidence excerpts and the previous runs for trend. PDF still exists, but it's the print view of the same file, produced on demand from the browser. Nobody builds a PDF pipeline.

### 7.1 Why one self-contained file

- **Fits the architecture.** No hosting required, so it works for the local run, the Automation deployment and the MSP folder alike. Nothing calls home from the page.
- **Survives strict environments.** Inline CSS and JS, no external fonts, no analytics, no remote images. It passes the content security policies of the people who'd buy it.
- **Portable.** Email filters often block `.html` attachments, so delivery is a link (7.4) or a `.zip`. Document that up front.
- **Size.** A 20k-user tenant with full evidence excerpts lands around 3 to 8 MB. Full evidence stays in the folder; the page embeds the affected-object lists per check, not every user record.

Stack: vanilla JS or an inlined micro-framework (Preact-sized), inline SVG charts, a print stylesheet, light and dark themes, keyboard navigable, WCAG AA. Embedded JSON blocks: `results`, `catalog` (titles, remediation, links, narratives for the checks in scope), `profile`, `exceptions`, `history` (prior runs' summary rows), `ca` (snapshot, document, diff).

### 7.2 Views

| View | What it shows |
|---|---|
| **Overview** | Posture grade with the method in one line, the six headline numbers, regressions since last run in red at the top, quick wins this week, Copilot readiness gate strip (green / amber / blocked) |
| **Domains** | One scorecard per domain in scope, status counts, narrative, trend arrows |
| **Checks explorer** | Every evaluated check in a table: domain, title, status, severity, license, framework tags, affected count. Filter, sort, free-text search. Status chips: pass, fail, partial, not evaluated, not applicable, accepted risk, covered by third party |
| **Check detail** (drawer) | Result and threshold, the affected objects (the 14 Global Admins, the 300-member exclusion group, the 212 sites with Everyone) with export to CSV, evidence file reference, **why it matters** (7.3), remediation steps, effort / user impact / license, links (7.3), portal deep link to the exact object where one exists, and a "record exception" button that emits the `exceptions.json` entry to paste |
| **Who are your admins** | Name, roles, permanent or eligible, strongest MFA method, last sign-in, synced from AD, mailbox. The one table every executive asks for |
| **External exposure** | Guests by domain and inviter, sharing links by domain, anonymous links, top 20 sites by external sharing, Teams federation state |
| **Copilot readiness** | The 18 gates as a checklist with the stopgap-vs-end-state explanation, what's blocking, and the order to fix it |
| **Conditional Access** | Policy pages, the matrix, health flags, and the change report since last run, with "changed by" from the audit log when available |
| **Recommendations** | All failed checks grouped by bucket (Stop the bleeding, Foundations, Program, Later). Copy a remediation plan, export to CSV, Jira or Azure DevOps work-item import format. Microsoft's Secure Score recommendations alongside with projected score gain per control |
| **Trend** | Headline numbers and domain scores across runs, regressions and improvements called out, catalog version noted per run so scores are comparable |
| **Licensing and value** | Unassigned licenses, licenses on disabled accounts, overlapping products (Duo next to Entra MFA, S1 next to MDE, Proofpoint next to MDO), E5 features paid for and unused, and the "requires P2 / E5" count from the catalog. Dollar figures when the profile has list prices. MSPs sell on this page |
| **Appendix** | Baseline, profile answers, exceptions with expiry, scopes used, API versions, collection times, evidence index, framework crosswalk, methodology |

**Executive mode** is a toggle, not a separate report: hides technical columns, evidence refs and API detail, keeps narratives, numbers and recommendations. Print from executive mode gives the 12-page board PDF; print from technical mode gives the full one.

### 7.3 Why it matters, and where to read more

Every check in the catalog carries three things the page renders in the detail drawer:

- **Risk narrative.** Two to four sentences, factual, no fear-mongering: what an attacker does with this gap, who it hits, how it's been used. Legacy auth open means password spray with no MFA prompt. User consent allowed means consent phishing lands a persistent OAuth app. No token protection means a stolen session cookie from an AiTM kit works from anywhere. Device code flow not blocked means a phishing link that signs the victim into the attacker's session. Oversharing plus Copilot means the intern can ask for the layoff list and get it. Each narrative tags the MITRE ATT&CK technique IDs **(verify attribution terms; the framework is openly licensed with attribution)** so a SOC can map it.
- **Severity with the reason.** Critical, High, Medium, Low, with one line on why it sits there and how the profile moved it (no P2 means no risk detections, so password-related gaps sit higher).
- **Links, three kinds.** The Microsoft Learn page for the setting; the best-practice guide (Microsoft's Zero Trust and deployment guides, Entra security operations guides, the relevant CIS section number, the Maester test page where one exists); and a **portal deep link** to the exact object (the CA policy, the app registration, the SharePoint site's sharing page) so "click the finding, land on the fix" works **(verify deep-link URL stability per portal; Entra and Intune have been reasonably stable, Purview less so)**.

Plus a one-line **"explain this to my boss"** per check for executive mode.

### 7.4 Delivery options

| How | When |
|---|---|
| Open the file locally | Local run, consultant engagements |
| `.zip` by email | When the client wants an attachment; `.html` alone gets blocked |
| **Report site** in the customer's subscription | Part of the Automation deployment (section 11): an Azure Static Web App with Entra sign-in, in their tenant, holding every run with an index page and trend. The URL is theirs; access is their Conditional Access. Nothing on Kainor's side |
| MSP portal | The MSP's own static index across clients, built locally from the client folders (section 10.5): clients ranked by grade, regressions this month, who's blocked for Copilot. Same self-contained HTML approach, hosted wherever the MSP hosts things |

### 7.5 Branding and white label

`brand.json`:

```json
{
  "preparedBy": { "name": "Example MSP", "logo": "./msp-logo.svg", "contact": "security@example-msp.com" },
  "client": { "name": "Contoso Ltd", "logo": "./contoso-logo.png" },
  "colors": { "primary": "#1F3A5F", "accent": "#E8A33D" },
  "font": "Inter, Helvetica, Arial, sans-serif",
  "confidentiality": "Confidential. Prepared for Contoso Ltd.",
  "footer": "Prepared by Example MSP",
  "caNamePattern": "^CA-\\d{3}-(Admins|Users|Guests|WorkloadIDs)-.+$"
}
```

Free tier: product branding, "Prepared with Posture" footer, Identity and CA domains only. Paid: white label, product branding removed entirely, all domains. Branding applies to the interactive page, the print view and the MSP portal index alike, from the one file.

---

## 8. Packaging and pricing options

Licensing mechanism: the LAPSlock entitlement function, keyed to the MSP's or org's tenant GUID. No license keys. The module checks once a month.

| Tier | Monthly | Annual (about two months free) | Includes |
|---|---|---|---|
| Free | $0 | $0 | Identity + CA domains, product branded, 1 tenant, CA doc and diff run locally. Free tier under the source-available license (D22) |
| Tenantkeep CA (entry SKU) | $9/mo | $89/yr | CA only: scheduled nightly snapshots and diff in the customer's tenant, drift alerts, white-label change reports, history, report site opt-in. 1 tenant |
| Pro (individual admin or consultant) | $19/mo | $199/yr | All domains, 1 tenant at a time, custom branding, trend |
| Organisation (internal team) | $49/mo | $499/yr | All domains, 1 tenant, white label, trend, scheduled CA diff, report site option |
| MSP | $99/mo | $999/yr | Unlimited client tenants, white label, Tenantkeep CA for every client, findings re-import, MSP portal index, priority support |

Both billing periods on every paid tier. MSPs tend to want monthly, internal teams want annual on a purchase order.

Reference points: CIPP's hosted option is $99/mo for an ops platform; a hand-built MSP posture assessment bills at $3k to $10k. An MSP that bills clients for a quarterly report recovers the annual fee on the first one. Don't price this like an app; price it like the deliverable.

Launch tactic: free MSP tier for the first ten MSPs who agree to a written quote and a logo on kainor.com. The sample report they produce is your marketing.

Naming, decided 2026-10-13: Kainor is the publisher only, not a product name. Family name **Tenantkeep** (a keep is the fortified tower where the keys are; "keep" is also what posture work does to a tenant), so this product is **Tenantkeep Posture**. Module name `Tenantkeep.Posture`, cmdlet noun prefix `Posture` (`Export-PostureCaSnapshot`). Checks passed on 2026-10-13: no software product, company, App Store app, GitHub repo or npm package found; tenantkeep.com and tenantkeep.app to be registered by Kainor. USPTO search still to do before the first public use. History: Tenantlock was the first pick and is a live competitor (tenantlock.com, Seattle solo developer); a purchase offer went $200 / $1,000 / $500 and stalled. Shiftlock is an existing App Store app. Realmlock was clean but meant nothing to the buyer. Microsoft trademarks (Entra, Graph, Intune) never appear in a product name.

---

## 9. MVP cut, driven by the first customer

Decisions moved Azure, Defender effective state and the Marketplace listing into v1, and added Hybrid. Your call: full v1 as listed, and you expect to beat twelve weeks with the runway before the job starts. The weeks below are a planning unit, not a commitment; the order is what matters, and every two-week checkpoint ships something usable.

| Weeks | Build | Why here |
|---|---|---|
| 1 to 2 | CA snapshot, document, diff (section 5). Start Partner Center enrollment the same week; verification takes weeks and runs in the background | Needed at work in week one; sellable alone; smallest surface |
| 3 to 4 | Check engine, baseline and profile loading, exceptions, Identity + Auth + CA scorecards from A.1 evidence, interactive HTML renderer, `brand.json`, `findings.csv` export, Entra portal deep links | Turns the audit's identity section into a report; first MSP tester gets a build |
| 5 to 6 | Devices, Endpoint security with Intune policy state and Defender hunting for effective state, Copilot readiness with the SAM import | The sections that sell |
| 7 to 8 | Azure hygiene, IAM and the Defender for Cloud passthrough; Collaboration and oversharing; Email security | Azure is small because Microsoft evaluates; Collaboration needs PnP proven |
| 9 to 10 | Purview, Governance, Operations; trend comparison; framework baselines first pass (10.6); print view and executive mode | Completes the Full template |
| 11 to 12 | Option B: Bicep, runbook wrapper, `createUiDefinition.json` with two plans (Conditional Access only, Full posture), Static Web App opt-in; Tenantkeep CA entitlement tier; Marketplace offer submission; sample report on the website | Ships the deployment story and the CA entry SKU with v1 |
| v1.1 | Hybrid domain (4.14): jump-box collector, imports, Hybrid Runbook Worker option; drift watch (12.1); MSP portal index; remaining baselines | Hybrid lines up with the audit plan's jump-box exports in weeks 3 to 5 of the job, so the first dataset exists before the code does |

One release every two weeks. Checkpoint after each: what shipped, what broke, what the tester said. If the job eats the schedule, ship weeks 1 to 8 as v1.0 and let B and the listing follow; the product is complete without them, just local-only.

---

## 10. Customization model: one catalog, every org gets its own report

The checks never change per customer. What changes is the four layers of data around them. This is how a 50-seat dental office and a 20k-user hybrid enterprise run the same module and get reports that each look written for them.

### 10.1 The four layers

| Layer | Owned by | What it holds | Example |
|---|---|---|---|
| **Check catalog** | The product, versioned | Every check: ID, domain, title, severity default, license required, evidence source, pass logic, remediation, Learn link, framework tags, applicability rule, threshold defaults | `CA-003 Phishing-resistant auth strength for admin roles` |
| **Baseline** | Ships with several (10.6); customers can author | Which check IDs are in scope, target values, severity overrides, section order | `copilot-readiness`, `standard`, `copilot-readiness`, and the framework baselines in 10.6 |
| **Org profile** (`profile.json`) | Customer or MSP, per tenant | Facts about the tenant and its risk appetite (10.2) | "BYOD: MAM only", "Third-party email gateway: Proofpoint", "Max permanent GA: 2" |
| **Exceptions** (`exceptions.json`) | Customer, per tenant | Accepted risk per check or per object, with justification, owner, approver, expiry | `CA-007 exclusion group over threshold: VPN-Legacy-Users, accepted until 2027-03-31, owner J. Smith` |

Two optional layers on top:

- **Custom checks folder.** Same JSON schema as the catalog, org-specific. "Our required CA policy set exists by name", "Our naming convention", "Our break-glass accounts are these two UPNs". Rendered inline with the standard checks, tagged as custom.
- **Narrative overrides.** A Markdown file per domain where the MSP writes its own paragraph, replaces remediation text with its house procedure, or adds a "what we did this quarter" block. Falls back to the generated narrative when absent.

### 10.2 What the profile captures

About 12 answers, collected by `New-PostureProfile` and stored as JSON. Licenses are read from the tenant and confirmed, not typed.

| Fact | Drives |
|---|---|
| Licenses present (E3, E5, Entra P2, Entra Suite, Intune Suite, SAM, Copilot, MDO P2, MDE P2) | "Not evaluated (requires X)" vs fail; the E5 business case count |
| Platforms in scope (Windows, macOS, Linux, iOS, Android) | Which device and endpoint checks appear at all |
| Identity model (cloud-only, hybrid with Entra Connect or Cloud Sync, ADFS still present) | Whether 4.14 renders; MDI checks; WHfB trust model targets. AD CS, SCCM and GPO presence are auto-detected by the collector |
| BYOD stance (none, MAM, MDM) | Mobile checks and targets |
| External collaboration stance (locked, guests with governance, open by policy) | Sharing and guest targets; a "locked" org fails on any guest, an "open" org passes with reviews in place |
| Copilot status (none, pilot, deployed) | Whether 4.7 renders, and whether C17 is a status or a red flag |
| Third-party controls in place (email gateway, EDR, MFA provider, MDM, SIEM, backup) | Checks render "Covered by <vendor>" instead of failing; migration plan date requested if the roadmap replaces the vendor |
| Regulated frameworks (none, HIPAA, PCI, CMMC, SOC 2, ISO 27001) | Framework crosswalk appendix and severity lifts on mapped checks |
| Thresholds (max permanent GA, stale device days, exclusion group max, inactive guest days, report-only max days, critical CVE max age) | Pass conditions, with product defaults shown next to the org's values |
| Audience (executive, technical, auditor) | Template and depth |
| Report cadence (one-off, monthly, quarterly) | Trend window and "what changed" scope |
| Named break-glass accounts | Exclusion checks know which accounts are supposed to be excluded |
| Azure footprint (none, platform only, workloads) | Whether 4.13 renders, and how much of it |

### 10.3 How a check consumes it

```json
{
  "id": "DEV-014",
  "domain": "Devices",
  "title": "FileVault enabled and recovery key escrowed",
  "severityDefault": "High",
  "license": ["Intune"],
  "applicableWhen": { "platforms": ["macOS"] },
  "coveredBy": ["mdm:jamf"],
  "thresholds": { "minEncryptedPercent": 100, "minEscrowedPercent": 100 },
  "evidence": ["09-intune-managed-devices", "encryption-report"],
  "pass": "encryptedPercent >= thresholds.minEncryptedPercent && escrowedPercent >= thresholds.minEscrowedPercent",
  "remediation": "Deploy a FileVault disk encryption policy with personal recovery key escrow to Entra and rotation after reveal. ...",
  "learn": "https://learn.microsoft.com/...",
  "frameworks": { "nist-csf-2": "PR.DS-01", "iso27001": "A.8.24", "cmmc": "SC.L2-3.13.16" }
}
```

A Windows-only profile never sees DEV-014. A Jamf shop sees it as "Covered by Jamf, verify escrow in Jamf" unless the roadmap says Jamf is leaving. An org that sets `minEscrowedPercent` to 98 for a known fleet of lab Macs passes at 98 and the appendix shows the override.

### 10.4 Framework crosswalk

Every check carries framework tags: CIS Microsoft 365 Benchmark section numbers, NIST CSF 2.0 subcategories, ISO 27001 Annex A controls, CMMC practice IDs. Regulated profiles get an appendix mapping checks to controls, which is what their auditor asks for. Reference numbers only; do not reproduce CIS benchmark text, their license doesn't allow it **(verify current CIS terms)**.

### 10.5 For MSPs

One folder per client: `brand.json`, `profile.json`, `exceptions.json`, `narrative/`, and the evidence runs. `New-PostureReport -Client ./clients/contoso` picks all of it up. Baselines live once at the MSP level, so a change to the MSP's house standard rolls to every client on the next run.

The appendix always prints the baseline name, the profile answers, and every exception with its expiry. The reader knows exactly what was and wasn't evaluated, and why. That transparency is what keeps "customizable" from becoming "we hid the failures."

### 10.6 Baselines shipped

A baseline is a check selection, targets, severity overrides and the framework crosswalk tags. The catalog is one; the mapping is the work, roughly a day or two per framework for a first pass and a review each time the catalog grows. Framework text is never reproduced, only control identifiers **(verify each publisher's terms; CIS in particular)**.

| Baseline | What it is | Ships |
|---|---|---|
| `standard` | Product default, Microsoft's own recommendations plus the catalog's defaults | v1 |
| `copilot-readiness` | Section 4.7 gates plus the sharing, labeling and governance checks that feed them | v1 |
| `nist-csf-2` | NIST Cybersecurity Framework 2.0 subcategories | v1 |
| `nist-800-171` / `cmmc-2` | Defense contractors; 800-171 practices and CMMC Level 2 | v1 |
| `cisa-scuba` | CISA Secure Cloud Business Applications baselines for M365; the federal civilian baseline, and what ScubaGear tests | v1 |
| `iso-27001-2022` | Annex A controls | v1 |
| `hipaa` | Security Rule administrative, physical and technical safeguards | v1 |
| `soc2-tsc` | Trust Services Criteria, Security plus Availability and Confidentiality | v1.1 |
| `pci-dss-4` | For tenants in scope; mostly identity, logging and endpoint controls | v1.1 |
| `essential-eight` | Australian Signals Directorate, maturity levels | v1.1 |
| `cyber-essentials` | UK NCSC | v1.1 |
| `nis2` | EU, mapped to the Article 21 measures | v1.1 |
| `msp-small-business` | Fewer checks, plainer targets, for the 50-seat clients | v1.1 |

"Government," decided 2026-10-13, means two baselines: `cisa-scuba` for federal civilian agencies and `nist-800-171` / `cmmc-2` for defense contractors. Both ship in v1. Tenants on GCC (Moderate) use the same worldwide endpoints as commercial tenants, so the collectors work there unchanged **(verify: GCC Moderate is on the commercial Entra and Graph endpoints; GCC High and DoD are on the US Government endpoints, graph.microsoft.us and login.microsoftonline.us)**. GCC High and DoD support is **not planned**: a separate endpoint set, separate module behaviours and a tiny market. Revisit only with a paying customer in hand.

---

## 11. Deployment: local, customer-hosted, or Kainor-hosted

You asked about cloud-based so orgs don't run anything locally. Here are the three ways to get there and why I'd pick the middle one.

| | A. Local run | B. Customer-hosted automation | C. Kainor-hosted SaaS |
|---|---|---|---|
| Where it runs | Admin's laptop (Mac, Windows, Linux) | Azure Automation runbook in the customer's subscription, deployed from a Kainor-published Bicep template | Kainor's cloud |
| How it authenticates | Delegated, as the signed-in admin | Managed identity with read-only Graph, Defender, Exchange and SharePoint app roles, consented by the customer in their own tenant to their own identity | Kainor multi-tenant app with standing app-only read in every customer tenant |
| Where the data lives | Local evidence folder | Customer's storage account | Kainor's database |
| What Kainor sees | Tenant GUID once a month | Tenant GUID once a month | Everything |
| Scheduling and alerts | launchd or Task Scheduler, manual | Built in: nightly CA diff with Teams or email alert, monthly or quarterly report delivered to a mailbox or SharePoint library | Built in |
| Mac gaps (SPO module, DAG reports) | Jump box or CSV import | Runbooks run on Windows sandboxes, so the SPO module and `Get-SPODataAccessGovernanceInsight` may run there unattended **(verify module support in Automation PS 7.x Windows runtime)** | n/a |
| Cost to customer | $0 | A few dollars a month of Automation and storage | Subscription |
| Fits "no Kainor server, delegated only, your controls rule" | Yes | Yes. The identity is theirs, consented by them, auditable by them | No |
| What it takes from you | The module | The module plus one Bicep template, a runbook wrapper, and a docs page | A multi-tenant app, data storage, encryption, SOC 2, breach liability, a support queue, and a second person |

**Why not C, at least now.** A hosted service is a multi-tenant app holding standing app-only read access to identity, device, email and sharing configuration across every customer. That's the exact thing LAPSlock's security page says Kainor won't do, it's what the security reviewer at any mid-size org rejects on sight, and it makes a one-person company a breach target worth attacking. It also puts you in CIPP's and CoreView's category, where you'd compete on hosting and features instead of on the deliverable. Revisit if 20 MSPs ask for it in writing and there's a second employee.

**Why B is the answer to your question.** Nobody runs anything on a laptop. The customer clicks Deploy to Azure, consents once to a managed identity in their own tenant, and the reports arrive on a schedule. The nightly CA diff turns a point-in-time report into monitored posture, which is the thing MSPs actually sell. And because the identity is the customer's, your entire trust story survives unchanged.

**MSP variant of B.** One deployment in the MSP's own tenant, running a multi-tenant app registration the MSP owns and consents into each client tenant through GDAP **(verify app-only permissions over GDAP for every API involved; Defender and SharePoint are the likely gaps)**. Fallback: one small deployment per client, which is also cleaner for client offboarding.

**Hosted viewer, maybe later.** If customers want a web page instead of a PDF, the runbook can push the finished HTML to a Kainor-hosted viewer with no tenant access. That's still customer security findings on your servers. Opt-in, encrypted, and not before v3.

Decision: A and B both ship in v1, with B listed on Azure Marketplace from day one (11.1). C is not planned. Hybrid (4.14) settles it: on-prem collection needs code inside the customer's network, a hosted service would need an agent of ours there, and agents are out. If a hosted tier ever happens it would be cloud-only, and the hybrid domain would stay on A and B.

**Two plans in the wizard.** "Conditional Access only" deploys the Tenantkeep CA runbook (5.5); "Full posture" deploys the whole collection. Same template, same identity, same storage; the plan sets the schedule and which collectors run.

**Report site, opt-in.** The default deliverable is the local HTML file. The Marketplace wizard offers "Build a report site" as a checkbox. When ticked, the template adds an Azure Static Web App in the customer's subscription, with Entra sign-in, holding every run and the trend. The customer pays for it, not Kainor. Two plan notes to verify at build: the Free SWA plan supports built-in Entra sign-in and invitation-based access for up to 25 named users, which is enough for a report audience; restricting sign-in to the customer's own tenant through custom authentication needs the Standard plan, about $9 a month **(verify current SWA plan features and pricing)**. Default to Free with invitations; document the Standard upgrade for larger audiences.

**Hybrid Runbook Worker, opt-in.** For customers on B who want the hybrid domain on the monthly run, the wizard offers a second checkbox that enables a Hybrid Worker group and prints the install steps for a server they own (4.14).

### 11.1 Listing the template on Azure Marketplace

Yes, and it's the right offer type. Checked against Microsoft's publishing docs on 2026-10-10:

- **Offer type: Azure Application, solution template plan.** It deploys an ARM template into the customer's own subscription, which is exactly option B. Solution template plans are not transactable through Marketplace, which is fine: the template is free, the module's license check stays with the existing Stripe and entitlement flow.
- **What you ship:** `mainTemplate.json` (compile the Bicep to ARM) and `createUiDefinition.json` for the portal wizard (tenant name, schedule, report recipients, which domains). Run it through the ARM template test toolkit before submission. Customer usage attribution is required on every solution template, which is a GUID in the template so Microsoft can attribute Azure consumption to the partner. It gives Kainor no access to anything.
- **Account:** a Partner Center commercial marketplace account with business verification. Budget a few weeks for verification and certification the first time.
- **What you get:** a listing in the Azure portal's Create a resource search and on the Marketplace site, a Get It Now button, and leads routed to Partner Center referrals. That's a distribution channel you don't have today, in front of exactly the admins who'd deploy this.
- **Managed application plans** are the transactable kind, but they mean the publisher manages resources inside the customer's subscription. That contradicts the brand, so skip them. Some current docs describe solution template as the only remaining plan kind **(verify at submission; the docs disagree with each other)**.
- **Microsoft Security Store** is a separate storefront and this template doesn't qualify: it takes transactable SaaS, Security Copilot agents, Sentinel connectors, or a MISA-approved API integration, and Entra SSO alone doesn't count. Revisit if there's ever a hosted tier.

Timing: decided, from day one. Start Partner Center enrollment in week 1 (section 9) because business verification runs for weeks in the background, and submit the offer when B is ready at the end of v1. The same `mainTemplate.json` goes on GitHub behind a Deploy to Azure button for people who can't use Marketplace (some CSP-resold subscriptions, and Azure Government **(verify Marketplace availability in Azure Government)**). One template, two front doors.

---

## 12. Feature backlog: what makes it the end-all

Everything below is real demand I'd expect from MSPs and internal teams. None of it is v1. Ranked roughly by value per effort.

### 12.1 Drift watch (Automation deployment)

The nightly run already snapshots CA. Extend it to the dozen changes that matter in a tenant without a SIEM, from audit log plus config snapshots: new permanent Global Admin or equivalent (Privileged Role, Privileged Authentication, Partner Tier2), break-glass sign-in, Security Defaults toggled, audit log disabled, admin consent granted or a new app with high-privilege permissions, domain federation change, DKIM disabled, new inbound connector or transport rule, new external forwarding rule, named location added, authentication methods policy change, Intune enrollment restriction change, SharePoint sharing setting change. Teams or email alert with the audit record and who did it. Say plainly it isn't a SIEM; it's the fifteen alerts a small org needs and a big org wants as a backstop.

### 12.2 Checks to add to the catalog

- **Conditional Access**: device code flow and authentication transfer blocked (authentication flows condition); MFA for Azure management and admin portals; workload identity policies; guest and external user policies; Continuous Access Evaluation state; compliant network when GSA is present.
- **Tenant settings**: users can register applications; restrict non-admin access to the Entra admin center; restrict tenant creation; guest invite restrictions and guest access level; tenant restrictions v2; cross-tenant sync configuration; SSPR scope and admin SSPR.
- **Hybrid**: password hash sync on even with PTA or federation (for leaked credential detection); PTA agent count of three or more; seamless SSO key rotation age; Entra Connect version age; staging server present; Connect server treated as Tier 0. Optional import of PingCastle or Purple Knight scores for on-prem AD.
- **Exchange**: mailbox audit bypass associations; OWA attachment policy on unmanaged devices; legacy EAS devices; shared mailbox licensing.
- **Teams and OneDrive**: third-party cloud storage in Teams; meeting recording and transcription policies; Known Folder Move enforced; sync client tenant restriction; departed-user OneDrive retention.
- **Intune**: Autopilot deployment profiles and ESP; enrollment status page; Windows 365 posture if present; device cleanup rule age.
- **Purview**: Communication Compliance, Information Barriers, Records Management state; eDiscovery holds vs retention policies for conflicts.
- **Licensing**: unassigned, on disabled users, overlapping SKUs, trial expiries, group-based vs direct.
- **Copilot**: licensed vs active users, agents and Copilot Studio governance, Graph connectors.

### 12.3 Evidence packs for auditors

Per finding or per domain, a `.zip` with the CSV and JSON evidence, the check definition, the timestamp, and a SHA-256 manifest. Auditors stop asking for screenshots.

### 12.4 Remediation handoff

Export the recommendations as Jira CSV, Azure DevOps work-item CSV, or Planner-importable format, with owner, due date and bucket. Owners and statuses round-trip through `findings.csv` so the next run shows progress, not just state.

### 12.5 Fix snippets

Each check can carry a read-only-safe PowerShell snippet that shows how the fix is done, clearly labelled as a starting point, never executed by the tool. The product stays read-only. The snippet saves the engineer the search.

### 12.6 MSP portal index

A static index built from all client folders: clients ranked by grade, regressions this month, Copilot-blocked clients, exceptions expiring, licenses wasted in dollars. Same one-file approach, hosted wherever the MSP hosts things.

### 12.7 Catalog versioning and re-scoring

Each run records the catalog version. When the catalog changes, old runs can be re-scored against the new catalog from their evidence so trend lines stay comparable. Without this, every catalog update looks like a posture change.

### 12.8 Intune configuration compare against a golden tenant

For MSPs: compare a client tenant's Intune policies (settings catalog, compliance, endpoint security, CA) against the MSP's reference tenant or a saved baseline export, setting by setting, with drift listed. TenantLock offers tenant-to-tenant compare today; ours adds the time axis (client vs its own last run) and the baseline axis (client vs the MSP standard) from the same evidence. Fits "checks are data." After the MSP portal index.

### 12.9 Deliberately not doing

- **Cross-customer benchmarks** ("orgs your size score X"). Needs data on Kainor's side. No.
- **Auto-remediation.** The tool is read-only. That's the whole trust story.
- **A hosted viewer** before v3 (section 11).

---

## 13. Risks, pushback, open questions

- **First customer IP: resolved.** Agreement in place; the product is Kainor's property and the first customer uses it under license. Two habits still worth keeping: never use a customer's evidence or screenshots in demos or marketing, and keep the Kainor repo off customer-owned machines so there's no argument later about where code was written.
- **Public source.** Someone will read the module and some will copy checks. The license, the catalog's copyright, GitHub DMCA takedowns for verbatim copies and the pace of the catalog are the defence; litigation beyond that is probably never worth it. Do not spend engineering time on obfuscation. The real risk of a public repo is a careless commit: real tenant evidence, a secret, a customer's data. Pre-commit scanning and an anonymized-only samples folder are mandatory from the first commit.
- **Maester overlap.** If Maester adds SharePoint and Copilot checks, the delta narrows to deliverable quality, governance, CA diff and trend. Still real, but check its roadmap before deciding how much of the engine to build versus wrap **(verify)**.
- **No API for DAG reports.** As far as I know the SAM data access governance reports are portal or SPO-module only, and the SPO module is Windows-only. The Copilot section therefore depends on an admin exporting CSVs or a jump box run. Document the steps; accept the friction **(verify, this may have changed)**.
- **PnP app registration per tenant.** Friction for MSPs. A documented consent URL and a one-time script reduce it; it doesn't go away.
- **Explainable scoring.** An MSP will be asked "why a C." Every score must trace to listed checks with weights shown in the appendix. Do not fold Secure Score into the overall grade; show it as its own number.
- **Beta endpoints.** Pin API versions per check, log them in the appendix, and expect breakage. Governance endpoints in particular move.
- **Advisory, not certification.** Footer and appendix state the report is a point-in-time technical assessment, not a compliance attestation. Keep the lawyer happy before the first MSP puts it in front of a client's auditor.
- **Scale.** A 20k-user tenant is the first customer. Design for it: paging, resumable collection, no in-memory joins on the full user list without need.
- **Public check catalog.** Publish it. Buyers want to see the list before they pay, and it ranks for "Copilot readiness checklist."

---

## 14. Decisions log

Resolved 2026-10-10 unless marked open.

| # | Decision | Outcome |
|---|---|---|
| D1 | Product name | **Tenantkeep Posture**, decided 2026-10-13 (section 8). Register tenantkeep.com and .app; USPTO search before first public use |
| D2 | Pricing model | Both monthly and annual, annual about two months free |
| D3 | Free tier scope | Identity + CA, including CA doc and diff |
| D4 | PDF engine | Headless Edge or Chrome, print view of the HTML |
| D5 | Maester as input | Optional import, never a dependency |
| D6 | CA diff standalone | Decided 2026-10-13: yes, as **Tenantkeep CA** (5.5). Open CLI free; the scheduled, alerting, white-label version is a $9/mo entry SKU shipped with option B in weeks 11 to 12 |
| D7 | Domain order after CA | Identity first |
| D8 | Hybrid | In, as section 4.14. Jump-box collector, Hybrid Runbook Worker option, imports. v1.1 |
| D9 | First customer agreement | Done; product is Kainor's property, customer benefits under license |
| D10 | Deployment path | A and B in v1. No hosted SaaS; hybrid plus no-agent rules it out |
| D11 | Baselines | Section 10.6: standard, Copilot readiness, CIS, NIST CSF 2.0, 800-171 / CMMC, CISA SCuBA, ISO 27001, HIPAA in v1; SOC 2, PCI, Essential Eight, Cyber Essentials, NIS2, small-business in v1.1. Government = SCuBA and CMMC, decided 2026-10-13. GCC High not planned |
| D12 | Defender in v1 | Yes: Intune policy state and hunting for effective state |
| D13 | Secure Score remediation text | Render it, verify terms first |
| D14 | Exceptions expiry default | 180 days, warning 30 days before |
| D15 | Primary output | Interactive HTML, print view for PDF |
| D16 | Report site | Local HTML is the deliverable; Static Web App is an opt-in checkbox in the template, in the customer's tenant, at the customer's cost |
| D17 | Marketplace listing | From day one; enrollment starts week 1, offer submitted with v1 |
| D18 | Drift watch | The fifteen in 12.1, after B ships |
| D19 | Portal deep links | Yes |
| D20 | Azure domain timing | v1 |
| D21 | Azure scope | Hygiene, IAM, Defender for Cloud passthrough; attack paths only with Defender CSPM |
| D22 | Licensing | **Source-available, decided 2026-10-13.** Public repo (the LAPSlock model), custom source-available license (PolyForm Shield as the standard fallback), per-tenant EULA, copyright on the catalog, signed releases, PowerShell Gallery with license URI, no external PRs. Section 6 has the detail |
