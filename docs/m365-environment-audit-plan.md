# Microsoft Environment Audit Plan (Initial Current-State Assessment)

| | |
|---|---|
| Owner | Connor Johnson |
| Scope | ~20k users, hybrid AD, M365 E3 today. Endpoints: Windows, macOS, and Ubuntu Linux (Linux mostly developers) |
| Version | v0.3 draft, 2026-10-09 |
| Status | Pre-engagement |
| Platform priority | Windows and macOS first (multi-year). Linux after, with a small minimum baseline that does not wait (section 6.11) |

Purpose: produce a current-state baseline, a risk register, and a dependency-ordered roadmap v1 for the modernization program (SCCM to Intune, Entra Join, passwordless, [MFA vendor]/[DNS filter]/[mail gateway]/[EDR vendor] exits, E3 to E5, Purview, Copilot hardening, Entra ID Governance, GSA or alternative SSE, SSO/SCIM, cross-platform privilege management).

Changelog: v0.2 adds macOS and Linux endpoint coverage, a cross-platform privilege management / application control workstream (ThreatLocker evaluation), and a rewritten [DNS filter]-exit section (section 6.4) with verified platform support facts. v0.3 adds section 6.11 (Linux root for developers: priority, decisions L1 to L6, options ladder) and the Microsoft SSO for Linux GA facts; roadmap re-phased so Linux follows Windows/Mac.

Incumbent products are written as role placeholders in square brackets, such as [MFA vendor] or [DNS filter], for publication; candidate products are named.

Anything marked **(verify)** is something I'm not certain about as of this writing. Check it against current Microsoft docs or the account team before relying on it.

---

## 0. Ground rules for the audit

- **Read-only.** The audit changes nothing. The only exceptions are "stop the bleeding" items (section 5) and each one goes through their change process, even if that process is bad. You're spending trust capital in the first 60 days; don't spend it on cowboy fixes.
- **Evidence for every finding.** Exports, screenshots, or report PDFs into a dated evidence folder. The scripts in Appendix A write to `~/audit/evidence/<timestamp>/`. The tracker (Appendix E) links each finding to its evidence.
- **Scale tax.** Things that took an afternoon at a few hundred users take weeks at 20k: Graph pulls, stakeholder discovery, app inventories, GPO sprawl. Budget 6 to 8 weeks elapsed, part-time while you onboard. Compress if you get help.
- **Map every finding to a workstream.** The audit exists to size and sequence the program, not to produce a 200-item list nobody reads. Section 1 is the map.
- **Separate "what's broken" from "what's missing."** Broken = risk now (admins without MFA, SCL -1 bypass rules). Missing = program work (no labels, no Autopilot). They go to different audiences.
- **Checkpoint weekly.** One-page Friday status to the sponsor: what was reviewed, top new findings, decisions needed, next week. Findings log grows continuously; don't batch to the end.

---

## 1. Target program and what the audit must size

| # | Workstream | Target state | Unblocked by |
|---|---|---|---|
| W1 | Licensing | E3 to E5 (plus Entra Suite, Intune Suite, Copilot, SAM as needed) | Business case from this audit; EA anniversary timing |
| W2 | Authentication | [MFA vendor] out, Microsoft Authenticator in; passwordless (Authenticator passkeys, FIDO2 keys, WHfB cloud Kerberos trust); SSPR decision | Authenticator rollout; Entra Kerberos object; DC patch levels |
| W3 | Conditional Access | Phishing-resistant auth strengths, token protection, risk-based policies, compliant device, compliant network | Entra ID P2 (E5); Intune compliance; GSA for compliant network |
| W4 | Endpoints (Windows, macOS, Linux) | Windows: SCCM to Intune, Autopilot, Entra Join for new/refresh, GPO rationalization, Win11. macOS: single management plane (Intune or Jamf + compliance connector), ADE enrollment, Platform SSO. Linux: enrolled and compliant where possible, MDE/EDR everywhere, defined sudo and encryption baseline | Intune; co-management; Cloud PKI or NDES; on-prem dependency cleanup; Mac/Linux tooling decision |
| W5 | Mobile | Intune MDM for corporate, MDM or MAM for BYOD (decision) | Intune; HR/Legal decision |
| W6 | Network edge | [DNS filter] out (no incumbent network vendor); SWG/DNS filtering and ZTNA that cover Windows, macOS, and Linux; VPN retired; compliant-network CA where the chosen stack supports it | Licensing (Entra Suite or SSE vendor); feature-gap analysis; decision in 6.4 |
| W7 | Endpoint security | [EDR vendor] to Defender for Endpoint (maybe) | E5 (MDE P2); contract dates; SOC readiness |
| W8 | Email security | [mail gateway] to Defender for Office 365 P2 | E5; MX/connector plan; archive/encryption/awareness replacements |
| W9 | Data protection | Purview: sensitivity labels, DLP, retention, Insider Risk, audit retention | E5; Legal/Records input |
| W10 | Copilot hardening | Oversharing cleanup, SAM (RAC/RCD), DSPM for AI, labels inherited | W9; SAM/Copilot licensing |
| W11 | Governance | Entra ID Governance: HR-driven lifecycle, access packages, access reviews, PIM for groups; SSO/SCIM consolidation | P2 + Entra ID Governance or Entra Suite; HRIS integration |
| W12 | Operations | Sentinel/SIEM, logging retention, M365 backup, cert/token expiry monitoring, documentation | E5 Sentinel benefit; staffing |
| W13 | Privilege management and application control | Approval-based admin elevation on Windows, macOS, and Linux from one console; decide whether default-deny application allowlisting is a control they want (ThreatLocker evaluation, section 3.12 and 6.10). Windows/Mac first; Linux elevation decision deferred to the Linux phase per 6.11, with the Tier 0 Linux baseline shipped early | W4 inventory of local admin and sudo usage; vendor eval; budget; decisions L1 to L6 |

Dependency chain that will drive the roadmap: **W1 licensing** unlocks almost everything. **W2/W3 identity** before **W4/W5 devices** (compliance signals feed CA). **W9 data** before **W10 Copilot**. **W6** before compliant-network CA (and the W6 vendor choice is coupled to the Linux ZTNA answer in W13). **W11** runs throughout once P2/Governance is licensed.

---

## 2. Week 0: before you touch anything

### 2.1 Access to request (all read-only)

| Surface | Role | Notes |
|---|---|---|
| Entra, Intune, SPO admin, Teams admin | Global Reader | Covers Intune and SPO admin center reads too |
| Defender XDR | Security Reader | Secure Score, incidents, MDE/MDO/MDI/MDA config |
| Purview | Compliance Administrator, or a custom role group of View-Only roles | Global Reader coverage inside Purview is patchy |
| Exchange Online | View-Only Organization Management | |
| Entra reports | Reports Reader | Usage reports |
| Azure | Reader at management group or relevant subscriptions | Sentinel, Log Analytics, Entra Connect Health, Arc |
| On-prem AD | Read-only domain account + a domain-joined jump box or PAW | AD, GPO, SCCM, ADFS, Entra Connect modules are Windows-only (Appendix B) |
| SCCM | Read-only Analyst | |
| Third parties | Read-only in [MFA vendor], [DNS filter], [EDR vendor], [mail gateway], HRIS (or an extract), existing SIEM, VPN | |
| Mac / Linux management | Read-only in Jamf (or whatever manages Macs), Landscape / Ansible / Puppet / Salt if any, developer platform (GitHub/GitLab org settings), secrets manager | Often nobody owns Linux laptops centrally; find out who does |

- Ask for PIM-eligible assignments if PIM exists. If they hand you permanent Global Admin on day one, write it down as finding #1.
- Confirm there is a documented break-glass account process before you log in with anything privileged. If there isn't one, that's finding #2 and a stop-the-bleeding candidate.

### 2.2 Tooling on the Mac

```powershell
# Shell
# brew install --cask powershell

# Graph: install submodules, not the Microsoft.Graph meta-module (saves ~20 minutes and a lot of RAM)
$mods = 'Microsoft.Graph.Authentication','Microsoft.Graph.Identity.SignIns','Microsoft.Graph.Identity.DirectoryManagement',
        'Microsoft.Graph.Identity.Governance','Microsoft.Graph.Users','Microsoft.Graph.Groups','Microsoft.Graph.Applications',
        'Microsoft.Graph.DeviceManagement','Microsoft.Graph.DeviceManagement.Enrollment','Microsoft.Graph.Devices.CorporateManagement',
        'Microsoft.Graph.Reports','Microsoft.Graph.Beta.DeviceManagement',
        'Microsoft.Entra','ExchangeOnlineManagement','PnP.PowerShell','MicrosoftTeams','Maester','ZeroTrustAssessment'
$mods | ForEach-Object { Install-Module $_ -Scope CurrentUser -Force -AllowClobber }
```

Mac gaps to plan around:

- `ActiveDirectory`, `GroupPolicy`, `ConfigurationManager`, `ADSync`, `ADFS`, and `Microsoft.Online.SharePoint.PowerShell` are Windows-only. Use the jump box (Appendix B). PnP.PowerShell covers the SPO tenant reads cross-platform.
- `Resolve-DnsName` is Windows-only. Use `dig` (the Appendix A.2 script does).
- `Connect-IPPSSession` (Purview) works cross-platform in ExchangeOnlineManagement 3.x REST mode in my experience **(verify on their tenant; fall back to the jump box)**.
- MicrosoftTeams module runs on PS7 on macOS in recent versions **(verify)**.
- PnP.PowerShell 2.x/3.x needs your own Entra app registration for interactive login (`Register-PnPEntraIDAppForInteractiveLogin`). That needs someone with Application Administrator or consent rights. Request it in week 0.

Run early, they're free baselines:

- **Maester** (`Install-MaesterTests`, `Connect-Maester`, `Invoke-Maester`): Pester-based Entra/Intune/EXO security tests incl. EIDSCA. Gives you a pass/fail HTML report to use as the before/after metric.
- **Microsoft Zero Trust Assessment** module: scored assessment across identity/devices/data. Cmdlet names per the module README **(verify current cmdlets)**.
- Secure Score, Identity Secure Score, Compliance Manager, and (post-E5) Exposure Management: screenshot day-one values.

### 2.3 Documents to collect

- Architecture: AD forest/domain/site topology, network diagrams, identity flow diagram (Entra Connect, ADFS, [MFA vendor], VPN), mail flow diagram.
- **Contracts and renewal dates** (Appendix D): Microsoft EA (anniversary and true-up date matter most), [MFA vendor], [DNS filter], [EDR vendor], [mail gateway], VPN, SIEM, PAM, backup, cert vendor, separate MDM if any, Jamf. These dates drive the roadmap sequence more than anything technical will.
- Licensing: current SKU counts, assignment method, add-ons, trials, Unified/Premier support entitlement, FastTrack status (20k seats qualifies; use them for the migrations, and ask the account team about funded security/Zero Trust workshops).
- Policies: acceptable use, BYOD, data classification, retention schedule (Legal/Records), security policy, change management, privacy notices for device management.
- Org chart for IT and Security, who owns what today, on-call, support model, helpdesk ticket categories with monthly volumes (password resets, MFA, device, access requests).
- Prior pen tests, audits, cyber insurance questionnaire (tells you what the board was already promised), recent incidents.

### 2.4 Stakeholder interviews (weeks 1 to 3, question bank in Appendix C)

Sponsor/IT leadership, Identity/AD team, Endpoint/SCCM team, Network team, Security/SOC (or MDR vendor), Messaging, Collaboration/SharePoint, Helpdesk lead, HRIS owner, Legal/Privacy/Records, Mac admins, top-20 app owners, OT/plant/frontline if applicable.

---

## 3. Audit workstreams

Each section: what to collect, how, questions to answer, red flags. Appendix A scripts cover most of the "how" for cloud surfaces.

### 3.1 Tenant and licensing baseline (W1)

**Collect**

- Tenant ID, region/data location, verified domains, federated vs managed domains.
- SKUs purchased vs consumed, add-ons, expired trials, assignment method (group-based vs direct).
- E5-tier features already in use via trials or standalone SKUs.
- Secure Score, Identity Secure Score, Compliance Manager score, Maester pass rate.
- Tenant-level settings: Security Defaults state, Microsoft-managed CA policies state, user settings (app registrations, consent, guest invites), external collaboration settings.

**Questions**

- Where are they paying twice? ([MFA vendor] on top of P1 MFA; [EDR vendor] on top of future MDE; [mail gateway] on top of EOP; separate SIEM vs Sentinel benefit.)
- When is the EA anniversary? That's your E5 decision deadline.
- How much is direct-assigned? Direct assignment at 20k = manual ops and license leakage.

**Red flags**

- Security Defaults on alongside CA (can't be both; means someone's confused).
- Licenses on disabled accounts, service accounts with E3.
- No group-based licensing.

### 3.2 Entra ID posture (W2, W3)

**Collect**

- Privileged roles: all assignments, permanent vs eligible, Global Admin count (target 2 to 5 including break-glass), admins synced from on-prem (should be cloud-only), admins with mailboxes/licenses, service principals in roles, PIM settings (MFA on activation, approval, max duration, alerts).
- Break-glass: exist, excluded from CA, cloud-only, monitored with alerts, credentials stored and tested.
- Conditional Access: full export. Look for report-only pileup, exclusion groups with hundreds of members, trusted-location MFA bypass, legacy auth block, device compliance requirements, sign-in frequency, auth strengths in use, token protection, Microsoft-managed policies.
- Authentication methods policy: SMS/voice still enabled, Authenticator settings (number matching, app context, geo), FIDO2/passkey settings (Authenticator passkeys enabled, key restrictions, passkey profiles), TAP, certificate-based auth, legacy MFA/SSPR policy migration state (should be "Migration complete").
- Registration: MFA registered %, passwordless-capable %, SSPR registered %, default method distribution, admins without a phishing-resistant method.
- Identity Protection: on E3/P1 you only get limited risk visibility. Note what's there; risky users/sign-ins policies become a day-one E5 item.
- Legacy auth: sign-in volume by client app (last 30 days). Entra workbook "Sign-ins using legacy authentication" is easier than Graph for this at 20k.
- Apps: app registration count, expired/expiring credentials, multi-tenant apps, high-privilege Graph application permissions (Directory.ReadWrite.All, Mail.ReadWrite, RoleManagement.ReadWrite.Directory, etc.), user consent setting, admin consent workflow, unused service principals, SAML signing certs expiring.
- Guests: count, inactive >90 days, inviter distribution, cross-tenant access defaults, B2B direct connect.
- Groups: dynamic vs assigned vs synced, M365 group creation restriction, expiration policy, naming policy, self-service.
- Entra devices: trust type breakdown (Entra joined / hybrid joined / registered), stale >90 days, BitLocker keys escrowed, device settings (who can join, local admin on join, MFA to join).
- Logs: sign-in/audit retention (30 days default on P1/P2), diagnostic settings to Log Analytics/Sentinel/storage, Entra Connect Health.

**Red flags**

- More than 10 Global Admins, synced admins, no break-glass, no PIM.
- Trusted-IP MFA bypass tied to office/VPN egress.
- SMS enabled broadly, per-user MFA still enforced on users.
- User consent = allow all.
- Legacy auth not blocked.
- 30-day log retention only, nothing shipped to a SIEM.

### 3.3 Hybrid identity and AD (W2, W4)

**Collect**

- Sync engine: Entra Connect Sync vs Cloud Sync, build (Microsoft blocks old builds; check auto-upgrade state), server OS, staging server, OU/attribute filtering, custom sync rules, sourceAnchor, sync interval and errors.
- Authentication: PHS vs PTA vs ADFS. Is PHS enabled alongside PTA/ADFS (needed for leaked-credential detection)? Seamless SSO configured?
- Writeback: password writeback (SSPR dependency), device writeback, group writeback method (Connect v1 writeback vs Cloud Sync group provisioning to AD; group writeback v2 was retired **(verify)**).
- Cloud Kerberos trust readiness: `AzureADKerberos` computer object present? DCs on 2016+ and patched? This is the prerequisite for WHfB cloud Kerberos trust and FIDO2/passkey SSO to on-prem resources.
- AD health: forest/domain functional levels, DC count and OS versions, FSMO, replication, DNS, time sync, tiering model, Domain/Enterprise/Schema Admins membership, Protected Users usage, krbtgt last rotation, RC4 allowed (msDS-SupportedEncryptionTypes), unconstrained delegation, kerberoastable service accounts (SPNs on user accounts), LAPS (legacy vs Windows LAPS), fine-grained password policies, Entra Password Protection agents, ADCS (templates, ESC1-8 exposure, who issues device certs, NDES), GPO count and linkage, stale users/computers, Exchange on-prem hybrid server still present, print and file servers.
- Tools: PingCastle, Purple Knight (Windows jump box). Defender for Identity ISPM posture reports if MDI exists (it probably doesn't on E3).

**Questions**

- What still needs AD? File/print, LDAP-bound apps, Kerberos/NTLM-only apps, 802.1X with machine certs, GPO-only configs, service accounts, SCCM. This list decides how far Entra Join can go and how fast.

**Red flags**

- ADFS still in play (count relying parties; it's a decom project).
- DCs older than 2016. RC4 permitted. No tiering. krbtgt never rotated.
- Entra Connect server treated as Tier 2 (it's Tier 0). PTA agents on random servers.
- No staging server for Entra Connect.

### 3.4 Authentication today: [MFA vendor], Authenticator, SSPR, passwordless readiness (W2)

**Collect**

- **[MFA vendor], every integration** (Admin console > Applications): VPN/RADIUS, Windows Logon/RDP, LDAP proxy, SSH/PAM, [MFA vendor] SSO (is [MFA vendor] the IdP for any SaaS?), Access Gateway, Device Health/trust policies, hardware tokens, bypass code usage, enrolled user count, policies per app.
- Entra MFA: Authenticator registered %, legacy per-user MFA states, legacy trusted IPs setting, OATH tokens, "remember MFA" days.
- SSPR: enabled scope, methods, number of methods required, writeback on, registration enforcement, admin SSPR policy, monthly password reset ticket volume, current reset process and how the helpdesk verifies identity.
- Passwordless readiness: Windows 11 share, TPM 2.0 coverage, WHfB deployed (which trust model), FIDO2 keys in use, Authenticator passkeys enabled, TAP enabled, Platform SSO for macOS state, shared/kiosk/frontline populations (their passwordless story differs), Verified ID or other helpdesk verification.

**Red flags**

- [MFA vendor] protects RDP/Windows logon (the replacement is WHfB, not Authenticator).
- [MFA vendor] SSO is an IdP for apps (that's an SSO migration, not an MFA swap).
- SMS default, per-user MFA enforced, SSPR security questions enabled.
- Helpdesk resets passwords on caller ID alone.

See section 6.1 for the SSPR vs passkeys decision framing.

### 3.5 Endpoints: SCCM, Intune, Windows, macOS, Linux (W4)

**Collect**

- **SCCM**: current branch version and patch state (there have been real CVEs), hierarchy (CAS? primaries, DP count), client count and health %, co-management enabled and which workloads moved, tenant attach, CMG, what SCCM is used for (OSD, apps, patching/SUP, compliance settings, inventory, reporting), task sequences, application/package count (= packaging backlog), collection count, admin count, server OS/SQL versions, infra cost.
- **Intune**: enrolled devices by platform and join type, Autopilot profiles and registered devices, enrollment restrictions, compliance policies and compliance %, config profile mix (settings catalog vs templates vs OMA-URI), update rings / Autopatch, Win32 app count, endpoint security policies (AV, EDR, ASR, BitLocker, firewall), RBAC/scope tags, Intune Suite features licensed (EPM, Remote Help, Cloud PKI, Advanced Analytics, Enterprise App Management), device cleanup rules, connectors and their expiry (Apple push cert, VPP/ABM tokens, Managed Google Play, MDE connector).
- **Fleet**: device count, OS distribution, hardware age and refresh cycle (drives the Entra Join timeline), TPM 2.0 and Win11-eligible %, Mac count and how they're managed (Jamf, Intune, nothing), Linux, kiosks/shared, VDI (AVD/Citrix/W365), servers managed by SCCM (Intune doesn't do servers; they need Arc/Azure Update Manager or stay on SCCM).
- **Windows 10**: EOL was Oct 14, 2025. ESU year 1 ends mid-October 2026, which is now. Confirm ESU year 2 coverage for anything still on Win10, or you inherit an unpatched fleet next week.
- **GPO**: total, linked/unlinked, settings volume. Export and run Intune Group Policy Analytics to get % mappable to settings catalog.
- **On-prem dependencies for Entra-joined devices**: file shares/DFS, print (Universal Print?), apps using Windows Integrated Auth, device certs for Wi-Fi/VPN (NDES/SCEP vs Cloud PKI), LAPS, local admin model, logon scripts, mapped drives, legacy LOB.
- Local admin population (feeds W13), patch compliance %, third-party app updating.

**macOS**

- Count, macOS version spread, hardware (Intel vs Apple silicon), ownership.
- Management plane: Jamf, Intune, Kandji/Mosyle, or nothing. If Jamf: is the Jamf-to-Intune device compliance connector in place so Macs can satisfy CA? ADE (Automated Device Enrollment) through Apple Business Manager, or manual enrollment?
- Identity: Platform SSO for macOS deployed? Local account creation method, password sync vs. passwordless (Secure Enclave key) mode, FileVault enabled and keys escrowed.
- Local admin: are users admins by default (common on Macs)? Any temporary-admin tooling (Jamf Connect, Privileges.app, Admin By Request)?
- Security: MDE on Mac (AV + EDR, network protection and web content filtering are GA on macOS), [EDR vendor] on Mac, firewall, Gatekeeper/XProtect state, Homebrew usage.
- App delivery: VPP apps, packaged installers, who maintains them.

**Linux (Ubuntu, developers)**

- Count, distro and version spread (Ubuntu LTS releases in use), how devices are issued and imaged, who owns them operationally.
- Management: Intune Linux enrollment (Ubuntu Desktop LTS; gives compliance + CA for browser-based access via Edge/Intune portal, bash script deployment, and custom compliance; no app catalog), Landscape, Ansible/Puppet/Salt, or unmanaged.
- Security agent: MDE on Linux (AV/EDR GA; network protection and web filtering are **preview, servers-only, insiders channel** as of this writing, so there's no Microsoft web-filtering story for Linux laptops today), [EDR vendor] on Linux, disk encryption (LUKS) state, firewall.
- Privilege: root/sudo model (everyone in sudoers? NOPASSWD? any logging?), local account vs. directory-bound (SSSD to AD?) vs. Entra-joined via Intune.
- Developer hygiene: SSH key handling, secrets on disk, Docker (daemon access = root), package managers pulling arbitrary code, personal GitHub access from corporate repos, CA coverage for GitHub/GitLab/cloud consoles.
- Access to private resources: VPN today? This population is the reason GSA can't be the only ZTNA answer (no Linux client), see 3.7 and 6.4.

**Red flags**

- SCCM unpatched. No co-management (longest migration path). Servers in SCCM with no server plan.
- Win10 without ESU. Apple push cert expiring. No Autopilot. OMA-URI soup. Everyone local admin.
- SCCM used as the "compliance" signal (CA can't see it without co-management).
- Macs on Jamf with no compliance connector (CA is blind to them). Mac users admin by default with no elevation tooling.
- Linux laptops with no EDR, no disk encryption, NOPASSWD sudo, and full VPN access. At a 20k company this is where the crown-jewel source code lives.

### 3.6 Mobile (W5)

**Collect**

- Current MDM/MAM: Intune, something else, or nothing. App protection policies and conditional launch settings. CA requiring approved app / app protection?
- Ownership model: corporate vs BYOD counts, stipend program, frontline/shared devices.
- Exchange ActiveSync device count and policies (EAS devices bypassing MAM is common).
- Apple Business Manager, VPP, push cert, Android Enterprise binding, OS version floors.
- HR/Legal stance on BYOD, consent documentation, union/works council constraints, privacy notices.

**Red flags**

- EAS unmanaged. No MAM at all. CA doesn't require app protection for mobile.
- Personal devices with full MDM and no consent documentation.

See section 6.3 for the MDM vs MAM decision framing.

### 3.7 Network edge: [DNS filter], VPN, GSA fit (W6)

**Collect**

- **[DNS filter]**: features actually used (DNS-layer only vs SIG: SWG, cloud firewall, CASB, RBI, DLP), deployment (roaming client, [VPN client] module, network DNS, virtual appliances), coverage (managed PCs only, or also servers, guests, IoT, Macs, mobile), policy count, SSL decryption, who consumes the reporting (SOC), AD identity integration.
- **VPN**: product, user count, always-on, split tunnel, MFA method ([MFA vendor] RADIUS?), private app inventory reached over VPN (becomes the GSA Private Access app list), egress IPs used as named locations.
- Offices: count, Wi-Fi 802.1X/NAC, proxies/PAC, SD-WAN, firewall vendor, any existing ZTNA or SASE plans.

**Platform coverage facts (verified 2026-10-09)**

- Global Secure Access client: Windows, macOS, iOS, Android. **No Linux client.** Servers, IoT, guests, unmanaged devices also need another answer.
- Defender for Endpoint web content filtering / network protection: GA on Windows and macOS. On Linux it's **preview, AMD64 servers only, insiders channel, enabled per tenant on request, no end-user block page.** Not a Linux laptop control today.
- Cloudflare One (WARP client): Windows, macOS, Linux. Entra ID as IdP with SCIM, Intune (Microsoft Endpoint Manager) as a device posture provider, DNS "locations" for unmanaged devices on your network.
- Zscaler and Netskope both ship Linux clients **(verify current distro support)**.
- ThreatLocker Web Control: agent-based filtering plus DNS redirect for unmanaged devices on-network. Per-OS support isn't stated publicly; ask the vendor (section 3.12).

**[DNS filter]-exit option matrix (fill in during audit; decision framing in 6.4)**

| Option | Win/Mac/mobile SWG | Linux laptop filtering | On-network unmanaged / IoT / guest | ZTNA (Win/Mac) | ZTNA (Linux) | Entra CA tie-in | License |
|---|---|---|---|---|---|---|---|
| A. Microsoft-max: GSA Internet + Private Access, MDE WCF, firewall DNS security on-network | GSA + MDE | None (MDE preview only); gap | Firewall vendor DNS security (often already licensed) | GSA Private Access | None; needs a second product | Full (compliant network, universal CA) | Entra Suite |
| B. Single SSE vendor (Cloudflare One, or Zscaler / Netskope) | Vendor client | Vendor client | DNS locations / IPsec from sites | Vendor ZTNA | Vendor client | Partial (Entra IdP + Intune posture, no compliant-network condition) | Vendor per-user |
| C. Hybrid: GSA for Win/Mac + Cloudflare (or similar) scoped to Linux and on-network DNS | GSA | Cloudflare | Cloudflare DNS locations | GSA | Cloudflare Access | Full for Win/Mac | Entra Suite + small Cloudflare tier |
| D. ThreatLocker Web Control + Network Control (only if ThreatLocker is adopted for W13) | TL agent | TL agent (verify module support) | DNS redirect | Network Control (host firewall model, agents both ends) | Network Control (verify) | None | TL per-endpoint |

**Red flags**

- [DNS filter] protecting servers/IoT (GSA won't). Trusted-IP MFA bypass tied to VPN egress. VPN without MFA. Full-tunnel VPN hairpinning M365 traffic.
- Linux developers reaching production over a flat VPN with no device posture check.

### 3.8 Endpoint and email security: [EDR vendor], Defender XDR, [mail gateway] (W7, W8)

**Collect**

- **[EDR vendor]**: agent coverage vs fleet, EDR mode, exclusions, Mac/Linux/server coverage, MDR used, SIEM integration, contract end date and auto-renew terms.
- **Defender stack**: MDE onboarding state (any?), Defender AV active vs passive, ASR rules, tamper protection, MDI sensors on DCs/ADFS/ADCS/Entra Connect (probably none on E3), Defender for Cloud Apps (app discovery, policies), Defender XDR unified RBAC, automated investigation level, device groups, Vulnerability Management coverage, Sentinel (workspace, connectors, ingestion cost, analytic rules, who watches it), Security Copilot.
- **Email**: MX per domain, inbound/outbound connectors, [mail gateway] modules in use (URL Defense, Attachment Defense, TAP, Encryption, EFD/DMARC, Archive, Security Awareness, Secure Share), EOP/MDO current policies (preset Standard/Strict or custom or defaults), Safe Links/Attachments, anti-phish impersonation settings, SPF/DKIM/DMARC per domain (DKIM enabled in EXO? DMARC p=none/quarantine/reject?), transport rules (count, any SCL -1 bypass for [mail gateway] IPs), Enhanced Filtering for Connectors enabled, quarantine policies, user-reported message path ([mail gateway] button vs Microsoft), journaling/archiving ([mail gateway] Archive to Purview retention), encryption ([mail gateway] Encryption to Purview Message Encryption), mailbox counts by type, mailbox forwarding to external (exfil check), Exchange hybrid servers.

**Red flags**

- SCL -1 bypass rules (whoever spoofs the [mail gateway] IP range bypasses everything). DMARC p=none. No DKIM.
- MDO untouched at defaults while being paid for post-E5.
- [EDR vendor] auto-renews in 60 days and nobody knew.
- MDI nowhere. Sentinel either non-existent or ingesting everything with no cost control.

### 3.9 Collaboration, data, Purview, Copilot readiness (W9, W10)

**Collect**

- **SharePoint/OneDrive**: tenant sharing settings (external sharing level, anonymous links, default link type/permission, expiration, domain allow/deny), site count, sites granting "Everyone" / "Everyone except external users", sites with active anonymous links, inactive sites, ownerless sites, OneDrive retention for departed users, legacy auth protocols in SPO, Restricted Access Control (RAC) / Restricted Content Discovery (RCD) in use, SAM licensed (included with Copilot licenses **(verify)**), data access governance reports, sensitivity labels on containers, Teams count and ownerless teams, M365 group expiration.
- **Teams**: external access/federation (open to all?), guest access, meeting policies (anonymous join, lobby), app permission policies, third-party app consent, Teams Phone.
- **Purview current state**: unified audit log on and retention (Standard 180 days; E5 Premium 1 year), audit retention policies, sensitivity labels (defined, published, auto-labeling, container labels), DLP policies by workload (EXO/SPO/OneDrive/Teams/Endpoint; devices onboarded for Endpoint DLP), retention policies/labels vs the Legal retention schedule, eDiscovery usage and active holds, Insider Risk Management (HR connector?), Communication Compliance, Information Barriers, Records Management, DSPM for AI, Information Protection scanner for on-prem shares, Purview role assignments.
- **Copilot**: licensed count, pilot state, settings (web grounding, agents/Copilot Studio governance, Graph connectors), oversharing assessment run (SAM reports), DSPM for AI reports, Restricted SharePoint Search in use (temporary measure), label inheritance behavior, meeting transcript/recording policies, prompt/response retention and audit.

**Red flags**

- Anonymous links org-wide. Audit log off. No labels, no DLP.
- Copilot already deployed on top of unassessed oversharing. Ownerless sites in the thousands.
- Teams federation fully open with no guest governance.

### 3.10 Governance, lifecycle, apps (W11)

**Collect**

- **Source of truth**: HRIS (Workday, SuccessFactors, UKG, other), how accounts get created today (manual, scripts, MIM, SailPoint/Saviynt/Okta), JML process maps, time-to-provision and time-to-deprovision, orphan accounts (enabled with no HR record), contractor handling, leaver steps (disable, revoke sessions, device wipe, mailbox conversion, OneDrive handoff), mover handling (group cleanup), rehires.
- **Access model**: role-based groups or ad hoc, group sprawl count, nesting, DL ownership, direct assignments.
- **Entra ID Governance today**: access reviews (any?), access packages, PIM for groups, lifecycle workflows, connected orgs, inactive users >90 days, inactive guests.
- **Apps/SSO**: enterprise apps by protocol (SAML/OIDC/password/linked), apps on ADFS (relying party trusts), apps on [MFA vendor] SSO or another IdP, LDAP-bound apps, header/Kerberos apps (App Proxy / GSA Private Access candidates), SCIM provisioning in use and for which apps, apps with local accounts (Defender for Cloud Apps discovery or [DNS filter] logs), expiring SAML certs, app owners assigned.
- **Non-human identities**: AD service accounts, gMSA adoption, Entra workload identities, secrets management, Workload ID Premium.
- **Admin model**: RBAC, PAWs, admin units (20k with multiple business units usually needs them), Intune scope tags, Exchange RBAC, Purview roles, SPO admin count.

Licensing note: access reviews and basic entitlement management are in Entra ID P2 (E5). Lifecycle workflows, ML-assisted reviews, auto-assignment policies, PIM-for-groups reviews need Entra ID Governance or Entra Suite **(verify against the current matrix; it shifts)**.

**Red flags**

- HR to AD by hand. No deprovisioning SLA. Thousands of inactive accounts.
- ADFS as app IdP. SAML certs expiring. No access reviews on privileged roles or guests.
- No admin units; one team holding GA for everything.

### 3.11 Operations and monitoring (W12)

**Collect**

- SIEM, log sources and retention, alert ownership, SOC/MDR arrangement, IR plan, tabletop history.
- M365 backup (Microsoft 365 Backup, third party, or nothing), AD backups and forest recovery plan, Entra Connect recovery, break-glass testing.
- Change management, documentation state, runbooks.
- Expiry monitoring: Apple push cert, VPP tokens, SAML certs, Entra Connect/ADFS certs, app secrets, domain registrations.
- Service health alerts, Message Center triage process, who tracks Microsoft retirement timelines.
- Support: Unified/Premier, CSAM, FastTrack engagement.

**Red flags**

- No backup decision documented. Nobody reads Message Center. No cert expiry calendar.

### 3.12 Cross-platform privilege management and application control (W13)

The goal you described: approval-based admin elevation on Windows, macOS, and Linux from one console, since Intune EPM is Windows-only (confirmed: nothing for macOS or Linux on Microsoft's Intune roadmap page as of today). ThreatLocker is the candidate on the table. The audit's job is to size the problem and write the evaluation criteria before anyone buys anything.

**Collect**

- Local admin population per platform: Windows (from Intune/SCCM inventory), macOS (admin-by-default is the norm; count), Linux (sudoers membership, NOPASSWD entries, shared root passwords).
- Why people have admin: developer tooling (Docker, package managers, IDEs), legacy apps, printers/drivers, "always had it." Group by reason; each reason is a policy you'll need.
- Current elevation tooling anywhere: Intune EPM (needs Intune Suite or EPM add-on), Jamf temporary admin, Privileges.app, Admin By Request, scripts, nothing.
- Application control today: AppLocker / WDAC on Windows, Gatekeeper-only on Mac, nothing on Linux. Any allowlisting attempted before and why it stopped.
- Helpdesk volume for "I need admin to install X" and the current approval path (ticket? verbal? none?).
- Developer workflow constraints: how often do devs compile and run new binaries, use containers, install from pip/npm/brew/apt. This decides whether default-deny allowlisting is realistic for that population.
- Server estate: does the Linux privilege problem extend to servers (SSH, sudo on prod)? That's a PAM problem, not an endpoint one.
- Existing EDR coexistence requirements ([EDR vendor] or MDE kernel hooks vs. a second agent).

**ThreatLocker evaluation criteria (what to make the vendor demonstrate, not describe)**

- Elevation Control on macOS and on Ubuntu: live demo of a request, approval, and time-boxed elevation on each. Their public docs confirm a Linux agent for Ubuntu 20.04 through 26.04 (eBPF on kernel 5.10+) but don't state which modules run on Linux or Mac. Get it in writing per module per OS.
- Approval workflow: Teams/Slack/portal approvals, approver groups, SLAs, audit trail, Entra ID group integration, MFA on approval.
- Application Control for developers: learning mode duration, how it handles compiled-on-device binaries, container runtimes, interpreter policies (python, node), Ringfencing for dev tools. Ask for a reference customer with a large developer population.
- Network Control as "ZTNA": it's a host-based firewall with dynamic ACLs. Both ends (laptop and server) need the agent for device-authorized rules; there's no identity-aware proxy, no clientless browser access, no Entra CA condition. Great for "only our devices can hit SSH/RDP on these servers," not a replacement for GSA Private Access or Cloudflare Access for web apps. Confirm Linux support for Network Control specifically.
- Web Control: per-OS support, category depth, TLS handling, reporting export to SIEM. Only relevant if the platform is adopted for W13 anyway.
- Coexistence with MDE or [EDR vendor], performance on developer workloads (build times), offline behavior, agent tamper protection.
- Operational load: who runs the approval queue at 20k, how many FTE the vendor's reference customers staff for it.
- Price per endpoint for the module bundle you'd actually use, vs. the alternatives below.

**Alternatives to price alongside (cross-platform EPM without the allowlisting platform)**

- Admin By Request (Windows, macOS, Linux; approval workflow; Entra integration).
- BeyondTrust Endpoint Privilege Management (Windows, macOS, Linux).
- CyberArk Endpoint Privilege Manager (Windows, macOS, Linux).
- Delinea Privilege Manager (Windows, macOS; Linux via their server PAM line) **(verify current Linux coverage)**.
- For developer access to servers/Kubernetes/databases specifically: Teleport (Entra SSO, access requests with approvals, session recording). Different problem from laptop admin rights, but often what "Linux privilege" turns out to mean.
- Intune EPM for Windows only plus one of the above for Mac/Linux: two consoles, two approval queues. I'd avoid it unless Intune Suite is being bought for other reasons.

**Red flags**

- Devs have NOPASSWD sudo and root Docker on laptops that also hold prod credentials.
- Mac users admin by default with no elevation tooling and no FileVault escrow.
- A prior allowlisting attempt that was abandoned (find out why before repeating it).

---

## 4. Timeline (6 to 8 weeks, part-time while onboarding)

| Week | Focus | Interviews | Output |
|---|---|---|---|
| 0 | Access, tooling, document collection, contract/renewal matrix, kickoff with sponsor | Sponsor | Access confirmed, evidence folder, Appendix D started |
| 1 | Run Maester + Zero Trust Assessment; 3.1 tenant/licensing; 3.2 Entra posture (Appendix A.1 script) | Identity/AD, Security | Day-one scores; first stop-the-bleeding list to sponsor |
| 2 | 3.3 hybrid/AD (jump box); 3.4 authentication/[MFA vendor] inventory | AD team, Helpdesk lead | AD health summary; [MFA vendor] integration list; SSPR data |
| 3 | 3.5 endpoints (SCCM + Intune + Windows/Mac/Linux fleet + GPO analytics); 3.6 mobile; 3.12 local admin and sudo inventory | Endpoint/SCCM, Mac admins, Linux/dev leads | Fleet baseline; packaging backlog; Entra Join dependency list; privilege problem sized |
| 4 | 3.7 network/[DNS filter]/VPN incl. Linux ZTNA need; 3.8 [EDR vendor]/Defender/[mail gateway] (Appendix A.2 script) | Network, SOC/MDR, Messaging | [DNS filter] feature matrix + exit option matrix; mail flow + policy baseline |
| 5 | 3.9 collaboration/Purview/Copilot readiness | SharePoint, Legal/Records, Copilot owner | Sharing posture; Purview gap list; Copilot readiness verdict |
| 6 | 3.10 governance/lifecycle/apps; 3.11 operations | HRIS owner, app owners, SIEM owner | JML map; app/SSO inventory; ops gaps |
| 7 | Scoring, dependency map, roadmap v1, E5/Suite business case, budget asks; vendor eval scopes written (ThreatLocker vs EPM alternatives; [DNS filter] exit options) | Sponsor preview | Draft readout; RFP-lite criteria for W6 and W13 |
| 8 | Readout; decisions requested (section 6) | Sponsor, leadership | Approved roadmap v1, decision log |

Every Friday: one-page status. Every finding into the tracker the day it's found.

If you have one helper, run weeks 1 to 2 and 3 to 4 in parallel and finish in 5 to 6 weeks.

---

## 5. Scoring and prioritization

Each finding gets:

- **Risk** = likelihood (1 to 5) x impact (1 to 5).
- **Effort** = S (days) / M (weeks) / L (a quarter) / XL (multi-quarter or needs licensing).
- **Dependency** = none / licensing / another workstream.
- **Quick win** = yes if under two weeks, low blast radius, no new license.
- **Owner** and **evidence link**.

Buckets:

1. **Stop the bleeding** (risk >= 16, effort S/M, no license dependency). Do now, with change control. Typical: admins without phishing-resistant MFA, no break-glass, legacy auth open, user consent allow-all, audit log off, SCL -1 bypass rules, expiring Apple push cert, Win10 without ESU, [EDR vendor] auto-renew about to fire.
2. **Foundations** (unblock other workstreams): E5 decision, Authenticator rollout, Intune co-management, MDE onboarding in passive mode, audit log/SIEM, admin units and RBAC.
3. **Program workstreams** (W2 to W11 as sequenced in section 7).
4. **Later** (real but not now).

Before/after metrics to carry through the whole program: Secure Score, Identity Secure Score, Compliance Manager score, Maester pass rate, MFA-registered %, passwordless-capable %, Intune compliance %, Entra-joined %, % of apps on Entra SSO, mean time to deprovision.

---

## 6. Decisions needed, and where I'd push back

You said you want disagreement said plainly, so here it is. Each of these is a decision for you and the sponsor; the audit's job is to put numbers under them.

### 6.1 SSPR vs passkeys

I don't think "skip SSPR and go passkeys" is the right framing, for three reasons:

- In hybrid AD the password still exists whether or not users know it. Passkeys reduce how often it's used; they don't remove the recovery problem.
- SSPR itself isn't the attack surface. Weak SSPR methods are (security questions, SMS, email). SSPR restricted to Authenticator with number matching is roughly as strong as the MFA you're already trusting for sign-in.
- SSPR's supported methods don't include FIDO2/passkeys, so a passkey-only user can't self-serve a reset at all. At 20k that means every lockout and forgotten password is a helpdesk ticket with a human doing identity verification, which is exactly where social engineering attacks land (the MGM/Okta-style helpdesk compromises).

Options to put in front of the sponsor once the audit has the reset ticket volume:

- **A.** SSPR on, Authenticator-only, two methods required, writeback enabled, registration enforced through the combined registration flow. Passkeys rolled out on top for sign-in. Lowest helpdesk cost.
- **B.** No SSPR. Passkeys + WHfB for sign-in. Recovery via helpdesk-issued Temporary Access Pass, gated by a strong verification step (Entra Verified ID Face Check, or a documented manager-plus-video process). Best security, highest ops cost, needs a real helpdesk procedure before day one.
- **C.** Hybrid: SSPR on for the general population (option A), off for admins and high-risk roles, who use option B.

I'd lean C. Measure first, decide after.

### 6.2 "Move as much as we can to Entra Joined"

There's no Microsoft-supported in-place conversion from hybrid joined to Entra joined. It's a reset (Autopilot) or a third-party profile migration tool. At 20k I'd ride the hardware refresh cycle:

- New and refreshed devices: Entra joined via Autopilot from day one.
- Existing hybrid-joined devices: stay hybrid, managed by Intune through co-management, until refresh.
- WHfB cloud Kerberos trust gives Entra-joined devices SSO to on-prem file/print/apps, so the join type stops mattering for most users once that's in.

The audit item that decides the pace is the on-prem dependency list in 3.5 (certs for 802.1X, LAPS, logon scripts, legacy LOB, GPO-only settings). Push to re-frame the goal as "100% of new devices Entra joined by [date], hybrid retired at refresh."

### 6.3 Privacy MDM vs MAM for phones

Decide by device ownership, not by preference:

- Corporate-owned: MDM (supervised iOS, fully managed Android). No debate.
- BYOD: MAM-first. App protection policies carry almost all of the data protection you actually want (encryption, conditional launch, cut/copy/paste controls, selective wipe). User Enrollment / work profile MDM is privacy-respecting, but at 20k the adoption drop-off, HR questions, and "can IT see my photos" tickets are real, and the marginal security gain over MAM is small. MDM-optional for BYOD users who want full Outlook/Teams features is a reasonable middle.

This one needs HR and Legal in the room, plus whatever union or works-council constraints exist. Get their answer in the audit, not after you've built policies.

### 6.4 Getting off [DNS filter] (and its vendor) entirely

You asked whether there's a Microsoft answer, or something better. Short version: Microsoft covers part of it, and with Linux developers in scope it can't cover all of it today.

**What Microsoft has**

- Global Secure Access Internet Access: secure web gateway with category/FQDN filtering, threat intelligence filtering, the M365 traffic profile, universal CA and the compliant-network condition. Clients for Windows, macOS, iOS, Android. No Linux client. No DNS-layer coverage for unmanaged devices on your network (Remote Networks can tunnel branch traffic via IPsec from the site router; confirm which traffic profiles that supports today **(verify)**).
- Defender for Endpoint web content filtering and network protection: GA on Windows and macOS, included in MDE P2 (E5). Category blocking plus custom indicators, reporting in the Defender portal. On Linux it's preview, servers only, insiders channel, no block page. Less policy depth than [DNS filter] SIG, but it's already paid for after E5 and it's a useful second layer.
- Nothing from Microsoft does DNS-layer filtering for IoT, guests, printers, or servers that can't run an agent. That's the [DNS filter] feature most people forget they're using.

**What's better, if "no incumbent network vendor" is the constraint**

- **Cloudflare One** is the one I'd pilot first. It replaces [DNS filter] feature-for-feature: DNS and HTTP filtering with the WARP client on Windows, macOS, and Linux; DNS locations for on-network unmanaged devices (the [DNS filter] network-DNS use case); Cloudflare Access for ZTNA including Linux; Entra ID as IdP with SCIM; Intune as a posture provider. It also answers the Linux ZTNA question without a second product. What you give up versus GSA: the Entra compliant-network CA condition and universal CA tenant restrictions, and the "it's in the Entra Suite we're already buying" economics.
- **Zscaler (ZIA + ZPA) and Netskope**: more depth (CASB, DLP, RBI), Linux clients, enterprise pricing and enterprise implementation effort. Right answer if the security team wants a full SSE platform and has budget; overkill if the need is DNS/SWG plus ZTNA.
- **DNS-only replacements** (DNSFilter, Infoblox Threat Defense, Akamai SIA): only if the audit shows [DNS filter] is used purely as DNS-layer filtering. Cheap, fast to deploy, but they don't solve ZTNA.
- Your **firewall vendor's DNS security** (Palo Alto DNS Security, Fortinet, etc.) is often already licensed and covers on-network IoT/guest. Check before buying anything for that slice.

**My lean**

Pick one of two coherent end-states rather than drifting into four products:

- **Microsoft-max** (option A in 3.7): GSA Internet + Private Access for Windows/Mac/mobile, MDE web filtering as a second layer, firewall DNS security on-network, and a deliberately scoped second product for Linux developers (Cloudflare for Linux only, or Teleport if the need is really server access). You keep the full Entra CA integration. Cost: Entra Suite plus a small second product; two consoles.
- **Single SSE** (option B): Cloudflare One for everything, skip GSA except the M365 traffic profile if it's included in your Entra licensing **(verify)**. One console, Linux is first-class, [DNS filter]'s on-network DNS feature survives. Cost: you lose compliant-network CA, and you're adding a vendor while trying to consolidate.

If the Linux developer population is more than a few hundred people and they hold production access, I'd lean to the single-SSE end-state. If it's small and server access can go through a PAM tool, Microsoft-max keeps the stack tighter. Either way, don't buy Entra Suite for GSA until this decision is made; the Suite still earns its keep for Entra ID Governance and Internet Access for Microsoft traffic, but GSA Private Access shouldn't be assumed.

### 6.5 Sequence: E5 first

Most of the program is blocked on licensing: Identity Protection, PIM-at-scale, MDE P2, MDO P2, MDI, Purview, Sentinel benefit. Get the E5 (and Entra Suite / Intune Suite) decision made early, timed to the EA anniversary. Use the [MFA vendor], [DNS filter], [EDR vendor], and [mail gateway] contract end dates to build the cost-offset story and the decommission sequence. Don't let technical workstreams run ahead of the license decision; you'll build on P1 and rebuild on P2.

### 6.6 [MFA vendor] exit has hidden dependencies

[MFA vendor] usually protects things Entra MFA doesn't natively: RDP/Windows logon (replacement is WHfB), VPN RADIUS (NPS extension, or remove the VPN with GSA Private Access), LDAP proxy (app re-platforming), [MFA vendor] SSO (an IdP migration). Authenticator rollout comes first anyway because Authenticator passkeys depend on it. Plan to run both for a quarter.

### 6.7 [EDR vendor] to Defender: fine to defer, but onboard MDE anyway

Post-E5 you're paying for MDE P2 whether you use it or not. Onboard the fleet to MDE with Defender AV in passive mode (automatic on Windows clients when [EDR vendor] is primary; set explicitly on servers) and EDR in block mode. You get Vulnerability Management, device inventory, and the compliance signal for CA immediately, and a no-drama cutover path if [EDR vendor] goes at renewal. Servers need Defender for Servers via Arc, which is a separate cost conversation.

### 6.8 [mail gateway] to MDO: workable, watch three things

SCL -1 bypass rules (remove them in the same change as the MX cutover, not before, not after), Enhanced Filtering for Connectors during the parallel period, and the non-filtering features [mail gateway] may be providing (archive, encryption, awareness training, DMARC reporting). Run MDO with preset Standard policies behind [mail gateway] for a few weeks, compare catch rates, then cut MX.

### 6.9 First 30 days: don't change anything

Except stop-the-bleeding items through their change process. The audit's credibility, and yours, depends on it.

### 6.10 ThreatLocker: good idea, wrong framing

The problem you described (approval-based admin elevation across Windows, macOS, and Linux from one console) is real, and Intune EPM genuinely doesn't solve it. Where I'd push back is on how ThreatLocker enters the conversation.

- **ThreatLocker is an allowlisting platform first.** Elevation Control is a module on top of Application Control and Ringfencing, and the agent is the same. If you adopt it for elevation, you're also deciding to run default-deny application control, or paying for a platform you half-use. At 20k with developers compiling and running new binaries all day, default-deny is a serious operational commitment: learning mode, approval queues, and a dev population that will route around it if it slows them down. Decide "do we want allowlisting as a control?" first. If yes, ThreatLocker is a strong candidate and elevation comes along for free. If no, buy a purpose-built cross-platform EPM tool (3.12 lists them) and skip the platform.
- **Mac and Linux module support isn't public.** Their docs confirm a Linux agent for Ubuntu 20.04 through 26.04, but not which modules work on Linux or Mac. "Does Elevation Control do sudo approvals on Ubuntu, live, today?" is the first question in the demo. If the answer is no, the cross-platform case collapses.
- **Network Control isn't ZTNA in the GSA/Cloudflare sense.** It's a host firewall with dynamic ACLs that needs the agent on both ends. It's excellent for microsegmentation ("only our laptops can reach SSH on these servers") and it does work without connector infrastructure. It doesn't do identity-aware proxying, clientless access, or Entra CA. It can complement GSA or Cloudflare; it can't replace them for web apps. Don't let the Linux ZTNA gap be the reason to buy ThreatLocker; solve that in 6.4.
- **Vendor count.** The whole program is consolidation toward Microsoft ([MFA vendor], [DNS filter], [mail gateway], maybe [EDR vendor] out). ThreatLocker adds a vendor and a second kernel agent next to MDE or [EDR vendor]. That's a fine trade if allowlisting is the goal. It's a poor trade for elevation alone.
- **Developers are the hard case regardless of tool.** Expect to end up with a tiered policy: standard users get approval-based elevation; developers get a pre-approved toolchain and time-boxed self-elevation with logging; server access goes through PAM/Teleport-style tooling, not laptop admin rights.

Recommendation: run the ThreatLocker eval against Admin By Request (or BeyondTrust/CyberArk EPM) on the elevation use case alone, with a Linux developer pilot group of 20 to 30 people. If ThreatLocker wins on elevation and the team wants allowlisting, buy the platform. If it only wins because of allowlisting, that's a separate decision with its own budget line.

### 6.11 Linux root for developers: priority, decisions, and the options ladder

**Where this sits in the program.** Windows and macOS are priority one and will take a couple of years. Linux hardening is deliberately later. Two reasons that's the right call: the population is smaller, and Microsoft is mid-build on Linux identity (see "What Microsoft shipped" below), so a heavy third-party integration bought today may be redundant in 18 months. One place I'd push back: don't defer *everything* Linux. A small minimum baseline is cheap, needs no new vendor, and protects the machines that hold source code and production credentials. That baseline rides along with Phase 0/3; the expensive decisions wait.

**Framing: "root for devs" is three problems**

1. sudo on their own laptop.
2. Privileged access to servers and production (a PAM problem, not a laptop problem).
3. Implicit root: `docker` group membership (the daemon runs as root), `curl | bash` installs, pip/npm post-install scripts run under sudo.

Most of the real risk is in 2 and 3, and those are cheaper to fix than 1. Also: application allowlisting controls *what runs*, not *who is root*. If ThreatLocker is adopted, everything in Tier 0 still applies.

**Decisions required (owner, timing)**

| # | Decision | Options | Owner | When |
|---|---|---|---|---|
| L1 | Is default-deny application allowlisting a control we want on developer machines? | Yes (ThreatLocker platform) / No (EPM tool only) / Windows+Mac only | CISO + Eng leadership | Before W13 vendor eval (audit week 7) |
| L2 | Minimum Linux baseline: ship now or wait for the Linux phase? | Now (recommended, Tier 0) / Wait | Connor + Eng leadership | Phase 0 |
| L3 | How do developers get sudo: standing, JIT with approval, or tiered by role? | Standing + logging / JIT via EPM tool / JIT via PIM for Groups / Tiered mix | Security + Eng leadership | Linux phase start, or earlier if ThreatLocker is bought for Win/Mac |
| L4 | Server and production access path | Teleport / Cloudflare Access / Entra SSH login on Arc-enabled servers / keep VPN (not recommended) | Security + Platform team | Coupled to 6.4 end-state |
| L5 | Linux device identity: adopt Microsoft SSO for Linux (Entra join + Intune compliance + CA) now, or wait for Platform SSO for Linux? | Join now (device trust + CA today) / Wait | Connor | Phase 3; low cost to do now |
| L6 | Developer environment model | Laptops stay thick clients / Cloud dev environments (Codespaces, remote dev containers) for the highest-risk teams | Eng leadership | Linux phase |

**Tier 0: minimum baseline, no new tools (recommend: do not defer)**

- Standard user by default; sudo only through a centrally managed group (AD group via SSSD if domain-bound, or a group pushed by Intune/Ansible/Landscape). Never local sudoers edits; you can't do JIT later if membership is a local file.
- No `NOPASSWD`. Short `timestamp_timeout` (5 to 15 min), `use_pty`, `log_output`, sudo logs to Sentinel. Check which sudo the LTS ships: Ubuntu 25.10 moved to sudo-rs, which implements a subset of classic sudoers (I/O logging among the gaps) **(verify for 26.04)**.
- Rootless Docker or Podman. Removes the "docker group = root" hole with almost no friction. Highest-value single change.
- LUKS everywhere, Secure Boot, no root login, no shared root password.
- MDE on Linux with tamper protection on. auditd rules for `execve` with euid 0, sudoers and group changes, new SUID binaries.
- Intune Linux enrollment (GA path, see below) with custom compliance scripts: NOPASSWD present? docker group non-empty? auditd stopped? disk unencrypted? Non-compliant blocks M365 and cloud consoles through CA. This is the enforcement lever without buying an agent.
- Short-lived credentials only on laptops: no long-lived cloud keys, SSH certs instead of raw keys, no prod tokens at rest. If laptop root yields nothing valuable, who has it matters less.

**Tier 1: just-in-time sudo with approvals, no allowlisting (decision L3)**

- Admin By Request for Linux: request, approve in Teams/portal, time-boxed sudo, logged, one console with Mac and Windows. The pragmatic pick.
- CyberArk EPM or BeyondTrust EPM Linux agents: same model, enterprise pricing, deeper PAM integration.
- No-new-vendor path: if Ubuntu is AD-bound via SSSD, make the sudo group an AD group and gate membership with Entra PIM for Groups plus Cloud Sync group provisioning to AD. Activation with MFA and justification, logged in Entra, reviewable with access reviews. Caveats: provisioning latency plus SSSD cache means minutes, not seconds, and it ties Linux to the AD footprint you're shrinking. Canonical's `authd` with the Entra ID broker is the non-AD cousin; whether it can map an Entra group to a local sudo group needs testing **(verify)**.

**Tier 2: make laptop root not matter for production (decisions L4, L6)**

- Server access through identity-aware tooling with device posture: Teleport (access requests, session recording, Entra SSO), Cloudflare Access, or Entra SSH login on Azure/Arc-enabled servers where sudo is granted by the "Virtual Machine Administrator Login" role, PIM-eligible, under CA. The last one is fully Microsoft-native and gives JIT root on servers today.
- Tier the developers: platform/infra devs keep standing sudo with heavy logging; app devs get JIT; nobody reaches production as root from a laptop.
- Cloud dev environments for the highest-risk teams turn the laptop into a thin client.

**Tier 3: detect**

- Sentinel analytics on MDE Linux process events: sudoers edits, new sudo group members, auditd or MDE stopped, `curl | sh` patterns, SUID changes, sudo by a user outside the approved group.

**What Microsoft shipped, and what to wait for (checked 2026-10-09)**

- Microsoft single sign-on for Linux (`microsoft-identity-broker`) 3.0.1 went GA on March 31, 2026. Devices now perform a Microsoft Entra **join** (not registration), can enroll in Intune, satisfy device-based CA, and support phishing-resistant MFA via smartcard/CBA or FIDO2 keys with a PIV applet. Supported: Ubuntu Desktop 24.04 and 26.04 LTS, RHEL 9 and 10. Ubuntu 22.04 Intune support ended August 2026. Requires the "Users may join devices to Microsoft Entra" setting to permit it.
- Not there yet: desktop login with Entra credentials (Microsoft's own notes call the join "a prerequisite step to enable platformSSO in the future"), Authenticator passkeys for Linux sign-in, Entra-group-to-sudo mapping, app deployment beyond bash scripts.
- Implication: device trust, compliance, and CA for Linux are available today at near-zero cost (decision L5: do it). Local accounts and sudo stay local for now. Re-evaluate Tier 1 when Platform SSO for Linux ships; it may make the PIM-for-Groups path work without AD.

**Recommendation**

Tier 0 and L5 in the first year alongside the Windows/Mac work, no budget needed. Run the Admin By Request pilot (20 to 30 Linux devs) during the ThreatLocker eval so elevation is compared like for like, but defer the purchase decision to the Linux phase unless ThreatLocker is bought for Windows/Mac anyway. Server access (L4) moves to Teleport or Entra SSH login with the 6.4 network decision, not the Linux phase, because that's where the production risk is.

---

## 7. Roadmap v0 (dependency-ordered sketch, refine after audit)

| Phase | Scope | Gate |
|---|---|---|
| 0. Stop the bleeding | Break-glass accounts, admins on phishing-resistant MFA, PIM for GA/PA/SA roles, block legacy auth, consent policy, audit log on + SIEM shipping, Win10 ESU, SCL -1 rules reviewed, expiring certs/tokens | Change approval |
| 1. Licensing | E5 decision, Entra Suite / Intune Suite / Copilot / SAM scoping, FastTrack engaged | EA anniversary |
| 2. Identity foundations | Identity Protection + risk CA, CA baseline (Microsoft-managed + persona-based custom set), Authenticator rollout, auth methods cleanup (SMS off), TAP, passkeys + WHfB cloud Kerberos trust, [MFA vendor] decom plan, helpdesk verification procedure, admin units + RBAC | Phase 1 |
| 3. Endpoints and mobile (Windows and macOS, multi-year) | Co-management + workload shift, Autopilot + Entra Join for new/refresh, GPO to settings catalog, Win11, MDE onboarding (passive) on Windows/Mac, Cloud PKI, SCCM server plan, mobile MDM/MAM per 6.3. Mac: compliance connector or Intune, Platform SSO, FileVault escrow. Cross-platform privilege management eval and rollout for Windows/Mac (W13, per 6.10), with a small Linux dev pilot group so the elevation tool is compared like for like | Phase 2 CA baseline |
| 3b. Linux minimum baseline (runs alongside Phase 3, no new vendor) | Tier 0 from 6.11: MDE with tamper protection, LUKS, no NOPASSWD, sudo via managed group with logging to Sentinel, rootless Docker/Podman, short-lived credentials, Microsoft SSO for Linux (Entra join + Intune compliance + CA, decision L5) | Decision L2 |
| 4. Data and Copilot | Audit retention, labels (publish, auto-label, container labels), DLP in simulation then enforce, retention per Legal schedule, oversharing cleanup (SAM/RAC/RCD, DSPM for AI), Insider Risk, then Copilot expansion | Phase 1; Legal input |
| 5. Email | MDO preset policies in parallel, EFC on, DKIM/DMARC to reject, archive/encryption replacements, MX cutover, [mail gateway] decom | [mail gateway] renewal date |
| 6. Network | End-state decision per 6.4 (Microsoft-max vs single SSE). Then: ZTNA pilot replacing VPN (GSA Private Access or Cloudflare Access, Linux devs in the first wave), SWG/DNS pilot, compliant-network CA where supported, on-network DNS security for IoT/guest, [DNS filter] decom | 3.7 matrix; licensing (Entra Suite or SSE vendor) |
| 7. Governance | HRIS-driven provisioning (API-driven inbound or connector), lifecycle workflows, access packages for standard roles, access reviews (privileged, guests, app roles), PIM for groups, SSO/SCIM migration off ADFS/[MFA vendor] SSO, workload identity hygiene | Entra ID Governance license |
| 8. Linux (after Windows/Mac) | Decisions L1, L3, L6: JIT sudo tooling (EPM tool, PIM for Groups path, or ThreatLocker if already adopted), developer tiering, cloud dev environments for high-risk teams; re-evaluate against whatever Microsoft has shipped for Linux by then (Platform SSO for Linux, passkeys, group mapping) | Phase 3 substantially complete; decision L1 |
| Parallel | Sentinel tuning, documentation, naming conventions, [EDR vendor]-to-MDE decision at renewal, server access path (decision L4, coupled to 6.4, does not wait for Phase 8) | |

Naming conventions: once I've seen their existing patterns I'll propose options for CA policies, groups, Intune profiles, and access packages. Your call on the final scheme.

---

## Appendix A. Mac PowerShell collection kit (read-only)

All scripts: PowerShell 7 on macOS, read-only Graph/EXO/Purview scopes, output to `~/audit/evidence/<timestamp>/` as JSON (full fidelity) plus CSV where the data is flat. Global Reader + Security Reader + View-Only Org Management should satisfy every call below; anything that fails on permissions is wrapped in try/catch and logged rather than aborting the run.

Expect 20 to 40 minutes on a 20k tenant for A.1, mostly the users and sign-in pulls.

### A.1 `Get-EntraIntuneBaseline.ps1`

```powershell
#Requires -Version 7.0
<#
.SYNOPSIS
  Read-only Entra ID + Intune baseline collection for the environment audit.
.NOTES
  Modules: Microsoft.Graph.Authentication, .Identity.SignIns, .Identity.DirectoryManagement, .Identity.Governance,
           .Users, .Groups, .Applications, .DeviceManagement, .DeviceManagement.Enrollment, .Devices.CorporateManagement,
           .Reports, Microsoft.Graph.Beta.DeviceManagement
  Run:     pwsh ./Get-EntraIntuneBaseline.ps1            (add -IncludeLegacyAuthSignIns for the slow 7-day legacy auth pull)
#>
[CmdletBinding()]
param(
    [string]$OutRoot = "$HOME/audit/evidence",
    [switch]$IncludeLegacyAuthSignIns,
    [int]$StaleDays = 90
)

$ErrorActionPreference = 'Stop'
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$Out   = Join-Path $OutRoot $stamp
New-Item -ItemType Directory -Path $Out -Force | Out-Null
Start-Transcript -Path (Join-Path $Out 'transcript.txt') | Out-Null

function Save-Evidence {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)] $InputObject,
        [Parameter(Mandatory)] [string] $Name,
        [switch] $Csv
    )
    begin { $items = [System.Collections.Generic.List[object]]::new() }
    process { if ($null -ne $InputObject) { $items.Add($InputObject) } }
    end {
        $items | ConvertTo-Json -Depth 12 | Set-Content -Path (Join-Path $Out "$Name.json")
        if ($Csv) { $items | Export-Csv -Path (Join-Path $Out "$Name.csv") -NoTypeInformation }
        Write-Host ("{0,-42} {1,7:N0}" -f $Name, $items.Count)
    }
}

function Invoke-Step {
    param([string]$Label, [scriptblock]$Script)
    try { & $Script }
    catch { Write-Warning "$Label failed: $($_.Exception.Message)"; Add-Content -Path (Join-Path $Out 'errors.txt') -Value "$Label :: $($_.Exception.Message)" }
}

$scopes = @(
    'Directory.Read.All','Policy.Read.All','AuditLog.Read.All','Reports.Read.All',
    'UserAuthenticationMethod.Read.All','Application.Read.All','Device.Read.All',
    'DeviceManagementManagedDevices.Read.All','DeviceManagementConfiguration.Read.All',
    'DeviceManagementServiceConfig.Read.All','DeviceManagementApps.Read.All',
    'RoleManagement.Read.Directory','RoleEligibilitySchedule.Read.Directory','RoleAssignmentSchedule.Read.Directory',
    'IdentityRiskyUser.Read.All','IdentityRiskEvent.Read.All','Organization.Read.All',
    'Group.Read.All','User.Read.All','OnPremDirectorySynchronization.Read.All'
)
Connect-MgGraph -Scopes $scopes -NoWelcome
$ctx = Get-MgContext
"Tenant: $($ctx.TenantId)  Account: $($ctx.Account)  Scopes: $($ctx.Scopes -join ', ')" | Set-Content (Join-Path $Out 'context.txt')
Write-Host "Writing to $Out`n"

# ---------- 1. Tenant + licensing ----------
Invoke-Step 'Organization' {
    Get-MgOrganization |
        Select-Object Id, DisplayName, TenantType, CountryLetterCode, OnPremisesSyncEnabled, OnPremisesLastSyncDateTime,
            @{n='VerifiedDomains';e={ ($_.VerifiedDomains | ForEach-Object { "$($_.Name)[$($_.Type)]" }) -join ';' }} |
        Save-Evidence -Name '01-organization'
}
Invoke-Step 'Subscribed SKUs' {
    Get-MgSubscribedSku |
        Select-Object SkuPartNumber, SkuId, CapabilityStatus, ConsumedUnits,
            @{n='Enabled';e={$_.PrepaidUnits.Enabled}}, @{n='Suspended';e={$_.PrepaidUnits.Suspended}}, @{n='Warning';e={$_.PrepaidUnits.Warning}},
            @{n='ServicePlans';e={ ($_.ServicePlans | Where-Object ProvisioningStatus -eq 'Success' | Select-Object -ExpandProperty ServicePlanName) -join ';' }} |
        Save-Evidence -Name '01-subscribed-skus' -Csv
}
Invoke-Step 'Hybrid sync features' {
    Get-MgDirectoryOnPremiseSynchronization | Save-Evidence -Name '01-onprem-sync-features'
}

# ---------- 2. Tenant-wide policies ----------
Invoke-Step 'Authorization policy'          { Get-MgPolicyAuthorizationPolicy | Save-Evidence -Name '02-authorization-policy' }
Invoke-Step 'Security defaults'             { Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy | Save-Evidence -Name '02-security-defaults' }
Invoke-Step 'Authentication methods policy' { Get-MgPolicyAuthenticationMethodPolicy | Save-Evidence -Name '02-authentication-methods-policy' }
Invoke-Step 'Authentication strengths'      { Get-MgPolicyAuthenticationStrengthPolicy -All | Save-Evidence -Name '02-authentication-strengths' }
Invoke-Step 'Admin consent request policy'  { Get-MgPolicyAdminConsentRequestPolicy | Save-Evidence -Name '02-admin-consent-request-policy' }
Invoke-Step 'Cross-tenant access defaults'  { Get-MgPolicyCrossTenantAccessPolicyDefault | Save-Evidence -Name '02-cross-tenant-access-defaults' }
Invoke-Step 'Cross-tenant access partners'  { Get-MgPolicyCrossTenantAccessPolicyPartner -All | Save-Evidence -Name '02-cross-tenant-access-partners' }

# ---------- 3. Conditional Access ----------
Invoke-Step 'CA policies' {
    $ca = Get-MgIdentityConditionalAccessPolicy -All
    $ca | Save-Evidence -Name '03-ca-policies-full'
    $ca | Select-Object DisplayName, State, CreatedDateTime, ModifiedDateTime,
        @{n='IncludeUsers';e={$_.Conditions.Users.IncludeUsers -join ';'}},
        @{n='ExcludeUsers';e={$_.Conditions.Users.ExcludeUsers -join ';'}},
        @{n='IncludeGroups';e={$_.Conditions.Users.IncludeGroups -join ';'}},
        @{n='ExcludeGroups';e={$_.Conditions.Users.ExcludeGroups -join ';'}},
        @{n='IncludeRoles';e={$_.Conditions.Users.IncludeRoles -join ';'}},
        @{n='IncludeApps';e={$_.Conditions.Applications.IncludeApplications -join ';'}},
        @{n='ExcludeApps';e={$_.Conditions.Applications.ExcludeApplications -join ';'}},
        @{n='ClientAppTypes';e={$_.Conditions.ClientAppTypes -join ';'}},
        @{n='Platforms';e={$_.Conditions.Platforms.IncludePlatforms -join ';'}},
        @{n='IncludeLocations';e={$_.Conditions.Locations.IncludeLocations -join ';'}},
        @{n='ExcludeLocations';e={$_.Conditions.Locations.ExcludeLocations -join ';'}},
        @{n='SignInRisk';e={$_.Conditions.SignInRiskLevels -join ';'}},
        @{n='UserRisk';e={$_.Conditions.UserRiskLevels -join ';'}},
        @{n='GrantOperator';e={$_.GrantControls.Operator}},
        @{n='GrantControls';e={$_.GrantControls.BuiltInControls -join ';'}},
        @{n='AuthStrengthId';e={$_.GrantControls.AuthenticationStrength.Id}},
        @{n='SignInFrequency';e={ if ($_.SessionControls.SignInFrequency.IsEnabled) { "$($_.SessionControls.SignInFrequency.Value) $($_.SessionControls.SignInFrequency.Type)" } }},
        @{n='PersistentBrowser';e={$_.SessionControls.PersistentBrowser.Mode}} |
        Save-Evidence -Name '03-ca-policies-summary' -Csv
}
Invoke-Step 'Named locations' {
    Get-MgIdentityConditionalAccessNamedLocation -All |
        Select-Object DisplayName, Id, CreatedDateTime, ModifiedDateTime,
            @{n='Type';e={$_.AdditionalProperties.'@odata.type'}},
            @{n='IsTrusted';e={$_.AdditionalProperties.isTrusted}},
            @{n='IpRanges';e={ ($_.AdditionalProperties.ipRanges | ForEach-Object { $_.cidrAddress }) -join ';' }},
            @{n='Countries';e={ $_.AdditionalProperties.countriesAndRegions -join ';' }} |
        Save-Evidence -Name '03-named-locations' -Csv
}

# ---------- 4. Privileged roles (active + PIM eligible) ----------
Invoke-Step 'Role assignments' {
    $roleDefs = @{}
    Get-MgRoleManagementDirectoryRoleDefinition -All | ForEach-Object { $roleDefs[$_.Id] = $_.DisplayName }

    Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ExpandProperty Principal |
        Select-Object @{n='Role';e={$roleDefs[$_.RoleDefinitionId]}}, AssignmentType, MemberType, DirectoryScopeId, StartDateTime, EndDateTime,
            @{n='PrincipalType';e={$_.Principal.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.',''}},
            @{n='PrincipalName';e={$_.Principal.AdditionalProperties.displayName}},
            @{n='PrincipalUpn';e={$_.Principal.AdditionalProperties.userPrincipalName}},
            @{n='PrincipalSynced';e={$_.Principal.AdditionalProperties.onPremisesSyncEnabled}},
            PrincipalId |
        Save-Evidence -Name '04-role-assignments-active' -Csv

    Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ExpandProperty Principal |
        Select-Object @{n='Role';e={$roleDefs[$_.RoleDefinitionId]}}, MemberType, DirectoryScopeId, StartDateTime, EndDateTime,
            @{n='PrincipalType';e={$_.Principal.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.',''}},
            @{n='PrincipalName';e={$_.Principal.AdditionalProperties.displayName}},
            @{n='PrincipalUpn';e={$_.Principal.AdditionalProperties.userPrincipalName}},
            PrincipalId |
        Save-Evidence -Name '04-role-assignments-pim-eligible' -Csv
}

# ---------- 5. Authentication method registration ----------
Invoke-Step 'Auth method registration' {
    $reg = Get-MgReportAuthenticationMethodUserRegistrationDetail -All -PageSize 999
    $reg | Select-Object UserPrincipalName, UserDisplayName, UserType, IsAdmin, IsMfaRegistered, IsMfaCapable,
        IsPasswordlessCapable, IsSsprRegistered, IsSsprEnabled, IsSsprCapable, IsSystemPreferredAuthenticationMethodEnabled,
        SystemPreferredAuthenticationMethods, UserPreferredMethodForSecondaryAuthentication, LastUpdatedDateTime,
        @{n='MethodsRegistered';e={$_.MethodsRegistered -join ';'}} |
        Save-Evidence -Name '05-auth-registration' -Csv

    $members = $reg | Where-Object UserType -eq 'member'
    [pscustomobject]@{
        TotalMembers            = $members.Count
        MfaRegisteredPct        = [math]::Round(100 * ($members | Where-Object IsMfaRegistered).Count / [math]::Max(1,$members.Count), 1)
        PasswordlessCapablePct  = [math]::Round(100 * ($members | Where-Object IsPasswordlessCapable).Count / [math]::Max(1,$members.Count), 1)
        SsprRegisteredPct       = [math]::Round(100 * ($members | Where-Object IsSsprRegistered).Count / [math]::Max(1,$members.Count), 1)
        Admins                  = ($members | Where-Object IsAdmin).Count
        AdminsNotPasswordless   = ($members | Where-Object { $_.IsAdmin -and -not $_.IsPasswordlessCapable }).Count
        AdminsNoMfa             = ($members | Where-Object { $_.IsAdmin -and -not $_.IsMfaRegistered }).Count
        UsersWithSms            = ($members | Where-Object { $_.MethodsRegistered -contains 'mobilePhone' }).Count
        UsersWithPasskeyOrFido  = ($members | Where-Object { $_.MethodsRegistered -match 'fido2|passKey' }).Count
        UsersWithWhfb           = ($members | Where-Object { $_.MethodsRegistered -contains 'windowsHelloForBusiness' }).Count
    } | Save-Evidence -Name '05-auth-registration-summary'
}

# ---------- 6. Users ----------
Invoke-Step 'Users' {
    $users = Get-MgUser -All -PageSize 999 -Property Id,UserPrincipalName,DisplayName,AccountEnabled,UserType,OnPremisesSyncEnabled,
        CreatedDateTime,SignInActivity,AssignedLicenses,Department,JobTitle,CompanyName,UsageLocation,CreationType,ExternalUserState
    $flat = $users | Select-Object Id, UserPrincipalName, DisplayName, AccountEnabled, UserType, OnPremisesSyncEnabled, CreatedDateTime,
        Department, JobTitle, CompanyName, UsageLocation, CreationType, ExternalUserState,
        @{n='LicenseCount';e={$_.AssignedLicenses.Count}},
        @{n='LastInteractiveSignIn';e={$_.SignInActivity.LastSignInDateTime}},
        @{n='LastNonInteractiveSignIn';e={$_.SignInActivity.LastNonInteractiveSignInDateTime}}
    $flat | Save-Evidence -Name '06-users' -Csv

    $cutoff = (Get-Date).AddDays(-$StaleDays)
    [pscustomobject]@{
        Total                 = $flat.Count
        Members               = ($flat | Where-Object UserType -eq 'Member').Count
        Guests                = ($flat | Where-Object UserType -eq 'Guest').Count
        Synced                = ($flat | Where-Object OnPremisesSyncEnabled).Count
        CloudOnlyMembers      = ($flat | Where-Object { $_.UserType -eq 'Member' -and -not $_.OnPremisesSyncEnabled }).Count
        Disabled              = ($flat | Where-Object { -not $_.AccountEnabled }).Count
        DisabledWithLicenses  = ($flat | Where-Object { -not $_.AccountEnabled -and $_.LicenseCount -gt 0 }).Count
        EnabledInactiveMembers= ($flat | Where-Object { $_.AccountEnabled -and $_.UserType -eq 'Member' -and $_.LastInteractiveSignIn -and $_.LastInteractiveSignIn -lt $cutoff }).Count
        EnabledNeverSignedIn  = ($flat | Where-Object { $_.AccountEnabled -and $_.UserType -eq 'Member' -and -not $_.LastInteractiveSignIn }).Count
        InactiveGuests        = ($flat | Where-Object { $_.UserType -eq 'Guest' -and (-not $_.LastInteractiveSignIn -or $_.LastInteractiveSignIn -lt $cutoff) }).Count
        PendingGuestInvites   = ($flat | Where-Object ExternalUserState -eq 'PendingAcceptance').Count
    } | Save-Evidence -Name '06-users-summary'
}

# ---------- 7. Groups ----------
Invoke-Step 'Groups' {
    Get-MgGroup -All -PageSize 999 -Property Id,DisplayName,GroupTypes,MailEnabled,SecurityEnabled,OnPremisesSyncEnabled,
        MembershipRule,MembershipRuleProcessingState,CreatedDateTime,Visibility,IsAssignableToRole,ExpirationDateTime |
        Select-Object Id, DisplayName, OnPremisesSyncEnabled, CreatedDateTime, Visibility, IsAssignableToRole, ExpirationDateTime, MembershipRule,
            @{n='Kind';e={
                if ($_.GroupTypes -contains 'Unified') { 'M365' }
                elseif ($_.GroupTypes -contains 'DynamicMembership') { 'DynamicSecurity' }
                elseif ($_.MailEnabled -and $_.SecurityEnabled) { 'MailEnabledSecurity' }
                elseif ($_.MailEnabled) { 'Distribution' }
                else { 'Security' } }},
            @{n='Dynamic';e={$_.GroupTypes -contains 'DynamicMembership'}} |
        Save-Evidence -Name '07-groups' -Csv
}

# ---------- 8. Entra devices ----------
Invoke-Step 'Entra devices' {
    $cutoff = (Get-Date).AddDays(-$StaleDays)
    $dev = Get-MgDevice -All -PageSize 999 -Property Id,DeviceId,DisplayName,OperatingSystem,OperatingSystemVersion,TrustType,
        ApproximateLastSignInDateTime,IsCompliant,IsManaged,AccountEnabled,RegistrationDateTime,ProfileType,ManagementType,EnrollmentType
    $flat = $dev | Select-Object Id, DeviceId, DisplayName, OperatingSystem, OperatingSystemVersion, AccountEnabled, IsCompliant, IsManaged,
        ApproximateLastSignInDateTime, RegistrationDateTime, ProfileType, ManagementType, EnrollmentType, TrustType,
        @{n='JoinType';e={ switch ($_.TrustType) { 'AzureAd' {'EntraJoined'} 'ServerAd' {'HybridJoined'} 'Workplace' {'Registered'} default {$_} } }},
        @{n='Stale';e={ -not $_.ApproximateLastSignInDateTime -or $_.ApproximateLastSignInDateTime -lt $cutoff }}
    $flat | Save-Evidence -Name '08-entra-devices' -Csv
    $flat | Group-Object JoinType, OperatingSystem | Select-Object Name, Count | Sort-Object Count -Descending | Save-Evidence -Name '08-entra-devices-by-join-os' -Csv
    $flat | Group-Object JoinType, Stale | Select-Object Name, Count | Save-Evidence -Name '08-entra-devices-stale' -Csv
}

# ---------- 9. Intune ----------
Invoke-Step 'Intune managed devices (beta for joinType/autopilot)' {
    Get-MgBetaDeviceManagementManagedDevice -All -PageSize 999 |
        Select-Object DeviceName, UserPrincipalName, OperatingSystem, OSVersion, SkuFamily, ComplianceState, ManagementAgent, JoinType,
            DeviceEnrollmentType, ManagedDeviceOwnerType, AutopilotEnrolled, IsEncrypted, IsSupervised, LastSyncDateTime, EnrolledDateTime,
            Manufacturer, Model, SerialNumber, AzureAdDeviceId |
        Save-Evidence -Name '09-intune-managed-devices' -Csv
}
Invoke-Step 'Intune managed devices summary' {
    $m = Import-Csv (Join-Path $Out '09-intune-managed-devices.csv')
    $m | Group-Object OperatingSystem, ManagementAgent, JoinType | Select-Object Name, Count | Sort-Object Count -Descending | Save-Evidence -Name '09-intune-summary-os-agent-join' -Csv
    $m | Group-Object OperatingSystem, ComplianceState | Select-Object Name, Count | Save-Evidence -Name '09-intune-summary-compliance' -Csv
    $m | Where-Object OperatingSystem -eq 'Windows' | Group-Object OSVersion | Select-Object Name, Count | Sort-Object Count -Descending | Save-Evidence -Name '09-intune-summary-windows-builds' -Csv
}
Invoke-Step 'Autopilot devices' {
    Get-MgDeviceManagementWindowsAutopilotDeviceIdentity -All -PageSize 999 |
        Select-Object SerialNumber, Manufacturer, Model, GroupTag, EnrollmentState, LastContactedDateTime, DeploymentProfileAssignmentStatus, ManagedDeviceId |
        Save-Evidence -Name '09-autopilot-devices' -Csv
}
Invoke-Step 'Intune compliance policies' {
    Get-MgDeviceManagementDeviceCompliancePolicy -All |
        Select-Object DisplayName, @{n='Type';e={$_.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.',''}}, CreatedDateTime, LastModifiedDateTime, Version |
        Save-Evidence -Name '09-intune-compliance-policies' -Csv
}
Invoke-Step 'Intune config profiles (templates)' {
    Get-MgDeviceManagementDeviceConfiguration -All |
        Select-Object DisplayName, @{n='Type';e={$_.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.',''}}, CreatedDateTime, LastModifiedDateTime |
        Save-Evidence -Name '09-intune-config-profiles-templates' -Csv
}
Invoke-Step 'Intune config profiles (settings catalog, beta)' {
    Get-MgBetaDeviceManagementConfigurationPolicy -All |
        Select-Object Name, Platforms, Technologies, SettingCount, CreatedDateTime, LastModifiedDateTime |
        Save-Evidence -Name '09-intune-config-profiles-settings-catalog' -Csv
}
Invoke-Step 'Intune apps' {
    Get-MgDeviceAppManagementMobileApp -All -PageSize 999 |
        Select-Object DisplayName, Publisher, @{n='Type';e={$_.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.',''}}, IsFeatured, CreatedDateTime, LastModifiedDateTime |
        Save-Evidence -Name '09-intune-apps' -Csv
}
Invoke-Step 'Apple push certificate (expiry!)' {
    Get-MgDeviceManagementApplePushNotificationCertificate | Select-Object AppleIdentifier, ExpirationDateTime, LastModifiedDateTime, TopicIdentifier |
        Save-Evidence -Name '09-apple-push-cert'
}
Invoke-Step 'Apple VPP tokens (expiry!)' {
    Get-MgDeviceAppManagementVppToken -All | Select-Object OrganizationName, AppleId, VppTokenAccountType, State, ExpirationDateTime, LastSyncDateTime, LastSyncStatus, AutomaticallyUpdateApps |
        Save-Evidence -Name '09-apple-vpp-tokens' -Csv
}

# ---------- 10. Applications and service principals ----------
Invoke-Step 'App registrations + credential expiry' {
    $now = Get-Date
    Get-MgApplication -All -PageSize 999 -Property Id,AppId,DisplayName,SignInAudience,CreatedDateTime,PasswordCredentials,KeyCredentials,PublisherDomain |
        Select-Object Id, AppId, DisplayName, SignInAudience, PublisherDomain, CreatedDateTime,
            @{n='Secrets';e={@($_.PasswordCredentials | Where-Object { $_ }).Count}},
            @{n='Certs';e={@($_.KeyCredentials | Where-Object { $_ }).Count}},
            @{n='EarliestExpiry';e={ (@($_.PasswordCredentials.EndDateTime) + @($_.KeyCredentials.EndDateTime) | Where-Object { $_ } | Sort-Object | Select-Object -First 1) }},
            @{n='ExpiredCredentials';e={ @((@($_.PasswordCredentials.EndDateTime) + @($_.KeyCredentials.EndDateTime)) | Where-Object { $_ -and $_ -lt $now }).Count }} |
        Save-Evidence -Name '10-app-registrations' -Csv
}
Invoke-Step 'Service principals' {
    $now = Get-Date
    Get-MgServicePrincipal -All -PageSize 999 -Property Id,AppId,DisplayName,AccountEnabled,ServicePrincipalType,AppOwnerOrganizationId,
        PreferredSingleSignOnMode,SignInAudience,Tags,KeyCredentials,PasswordCredentials,CreatedDateTime,AppRoleAssignmentRequired |
        Select-Object Id, AppId, DisplayName, AccountEnabled, ServicePrincipalType, AppOwnerOrganizationId, PreferredSingleSignOnMode, SignInAudience,
            AppRoleAssignmentRequired, CreatedDateTime,
            @{n='HomeTenantApp';e={$_.AppOwnerOrganizationId -eq $ctx.TenantId}},
            @{n='IsEnterpriseAppListed';e={$_.Tags -contains 'WindowsAzureActiveDirectoryIntegratedApp'}},
            @{n='SamlCertExpiry';e={ (@($_.KeyCredentials | Where-Object Usage -eq 'Verify' | Select-Object -ExpandProperty EndDateTime) | Sort-Object | Select-Object -First 1) }},
            @{n='HasExpiredCreds';e={ @((@($_.PasswordCredentials.EndDateTime) + @($_.KeyCredentials.EndDateTime)) | Where-Object { $_ -and $_ -lt $now }).Count -gt 0 }} |
        Save-Evidence -Name '10-service-principals' -Csv
}
Invoke-Step 'Graph application permissions granted to apps' {
    $graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
    $roleMap = @{}; $graphSp.AppRoles | ForEach-Object { $roleMap[$_.Id] = $_.Value }
    Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $graphSp.Id -All -PageSize 999 |
        Select-Object PrincipalDisplayName, PrincipalId, PrincipalType, @{n='Permission';e={$roleMap[$_.AppRoleId]}}, CreatedDateTime |
        Sort-Object Permission |
        Save-Evidence -Name '10-graph-app-permissions' -Csv
}
Invoke-Step 'Delegated OAuth2 grants' {
    Get-MgOauth2PermissionGrant -All -PageSize 999 |
        Select-Object ClientId, ConsentType, PrincipalId, ResourceId, Scope |
        Save-Evidence -Name '10-oauth2-delegated-grants' -Csv
}

# ---------- 11. Identity Protection (needs P2; fails gracefully on P1) ----------
Invoke-Step 'Risky users' {
    Get-MgRiskyUser -All -PageSize 999 |
        Select-Object UserPrincipalName, RiskLevel, RiskState, RiskDetail, RiskLastUpdatedDateTime, IsDeleted, IsProcessing |
        Save-Evidence -Name '11-risky-users' -Csv
}
Invoke-Step 'Risk detections (30d)' {
    $since = (Get-Date).AddDays(-30).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    Get-MgRiskDetection -All -PageSize 999 -Filter "activityDateTime ge $since" |
        Select-Object UserPrincipalName, RiskEventType, RiskLevel, RiskState, RiskDetail, DetectionTimingType, ActivityDateTime, IPAddress,
            @{n='Country';e={$_.Location.CountryOrRegion}} |
        Save-Evidence -Name '11-risk-detections-30d' -Csv
}

# ---------- 12. Legacy auth sign-ins (optional, slow; the Entra workbook is easier) ----------
if ($IncludeLegacyAuthSignIns) {
    Invoke-Step 'Legacy auth sign-ins (7d, interactive)' {
        $legacy = 'Exchange ActiveSync','IMAP4','POP3','Authenticated SMTP','Other clients','Exchange Web Services','MAPI Over HTTP',
                  'Outlook Anywhere (RPC over HTTP)','Offline Address Book','Autodiscover','Reporting Web Services','Outlook Service','Exchange Online PowerShell'
        $since = (Get-Date).AddDays(-7).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        $rows = foreach ($app in $legacy) {
            try { Get-MgAuditLogSignIn -All -PageSize 999 -Filter "createdDateTime ge $since and clientAppUsed eq '$app'" }
            catch { Write-Warning "legacy auth query failed for '$app': $($_.Exception.Message)" }
        }
        $rows | Select-Object CreatedDateTime, UserPrincipalName, AppDisplayName, ClientAppUsed, IPAddress, IsInteractive,
            @{n='ErrorCode';e={$_.Status.ErrorCode}}, @{n='Country';e={$_.Location.CountryOrRegion}} |
            Save-Evidence -Name '12-legacy-auth-signins-7d' -Csv
        $rows | Group-Object ClientAppUsed, UserPrincipalName | Select-Object Name, Count | Sort-Object Count -Descending |
            Save-Evidence -Name '12-legacy-auth-by-protocol-user' -Csv
    }
}

Stop-Transcript | Out-Null
Disconnect-MgGraph | Out-Null
Write-Host "`nDone. Evidence: $Out"
if (Test-Path (Join-Path $Out 'errors.txt')) { Write-Warning "Some steps failed. See $(Join-Path $Out 'errors.txt')" }
```

### A.2 `Get-ExoPurviewBaseline.ps1`

```powershell
#Requires -Version 7.0
<#
.SYNOPSIS
  Read-only Exchange Online + Purview baseline, plus mail DNS via dig (Resolve-DnsName is Windows-only).
.NOTES
  Module: ExchangeOnlineManagement 3.x. Roles: View-Only Organization Management (EXO) + Compliance Administrator or view-only Purview role group.
  Connect-IPPSSession on macOS: works in REST mode in my experience; if it refuses, run the Purview half from the Windows jump box.
#>
[CmdletBinding()]
param(
    [string]$Upn     = 'admin@contoso.example',
    [string]$OutRoot = "$HOME/audit/evidence",
    [switch]$SkipMailboxEnumeration   # the two 20k-row mailbox pulls take 10 to 20 minutes
)

$ErrorActionPreference = 'Stop'
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$Out   = Join-Path $OutRoot "$stamp-exo"
New-Item -ItemType Directory -Path $Out -Force | Out-Null
Start-Transcript -Path (Join-Path $Out 'transcript.txt') | Out-Null

function Save-Evidence {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)] $InputObject, [Parameter(Mandatory)] [string] $Name, [switch] $Csv)
    begin { $items = [System.Collections.Generic.List[object]]::new() }
    process { if ($null -ne $InputObject) { $items.Add($InputObject) } }
    end {
        $items | ConvertTo-Json -Depth 8 -WarningAction SilentlyContinue | Set-Content -Path (Join-Path $Out "$Name.json")
        if ($Csv) { $items | Export-Csv -Path (Join-Path $Out "$Name.csv") -NoTypeInformation }
        Write-Host ("{0,-42} {1,7:N0}" -f $Name, $items.Count)
    }
}
function Invoke-Step {
    param([string]$Label, [scriptblock]$Script)
    try { & $Script }
    catch { Write-Warning "$Label failed: $($_.Exception.Message)"; Add-Content -Path (Join-Path $Out 'errors.txt') -Value "$Label :: $($_.Exception.Message)" }
}

# ---------- Exchange Online ----------
Connect-ExchangeOnline -UserPrincipalName $Upn -ShowBanner:$false

Invoke-Step 'Org config' {
    Get-OrganizationConfig | Select-Object Name, OAuth2ClientProfileEnabled, DefaultAuthenticationPolicy, AuditDisabled, IsDehydrated,
        SendFromAliasEnabled, FocusedInboxOn, MailTipsAllTipsEnabled, DefaultPublicFolderMailbox, EwsEnabled, EwsApplicationAccessPolicy,
        ActivityBasedAuthenticationTimeoutEnabled, ActivityBasedAuthenticationTimeoutInterval, OutlookMobileGCCRestrictionsEnabled |
        Save-Evidence -Name 'exo-01-orgconfig'
}
Invoke-Step 'Authentication policies'    { Get-AuthenticationPolicy | Save-Evidence -Name 'exo-01-auth-policies' }
Invoke-Step 'Audit config'               { Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled, UnifiedAuditLogFirstOptInDate, AdminAuditLogEnabled | Save-Evidence -Name 'exo-01-audit-config' }
Invoke-Step 'Accepted domains'           { Get-AcceptedDomain | Select-Object DomainName, DomainType, Default, AuthenticationType, InitialDomain | Save-Evidence -Name 'exo-02-accepted-domains' -Csv }
Invoke-Step 'DKIM'                       { Get-DkimSigningConfig | Select-Object Domain, Enabled, Status, Selector1CNAME, Selector2CNAME, LastChecked | Save-Evidence -Name 'exo-02-dkim' -Csv }
Invoke-Step 'Inbound connectors' {
    Get-InboundConnector | Select-Object Name, Enabled, ConnectorType, ConnectorSource, RestrictDomainsToIPAddresses, RestrictDomainsToCertificate,
        TreatMessagesAsInternal, EFSkipLastIP, @{n='EFSkipIPs';e={$_.EFSkipIPs -join ';'}}, @{n='SenderIPAddresses';e={$_.SenderIPAddresses -join ';'}},
        @{n='SenderDomains';e={$_.SenderDomains -join ';'}}, TlsSenderCertificateName, WhenChanged |
        Save-Evidence -Name 'exo-03-inbound-connectors'
}
Invoke-Step 'Outbound connectors' {
    Get-OutboundConnector | Select-Object Name, Enabled, ConnectorType, UseMXRecord, @{n='SmartHosts';e={$_.SmartHosts -join ';'}},
        @{n='RecipientDomains';e={$_.RecipientDomains -join ';'}}, TlsSettings, TlsDomain, RouteAllMessagesViaOnPremises, WhenChanged |
        Save-Evidence -Name 'exo-03-outbound-connectors'
}
Invoke-Step 'Transport rules (look for SetSCL -1)' {
    Get-TransportRule -ResultSize Unlimited | Select-Object Name, State, Priority, Mode, SetSCL, @{n='SenderIpRanges';e={$_.SenderIpRanges -join ';'}},
        FromScope, SentToScope, @{n='HeaderContains';e={$_.HeaderContainsMessageHeader}}, Description, WhenChanged |
        Save-Evidence -Name 'exo-03-transport-rules' -Csv
}
Invoke-Step 'EOP: content filter'        { Get-HostedContentFilterPolicy | Save-Evidence -Name 'exo-04-eop-content-filter' }
Invoke-Step 'EOP: connection filter'     { Get-HostedConnectionFilterPolicy | Save-Evidence -Name 'exo-04-eop-connection-filter' }
Invoke-Step 'EOP: anti-malware'          { Get-MalwareFilterPolicy | Save-Evidence -Name 'exo-04-eop-malware' }
Invoke-Step 'Anti-phish'                 { Get-AntiPhishPolicy | Save-Evidence -Name 'exo-04-antiphish' }
Invoke-Step 'Outbound spam'              { Get-HostedOutboundSpamFilterPolicy | Save-Evidence -Name 'exo-04-outbound-spam' }
Invoke-Step 'Preset policy rules (EOP)'  { Get-EOPProtectionPolicyRule | Select-Object Name, State, Priority, SentTo, SentToMemberOf, RecipientDomainIs | Save-Evidence -Name 'exo-04-preset-rules-eop' }
Invoke-Step 'Preset policy rules (MDO)'  { Get-ATPProtectionPolicyRule | Select-Object Name, State, Priority, SentTo, SentToMemberOf, RecipientDomainIs | Save-Evidence -Name 'exo-04-preset-rules-mdo' }
Invoke-Step 'MDO: Safe Links'            { Get-SafeLinksPolicy | Save-Evidence -Name 'exo-05-mdo-safelinks' }
Invoke-Step 'MDO: Safe Attachments'      { Get-SafeAttachmentPolicy | Save-Evidence -Name 'exo-05-mdo-safeattachments' }
Invoke-Step 'MDO: global settings'       { Get-AtpPolicyForO365 | Save-Evidence -Name 'exo-05-mdo-global' }
Invoke-Step 'Quarantine policies'        { Get-QuarantinePolicy | Select-Object Name, EndUserQuarantinePermissions, ESNEnabled, QuarantinePolicyType | Save-Evidence -Name 'exo-05-quarantine-policies' }
Invoke-Step 'Remote domains'             { Get-RemoteDomain | Select-Object Name, DomainName, AutoForwardEnabled, AutoReplyEnabled, AllowedOOFType, TNEFEnabled | Save-Evidence -Name 'exo-06-remote-domains' -Csv }
Invoke-Step 'Sharing policies'           { Get-SharingPolicy | Save-Evidence -Name 'exo-06-sharing-policies' }
Invoke-Step 'OWA mailbox policies'       { Get-OwaMailboxPolicy | Select-Object Name, IsDefault, OfflineEnabledWin, OfflineEnabledWeb, ThirdPartyFileProvidersEnabled, ConditionalAccessPolicy, LinkedInEnabled, OutlookBetaToggleEnabled | Save-Evidence -Name 'exo-06-owa-policies' }
Invoke-Step 'ActiveSync org settings'    { Get-ActiveSyncOrganizationSettings | Save-Evidence -Name 'exo-07-eas-org-settings' }
Invoke-Step 'Mobile device mailbox pols' { Get-MobileDeviceMailboxPolicy | Save-Evidence -Name 'exo-07-mobile-device-policies' }
Invoke-Step 'Role groups'                { Get-RoleGroup | Select-Object Name, @{n='Members';e={$_.Members -join ';'}}, @{n='Roles';e={$_.Roles -join ';'}} | Save-Evidence -Name 'exo-08-role-groups' }

if (-not $SkipMailboxEnumeration) {
    Invoke-Step 'Mailboxes (type, holds, forwarding)' {
        $mbx = Get-EXOMailbox -ResultSize Unlimited -Properties RecipientTypeDetails,LitigationHoldEnabled,InPlaceHolds,ArchiveStatus,ForwardingSmtpAddress,
            ForwardingAddress,DeliverToMailboxAndForward,AuditEnabled,WhenCreated,WhenMailboxCreated |
            Select-Object UserPrincipalName, DisplayName, RecipientTypeDetails, LitigationHoldEnabled, @{n='InPlaceHoldCount';e={@($_.InPlaceHolds | Where-Object { $_ }).Count}},
                ArchiveStatus, ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward, AuditEnabled, WhenMailboxCreated
        $mbx | Save-Evidence -Name 'exo-09-mailboxes' -Csv
        $mbx | Group-Object RecipientTypeDetails | Select-Object Name, Count | Save-Evidence -Name 'exo-09-mailboxes-by-type' -Csv
        $mbx | Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress } | Save-Evidence -Name 'exo-09-mailboxes-with-forwarding' -Csv
    }
    Invoke-Step 'CAS mailbox protocols' {
        $cas = Get-EXOCASMailbox -ResultSize Unlimited -Properties ActiveSyncEnabled,ImapEnabled,PopEnabled,SmtpClientAuthenticationDisabled,OWAEnabled,MAPIEnabled,EwsEnabled |
            Select-Object PrimarySmtpAddress, ActiveSyncEnabled, ImapEnabled, PopEnabled, SmtpClientAuthenticationDisabled, OWAEnabled, MAPIEnabled, EwsEnabled
        $cas | Save-Evidence -Name 'exo-10-cas-mailboxes' -Csv
        [pscustomobject]@{
            Total                     = $cas.Count
            ImapEnabled               = ($cas | Where-Object ImapEnabled).Count
            PopEnabled                = ($cas | Where-Object PopEnabled).Count
            ActiveSyncEnabled         = ($cas | Where-Object ActiveSyncEnabled).Count
            SmtpAuthExplicitlyEnabled = ($cas | Where-Object { $_.SmtpClientAuthenticationDisabled -eq $false }).Count
        } | Save-Evidence -Name 'exo-10-cas-summary'
    }
}

# ---------- Mail DNS via dig ----------
Invoke-Step 'Mail DNS (MX/SPF/DMARC)' {
    $domains = (Get-AcceptedDomain | Where-Object DomainType -eq 'Authoritative').DomainName
    $dns = foreach ($d in $domains) {
        [pscustomobject]@{
            Domain = $d
            MX     = ((& dig +short MX $d) -join ' | ')
            SPF    = (((& dig +short TXT $d) | Where-Object { $_ -match 'v=spf1' }) -join '')
            DMARC  = ((& dig +short TXT "_dmarc.$d") -join '')
        }
    }
    $dns | Save-Evidence -Name 'dns-01-mail-records' -Csv
}

Disconnect-ExchangeOnline -Confirm:$false | Out-Null

# ---------- Purview (Security & Compliance PowerShell) ----------
Connect-IPPSSession -UserPrincipalName $Upn

Invoke-Step 'Sensitivity labels'         { Get-Label | Select-Object DisplayName, Name, Guid, Priority, ContentType, ParentId, Disabled, Tooltip | Save-Evidence -Name 'pv-01-sensitivity-labels' -Csv }
Invoke-Step 'Label policies'             { Get-LabelPolicy | Select-Object Name, Enabled, Mode, Type, @{n='Labels';e={$_.Labels -join ';'}}, @{n='Workload';e={$_.Workload}}, WhenChanged | Save-Evidence -Name 'pv-01-label-policies' }
Invoke-Step 'Auto-labeling policies'     { Get-AutoSensitivityLabelPolicy | Select-Object Name, Enabled, Mode, ApplySensitivityLabel, @{n='Workload';e={$_.Workload}}, WhenChanged | Save-Evidence -Name 'pv-01-autolabel-policies' }
Invoke-Step 'DLP policies'               { Get-DlpCompliancePolicy | Select-Object Name, Enabled, Mode, Priority, @{n='Workload';e={$_.Workload}}, WhenCreated, WhenChanged | Save-Evidence -Name 'pv-02-dlp-policies' -Csv }
Invoke-Step 'DLP rules'                  { Get-DlpComplianceRule | Select-Object Name, ParentPolicyName, Disabled, Priority, ReportSeverityLevel, BlockAccess, NotifyUser | Save-Evidence -Name 'pv-02-dlp-rules' -Csv }
Invoke-Step 'Retention policies'         { Get-RetentionCompliancePolicy -DistributionDetail | Select-Object Name, Enabled, Mode, @{n='Workload';e={$_.Workload}}, DistributionStatus, RestrictiveRetention, WhenChanged | Save-Evidence -Name 'pv-03-retention-policies' -Csv }
Invoke-Step 'Retention rules'            { Get-RetentionComplianceRule | Select-Object Name, Policy, RetentionDuration, RetentionComplianceAction, ExpirationDateOption, Disabled | Save-Evidence -Name 'pv-03-retention-rules' -Csv }
Invoke-Step 'Retention labels'           { Get-ComplianceTag | Select-Object Name, RetentionAction, RetentionDuration, RetentionType, IsRecordLabel, IsRegulatoryRecord | Save-Evidence -Name 'pv-03-retention-labels' -Csv }
Invoke-Step 'Insider Risk policies'      { Get-InsiderRiskPolicy | Select-Object Name, Enabled, InsiderRiskScenario, WhenChanged | Save-Evidence -Name 'pv-04-insider-risk-policies' }
Invoke-Step 'Communication Compliance'   { Get-SupervisoryReviewPolicyV2 | Select-Object Name, Enabled, WhenChanged | Save-Evidence -Name 'pv-04-communication-compliance' }
Invoke-Step 'Information barriers'       { Get-InformationBarrierPolicy | Select-Object Name, State, AssignedSegment, SegmentsBlocked, SegmentsAllowed | Save-Evidence -Name 'pv-04-information-barriers' }
Invoke-Step 'Audit retention policies'   { Get-UnifiedAuditLogRetentionPolicy | Select-Object Name, Priority, RetentionDuration, @{n='RecordTypes';e={$_.RecordTypes -join ';'}}, @{n='UserIds';e={$_.UserIds -join ';'}} | Save-Evidence -Name 'pv-05-audit-retention-policies' }
Invoke-Step 'eDiscovery searches'        { Get-ComplianceSearch | Select-Object Name, Status, CreatedTime, CreatedBy, CaseName | Save-Evidence -Name 'pv-06-ediscovery-searches' -Csv }
Invoke-Step 'eDiscovery cases'           { Get-ComplianceCase | Select-Object Name, Status, CaseType, CreatedDateTime | Save-Evidence -Name 'pv-06-ediscovery-cases' -Csv }
Invoke-Step 'Alert policies'             { Get-ProtectionAlert | Select-Object Name, Disabled, Severity, Category, ThreatType, IsSystemRule | Save-Evidence -Name 'pv-07-alert-policies' -Csv }
Invoke-Step 'Purview role groups'        { Get-RoleGroup | Select-Object Name, @{n='Members';e={$_.Members -join ';'}}, @{n='Roles';e={$_.Roles -join ';'}} | Save-Evidence -Name 'pv-08-role-groups' }

Disconnect-ExchangeOnline -Confirm:$false | Out-Null
Stop-Transcript | Out-Null
Write-Host "`nDone. Evidence: $Out"
if (Test-Path (Join-Path $Out 'errors.txt')) { Write-Warning "Some steps failed. See $(Join-Path $Out 'errors.txt')" }
```

### A.3 SharePoint (PnP) and Teams snippets

PnP needs a one-time app registration by someone with Application Administrator rights, then it's a normal interactive login:

```powershell
# One time, by an admin who can register apps (or ask them to run it and hand you the ClientId):
Register-PnPEntraIDAppForInteractiveLogin -ApplicationName 'PnP-Audit-ReadOnly' -Tenant '<tenant>.onmicrosoft.com' -Interactive

# Then, each run:
Connect-PnPOnline -Url 'https://<tenant>-admin.sharepoint.com' -Interactive -ClientId '<app id>'

Get-PnPTenant | Select-Object SharingCapability, DefaultSharingLinkType, DefaultLinkPermission, RequireAnonymousLinksExpireInDays,
    FileAnonymousLinkType, FolderAnonymousLinkType, OneDriveSharingCapability, SharingDomainRestrictionMode, SharingAllowedDomainList,
    SharingBlockedDomainList, ExternalUserExpirationRequired, ExternalUserExpireInDays, ShowEveryoneClaim, ShowEveryoneExceptExternalUsersClaim,
    ShowAllUsersClaim, LegacyAuthProtocolsEnabled, ConditionalAccessPolicy, EnableRestrictedAccessControl, EnableAzureADB2BIntegration,
    PreventExternalUsersFromResharing, NotifyOwnersWhenItemsReshared |
    ConvertTo-Json | Set-Content ~/audit/evidence/spo-tenant-settings.json

Get-PnPTenantSite -IncludeOneDriveSites -Detailed |
    Select-Object Url, Title, Template, SharingCapability, StorageUsageCurrent, LastContentModifiedDate, Owner, GroupId, SensitivityLabel,
        LockState, RestrictedAccessControl, DenyAddAndCustomizePages |
    Export-Csv ~/audit/evidence/spo-sites.csv -NoTypeInformation
# At 20k users this is 20k+ OneDrives plus team sites; run it once, it can take 30+ minutes.
# The "Everyone" / anonymous-link / oversharing views come from SAM data access governance reports or the Microsoft 365 Assessment tool.
```

Teams (MicrosoftTeams module, PS7; cross-platform in recent versions **(verify on first run)**):

```powershell
Connect-MicrosoftTeams
Get-CsTenantFederationConfiguration | ConvertTo-Json -Depth 5 | Set-Content ~/audit/evidence/teams-federation.json
Get-CsTeamsClientConfiguration     | ConvertTo-Json -Depth 5 | Set-Content ~/audit/evidence/teams-client-config.json
Get-CsTeamsMeetingPolicy -Identity Global | ConvertTo-Json -Depth 5 | Set-Content ~/audit/evidence/teams-meeting-policy-global.json
Get-CsExternalAccessPolicy          | ConvertTo-Json -Depth 5 | Set-Content ~/audit/evidence/teams-external-access.json
Get-CsTeamsAppPermissionPolicy      | ConvertTo-Json -Depth 5 | Set-Content ~/audit/evidence/teams-app-permission-policies.json
Get-CsTeamsGuestMessagingConfiguration | ConvertTo-Json | Set-Content ~/audit/evidence/teams-guest-messaging.json
```

### A.4 Maester and Zero Trust Assessment

```powershell
# Maester (Pester-based Entra/Intune/EXO security tests incl. EIDSCA). Produces an HTML report you can keep as the day-one baseline.
New-Item -ItemType Directory -Path ~/audit/maester -Force | Out-Null
Set-Location ~/audit/maester
Install-MaesterTests
Connect-Maester
Invoke-Maester -OutputFolder ~/audit/evidence/maester

# Microsoft Zero Trust Assessment (cmdlet names per the module README; verify before running)
Connect-ZtAssessment
Invoke-ZtAssessment -Path ~/audit/evidence/zt-assessment
```

---

## Appendix B. Windows jump box checklist (AD, GPO, Entra Connect, ADFS, SCCM)

These need RSAT / the product's own module and won't run from the Mac. Ask me for full scripts once you know what's installed on the jump box; the list below is what to pull.

**Active Directory** (`ActiveDirectory` module, PingCastle, Purple Knight)

- `Get-ADForest`, `Get-ADDomain`: functional levels, FSMO, domains, trusts (`Get-ADTrust -Filter *`).
- DCs: `Get-ADDomainController -Filter * | Select Name, OperatingSystem, OperatingSystemVersion, Site, IsGlobalCatalog, IsReadOnly`.
- Privileged groups: members of Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Backup Operators, Server Operators, Print Operators (recursive), and `adminCount=1` users.
- krbtgt: `Get-ADUser krbtgt -Properties PasswordLastSet`.
- Kerberoastable: `Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName, PasswordLastSet, msDS-SupportedEncryptionTypes`.
- Delegation: `Get-ADComputer -Filter {TrustedForDelegation -eq $true}`, `Get-ADUser -Filter {TrustedForDelegation -eq $true}`, `msDS-AllowedToDelegateTo`.
- Encryption: `msDS-SupportedEncryptionTypes` on computers and service accounts (RC4 exposure), domain default encryption GPO.
- Password policy: `Get-ADDefaultDomainPasswordPolicy`, `Get-ADFineGrainedPasswordPolicy -Filter *`.
- LAPS: `ms-Mcs-AdmPwd` (legacy) vs `msLAPS-Password` attribute presence; `Get-LapsADComputer` where Windows LAPS is in use.
- Stale objects: users and computers with `LastLogonTimestamp` older than 90/180 days, enabled.
- Computer OS distribution: `Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion, LastLogonTimestamp | Group OperatingSystem`.
- Entra Kerberos: `Get-ADComputer AzureADKerberos -Server <domain>` (exists = cloud Kerberos trust prerequisite done).
- ADCS: `certutil -dump`, templates with enrollee-supplies-subject + client auth (ESC1), Locksmith module, who can enroll.
- Protected Users group membership, AdminSDHolder ACL, domain root ACL (DCSync rights).
- PingCastle full report; Purple Knight report. Both are free and give exec-friendly scoring.

**Group Policy** (`GroupPolicy` module)

- `Get-GPO -All | Select DisplayName, GpoStatus, CreationTime, ModificationTime, @{n='Links';e={...}}` plus `Get-GPOReport -All -ReportType Xml` for Intune Group Policy Analytics import.
- Unlinked GPOs, GPOs with no settings, GPOs linked at domain root, login scripts, drive maps, printer deployments, WMI filters.

**Entra Connect** (on the sync server, `ADSync` module)

- `Get-ADSyncScheduler`, `Get-ADSyncGlobalSettings`, `Get-ADSyncConnector | Select Name, Type`, `Get-ADSyncRule | Where { -not $_.IsStandardRule }` (custom rules), `Get-ADSyncAADCompanyFeature` (writeback features), `Get-ADSyncAutoUpgrade`, OU filtering via the Sync Service Manager, staging mode state, version from Add/Remove Programs.
- Who can log on to the server, is it in Tier 0, where is the config backup.

**ADFS** (if present)

- `Get-AdfsProperties`, `Get-AdfsRelyingPartyTrust | Select Name, Enabled, Identifier, LastUpdateTime` (every row is a migration item), `Get-AdfsCertificate` (expiry), `Get-AdfsClaimsProviderTrust`, WAP servers, extranet lockout config, ADFS sign-in logs for last-30-day usage per RP.

**SCCM** (`ConfigurationManager` module on a console machine, or SQL views)

- Site: `Get-CMSite` (version, build), `Get-CMSiteRole`/distribution points, SQL version.
- Clients: `Get-CMDevice -Fast | Measure`, client health dashboard, co-management state per device (`CoManaged`, `ClientState`), `Get-CMCoManagementPolicy` **(verify cmdlet; it's `Get-CMCoManagementPolicy` in recent builds)** for enabled workloads.
- Content: `Get-CMApplication | Measure`, `Get-CMPackage | Measure`, `Get-CMTaskSequence | Measure`, `Get-CMSoftwareUpdateDeployment`, `Get-CMBaseline | Measure`, `Get-CMCollection | Measure`.
- Admins: `Get-CMAdministrativeUser`.
- Servers in scope: devices where OperatingSystem like '%Server%'.

**[MFA vendor], [DNS filter], [mail gateway], [EDR vendor]**: admin console exports. [MFA vendor]: Applications list CSV + policy export. [DNS filter]: deployment report, policy list, top categories. [mail gateway]: module list, policy routes, TAP dashboard, DMARC/EFD status. [EDR vendor]: endpoints export by OS/agent version, policy, exclusions.

---

## Appendix C. Interview question bank

**Sponsor / IT leadership**

- Why this program, why now, what was promised to the board and when.
- Budget envelope, EA anniversary, appetite for E5 and Suites.
- What's untouchable (politically or contractually) for the next 12 months.
- Who has said no to similar things before, and why.
- Change management process, CAB cadence, who signs off on identity changes.

**Identity / AD team**

- Walk me through a new hire from HR record to first login. Then a termination.
- How does someone get an admin role today? Who approves? How often reviewed?
- Where do the break-glass credentials live, when were they last tested?
- PHS/PTA/ADFS: why the current choice? Any plan to retire ADFS?
- What breaks if Entra Connect is down for a day?
- Any known AD hygiene debt (RC4, old DCs, no tiering)?

**Endpoint / SCCM team**

- What does SCCM do that you'd miss? OSD, patching, apps, inventory, compliance, reporting?
- How many packaged apps are actively deployed vs. dead?
- What's the hardware refresh cycle and the current average device age?
- Any co-management or Intune work already started? What stalled?
- How are Macs managed? How many?
- Servers under SCCM: how many, what's the plan?
- Local admin: who has it, why?

**Mac admins**

- Jamf or Intune or neither? ADE through Apple Business Manager? Platform SSO deployed?
- Are users local admins? Any temporary-admin tooling? FileVault keys escrowed where?
- How do Macs satisfy Conditional Access today (compliance connector, or not at all)?

**Linux / developer leads**

- How many Ubuntu laptops, which LTS versions, who images and supports them?
- What manages them (Intune, Landscape, Ansible, nothing)? EDR installed? Disk encrypted?
- Sudo model: everyone in sudoers? NOPASSWD? Root Docker? Any logging?
- What do devs reach over VPN today (repos, build systems, Kubernetes, databases, cloud consoles)? Which of those have MFA and CA in front of them?
- Would an approval-based elevation flow be tolerated, and what would make devs route around it?
- Has application allowlisting ever been tried on dev machines? What happened?

**Helpdesk lead**

- Monthly tickets for: password reset, MFA/[MFA vendor], device enrollment, access requests, app issues, "I need admin to install X."
- How do you verify identity before resetting a password or MFA method?
- What's the worst recurring ticket class?

**Network team**

- [DNS filter]: which features, which devices, who reads the reports?
- VPN: concurrency, always-on, what's reached through it, MFA method.
- Office Wi-Fi: 802.1X cert source, NAC.
- Any SASE/ZTNA plans or vendor commitments already made?

**Security / SOC / MDR**

- What's in the SIEM, what's not, retention, cost, who triages.
- [EDR vendor]: why [EDR vendor], how is it working, who would object to MDE.
- Incident history last 24 months. Phishing click rates.
- Who owns Secure Score today? (Usually nobody.)

**Messaging**

- [mail gateway] modules and what you'd fight to keep.
- Mail flow diagram. Any on-prem Exchange left and why.
- DMARC posture and who owns third-party senders.

**Collaboration / SharePoint**

- External sharing: who decided the current settings, any incidents.
- Site provisioning process, ownership model, ownerless site count.
- Copilot: licensed, piloted, any oversharing assessment done?
- Any labels or DLP ever attempted? What happened?

**HRIS owner**

- System of record, how changes flow to IT today, what fields exist (manager, cost center, location, worker type, start/end dates), contractor handling, data quality.

**Legal / Privacy / Records**

- Retention schedule exists? Who owns it?
- Legal holds active? Regulatory frameworks in scope.
- BYOD policy, employee monitoring stance, works council / union constraints, privacy notices required for Insider Risk.

**App owners (top 20 by users)**

- How do users authenticate? Who provisions accounts? Who removes them? SAML cert owner? Any API/SCIM available?

---

## Appendix D. Contract and renewal matrix

| Vendor / product | Scope | Annual cost | Term end | Auto-renew | Notice period | Replaced by | Decision needed by |
|---|---|---|---|---|---|---|---|
| Microsoft EA | E3 + add-ons | | | | | E5 (+ Suites) | EA anniversary minus 90 days |
| [MFA vendor] | MFA, SSO?, device trust? | | | | | Authenticator, WHfB, CA | |
| [DNS filter] | DNS / SIG | | | | | Per 6.4: GSA + MDE + firewall DNS, or Cloudflare One | |
| Cloudflare One (candidate) | SWG / DNS / ZTNA incl. Linux | | | | | n/a (replacement) | |
| ThreatLocker (candidate) | Allowlisting / elevation / host firewall | | | | | n/a (new; vs Admin By Request, BeyondTrust, CyberArk EPM) | |
| [EDR vendor] | EDR (clients, servers, Mac?) | | | | | MDE P2 + Defender for Servers | |
| [mail gateway] | Email security, archive?, encryption?, awareness? | | | | | MDO P2, Purview | |
| VPN | | | | | | GSA Private Access | |
| SIEM | | | | | | Sentinel | |
| Jamf / Mac MDM (if separate) | | | | | | Intune, or keep with compliance connector | |
| Linux management (Landscape etc.) | | | | | | Intune Linux enrollment or keep | |
| PAM / IGA (if any) | | | | | | Entra ID Governance / PIM | |
| Backup (M365) | | | | | | Microsoft 365 Backup or keep | |
| Certificate authority | | | | | | Intune Cloud PKI | |

---

## Appendix E. Findings tracker and evidence layout

Findings tracker (keep it in a sheet or a `findings.csv` next to this file; one row per finding):

| ID | Workstream | Finding | Evidence | Likelihood 1-5 | Impact 1-5 | Risk | Effort S/M/L/XL | Dependency | Quick win | Bucket | Owner | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F-001 | W2 | Example: 14 permanent Global Admins, 6 synced from AD | 04-role-assignments-active.csv | 4 | 5 | 20 | S | none | Y | Stop the bleeding | | Open |

Evidence folder layout:

```
~/audit/
  m365-environment-audit-plan.md        (this file)
  findings.csv
  decisions.md                          (decision log: date, decision, who, why)
  status/                               (weekly one-pagers)
  evidence/
    20261013-0900/                      (A.1 run)
    20261013-1100-exo/                  (A.2 run)
    maester/
    zt-assessment/
    jumpbox/                            (AD, GPO, SCCM, PingCastle exports)
    vendor-exports/                     ([MFA vendor], [DNS filter], [mail gateway], [EDR vendor])
    interviews/                         (notes per stakeholder)
    contracts/
```

---

## Appendix F. Sources for platform-support claims (checked 2026-10-09)

- GSA clients (Windows, Android, macOS, iOS; no Linux): https://learn.microsoft.com/en-us/entra/global-secure-access/concept-clients
- Intune in-development page (EPM Windows-only; Linux additions limited to Defender update settings): https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/in-development
- MDE network protection for Linux (preview, servers, insiders channel): https://learn.microsoft.com/en-us/defender-endpoint/network-protection-linux
- ThreatLocker product list: https://www.threatlocker.com/llms.txt
- ThreatLocker Web Control: https://threatlocker.com/platform/web-control
- ThreatLocker supported Linux versions: https://threatlocker.kb.help/supported-linux-versions/
- Cloudflare One client platforms: https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/warp/
- Cloudflare Entra ID integration (IdP + SCIM): https://developers.cloudflare.com/cloudflare-one/identity/idp-integration/entra-id/
- Cloudflare device posture service providers (Microsoft Endpoint Manager, Workspace ONE): https://developers.cloudflare.com/cloudflare-one/identity/devices/service-providers/
- Microsoft single sign-on for Linux (Entra join, Intune, CA, PRMFA, supported distros): https://learn.microsoft.com/en-us/entra/identity/devices/sso-linux
- What's new in Microsoft single sign-on for Linux (3.0.1 GA March 31, 2026; 3.0.2 April 27, 2026): https://learn.microsoft.com/en-us/entra/identity/devices/whats-new-linux

---

## Open inputs that would sharpen v0.4

- HRIS platform and whether any IGA/IAM product sits between HR and AD today.
- SIEM in place (Sentinel, Splunk, other) and who runs the SOC.
- Mac share of the fleet and how Macs are managed (Jamf vs Intune vs nothing).
- Linux headcount, what the developers reach over VPN, and whether "Linux privilege" means laptop sudo, server access, or both.
- Whether anyone has appetite for default-deny application allowlisting, or only for elevation approvals (changes the W13 shortlist).
- Copilot status: licensed, piloted, or not yet.
- Hard dates: EA anniversary, [MFA vendor]/[DNS filter]/[EDR vendor]/[mail gateway] term ends, any board or audit deadlines.
- Team: who, if anyone, is helping you run the audit.

