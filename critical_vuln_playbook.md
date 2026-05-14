# Critical Vulnerability as Cyber Incident — IR Playbook
### Financial Institution · Generalized Framework

> **Trigger:** CISA KEV + CVSS ≥ 9.0 + confirmed bank exposure  
> **Aligned to:** NIST SP 800-61r3 · CSF 2.0 · FFIEC · NY DFS Part 500  
> **Teams:** Incident Response · Vulnerability Management · Cyber Threat Intelligence · Cyber Threat Response (SOC) · Cloud & Network Services · Cloud & Application Defense

---

## Section 1 — The Core Concept: Two Parallel Tracks

A critical CVE with known in-the-wild exploitation and confirmed bank exposure is **both a patching problem and a cyber incident**. These are not the same activity and should not be owned by the same team simultaneously.

**Analogy:** Like a hospital discovering a contaminated blood supply. The clinical team identifies affected patients and administers treatment (VM = scan, patch, re-scan). A separate investigation team determines whether patients were already harmed and contains the damage (IR = compromise assessment, threat hunt, containment).

**The two tracks run in parallel — neither blocks the other.**

| Track | Owned by | Focus |
|-------|----------|-------|
| VM Track | Vulnerability Management | Advisory triage → Tenable scan → patch → verify → re-scan |
| IR Track | Incident Response | Incident open → CTI brief → threat hunt → appliance investigation → network mitigation → closure |

### Activation Criteria — all three must be met

1. CVE is on CISA KEV catalog **or** has confirmed active exploitation per vendor advisory / CTI feeds
2. CVSS base score ≥ 9.0 **or** vendor severity = Critical
3. VM team has confirmed ≥1 bank asset is exposed (Tenable positive or asset inventory match)

> If criteria 1 and 2 are met but 3 is pending: activate **watchlist posture** — CTI monitoring, SOC alert tuning, no full IR track yet.

> **⚠ Library-level CVE exception (Log4Shell class):** For CVEs in embedded libraries (Log4j2, Spring, OpenSSL, etc.), Tenable infrastructure scans may return false negatives — the vulnerable component lives inside an application's transitive dependency, invisible to a network scan. If the CVE affects a widely-embedded library, activate the IR track on criteria 1 and 2 alone, then run a parallel SBOM-driven discovery track (see Phase 1, step 1.5) rather than waiting for Tenable to confirm. A negative Tenable result is not definitive for library-level CVEs.

---

## Section 2 — Team Roles & Responsibilities

### 🔴 Incident Response (IR)
- Incident commander for the IR track
- Opens and owns the incident ticket (`CRITVAL-[CVE-ID]-[YYYY-MM-DD]`)
- Coordinates all non-VM response teams
- Drives compromise assessment workstreams
- Leadership communication and escalation
- Evidence preservation; closure and lessons learned

### 🟢 Vulnerability Management (VM)
- Receives and assesses the advisory
- Runs Tenable scans to confirm exposure
- Determines exploitability in bank context
- Briefs IR on exposed asset inventory
- Coordinates and tracks patching, re-scanning
- Communicates patch status to IR throughout

### 🟣 Cyber Threat Intelligence (CTI)
- Produces CVE threat actor and TTP assessment
- Searches dark web / FS-ISAC for bank-specific exposure
- Develops threat hunt hypotheses for SOC
- Provides IOCs, TTPs, actor attribution
- Monitors continuously and notifies IR of new exploitation evidence

### 🔵 Cyber Threat Response / SOC
- Executes SIEM/EDR threat hunts from CTI hypotheses
- Monitors for exploitation IOCs on affected asset classes
- Reviews authentication / session logs
- Escalates confirmed indicators to IR immediately

### 🩵 Cloud & Network Services (Net/FW)
- Implements emergency network mitigations (WAF, ACLs, FW rules)
- Restricts access to exposed services per IR direction
- Provides network telemetry to SOC/IR
- Implements and documents compensating controls
- Supports isolation of compromised assets if needed

### 🟡 Cloud & Application Defense (AppD)
- Investigates specific appliances and platforms (Citrix, Palo Alto, Ivanti, etc.)
- Pulls and reviews appliance telemetry and logs
- Validates configuration and hardening status
- Implements application-layer compensating controls
- Provides platform expertise and forensic support

---

## Section 3 — RACI Matrix

**R** = Responsible · **A** = Accountable · **C** = Consulted · **I** = Informed

| Activity | IR | VM | CTI | SOC | Net/FW | AppD | Mgmt |
|----------|----|----|-----|-----|--------|------|------|
| **ADVISORY RECEIPT & ASSESSMENT** | | | | | | | |
| Receive and parse advisory / CISA KEV | A | R | C | I | I | I | I |
| Determine exposure via Tenable scan | I | R/A | I | I | I | C | I |
| Assess exploitability in bank context | C | R/A | C | I | I | C | I |
| Decision: activate IR track | R/A | C | C | I | I | I | C |
| Brief leadership — initial notification | R/A | C | C | I | I | I | I |
| **THREAT INTELLIGENCE & HUNT** | | | | | | | |
| Produce CVE threat actor assessment | I | I | R/A | C | I | I | I |
| Search FS-ISAC / dark web for bank exposure | I | I | R/A | I | I | I | I |
| Develop threat hunt hypotheses | C | I | R/A | C | I | I | I |
| Execute SIEM/EDR threat hunt | C | I | C | R/A | I | I | I |
| Review auth / session logs on affected assets | C | I | I | R/A | I | C | I |
| **NETWORK & ACCESS MITIGATION** | | | | | | | |
| Determine compensating controls | A | C | C | I | R | C | I |
| Implement emergency firewall / ACL / WAF | A | I | I | I | R | I | I |
| Investigate specific appliances | A | I | I | C | C | R | I |
| Pull and analyze appliance telemetry | A | I | I | C | I | R | I |
| **REMEDIATION & CLOSURE** | | | | | | | |
| Coordinate and execute patching | I | R/A | I | I | C | C | I |
| Verification re-scan (Tenable) | I | R/A | I | I | I | I | I |
| Determine incident closure criteria | R/A | C | C | C | I | I | C |
| Executive / regulatory reporting | R/A | C | I | I | I | I | C |

---

## Section 4 — Threat Context: Why Banks Are Primary Targets

Based on current threat intelligence and CISA KEV analysis:

- Vulnerabilities enter the KEV catalog an average of **42 days** after disclosure — but exploitation begins within **hours** of PoC publication
- Automated mass scanning of internet-facing assets begins within **24 hours** of public disclosure
- Targeted financial sector exploitation begins within **48 hours**
- Ransomware affiliates, Initial Access Brokers (IABs), and nation-state actors prioritize financial sector
- A valid session token from a NetScaler appliance is a marketable commodity on criminal markets within days of a session-hijacking CVE being exploited
- IABs specifically sell financial sector network access obtained via gateway CVEs

**The exploit window** (gap between CVE disclosure and patch deployment) is the period of maximum risk. The IR track's purpose is to determine whether this window was used against the bank.

---

## Section 5 — Phase 0: Activation

**⏱ T+0 to T+2 hours after VM confirms exposure**

### 0.1 — Verify activation criteria
- [ ] CVE is on CISA KEV or confirmed exploited in the wild
- [ ] CVSS ≥ 9.0 or vendor severity = Critical
- [ ] VM confirms ≥1 exposed bank asset via Tenable or asset inventory

### 0.2 — Open incident ticket
```
Ticket naming: CRITVAL-[CVE-ID]-[YYYY-MM-DD]
Example: CRITVAL-CVE-2026-3055-2026-05-14
Severity: P1 (internet-facing) / P2 (internal-only)
Link VM ticket as sibling record (not parent/child)
```

### 0.3 — Send initial leadership notification (≤2 hours)
- CISO, business line security officers, enterprise risk
- Contents: CVE ID, affected technology, exposed asset count, current patch status, active exploitation observed (yes/no/unknown)

### 0.4 — Stand up response team
- Convene IR, CTI, SOC, AppD, Net/FW within 2 hours
- IR briefs on: affected asset classes, network location, business criticality, exploit availability, CTI context
- Assign workstream leads; set 4-hour update cadence

---

## Section 6 — Phase 1: Threat Intelligence

**⏱ T+0 to T+4 hours, then continuously**  
**Owner: CTI**

### 1.1 — Produce CVE threat actor and TTP assessment (≤4 hours)

CTI written assessment must cover:
- Known threat actor groups exploiting this CVE
- MITRE ATT&CK TTPs associated with exploitation and post-exploitation
- Post-exploitation behavior in the wild (lateral movement, persistence, exfiltration)
- Industries and geographies being targeted
- Ransomware group involvement
- IAB activity — are session tokens / access being sold?

### 1.2 — Search for bank-specific exposure
- FS-ISAC sharing channels
- Dark web markets and forums for bank domains, IP ranges, brand mentions
- MISP, threat sharing platforms, vendor intel portals for bank ASN/IP IOCs
- Shodan / Censys for bank internet-facing instances of affected technology (cross-reference VM inventory)

### 1.3 — Develop threat hunt hypotheses for SOC

CTI delivers a hunt hypothesis document covering:
- Log sources to query
- SIEM search queries for known IOCs
- Behavioral anomalies to hunt (e.g. session token reuse from anomalous IPs, unusual auth patterns, lateral movement from gateway IPs)
- EDR/NDR detection signatures

**Example — Citrix session token hunt hypothesis:**
```sql
-- Hypothesis: attacker obtained session token via memory leak, replayed from unusual IP
-- Hunt: Citrix auth sessions with source IP not in user's historical baseline
SELECT username, src_ip, session_id, auth_time
FROM citrix_auth_logs
WHERE auth_time >= '<ADVISORY_DATE>'
  AND src_ip NOT IN (
    SELECT DISTINCT src_ip FROM citrix_auth_logs
    WHERE auth_time < '<ADVISORY_DATE>' AND username = username
  )
```

### 1.4 — Continuous monitoring
- Daily CTI updates to IR: new PoCs, new actor groups, bank-specific intelligence, targeting pattern changes
- Immediate escalation to IR if bank-specific intelligence surfaces — do not wait for scheduled update

### 1.5 — SBOM-driven discovery — for library / embedded component CVEs (Log4Shell class)
**Owners: VM · AppD · IR** — Activate when CVE affects an embedded library or framework

When a CVE affects an embedded library (Apache Log4j2, Spring Framework, OpenSSL, etc.), infrastructure scanning alone is insufficient. The vulnerable component may exist as a JAR-within-JAR, a transitive Python dependency, or a statically linked binary — none visible to Tenable. Run these parallel tracks alongside Tenable:

**Track A — SBOM query:** Query maintained Software Bills of Materials for the affected component and version range. Treat absence from SBOM as unknown, not clean.

**Track B — Build artifact scan:**
```bash
# Grype — scan container image:
grype IMAGE_NAME:TAG --only-fixed | grep -i "log4j\|CVE-2021-44228"

# Scan application directory:
grype dir:/path/to/application/ | grep -i "log4j"

# OWASP Dependency-Check:
dependency-check --project BankApp --scan ./target/ --out ./dc-report/ --format HTML
```

**Track C — Application team self-declaration:** IR sends a structured query to all development teams within 24 hours. Allow 24h response; escalate non-responders to engineering leads.

**Track D — Network detection (secondary):** Deploy SOC rules for JNDI strings in WAF/NGFW logs (`${jndi:ldap://`, `${jndi:dns://`, obfuscated variants) — indicates active exploitation attempts regardless of confirmed host vulnerability.

---

## Section 7 — Phase 2: Threat Hunt & Appliance Investigation

**⏱ T+2 to T+24 hours, continues until closed**  
**Owners: SOC (hunt) · AppD (appliance) · IR (coordination)**

> **This is the most critical phase for financial institutions.** The question is not only "are we patched?" but "were we exploited before patching?" Patching removes the vulnerability; only investigation determines whether the window was used against the bank.

### 2.1 — Execute SIEM/EDR threat hunt

SOC executes structured hunts across SIEM, EDR, NDR/NGFW, and Email/DLP using CTI-provided hypotheses. Document all results — positive and negative. Negative findings with documented methodology are evidence for closure decisions and regulatory review.

### 2.2 — Appliance-specific investigation

**For network gateway appliances (Citrix, Palo Alto, Ivanti, F5, etc.):**
- Pull full authentication logs for the exposure window
- Identify all sessions established during the window
- Cross-reference session source IPs against threat intel and user baselines
- Check for unauthorized configuration changes
- Review VPN session logs for unusual volume, duration, off-hours access
- Check for persistence mechanisms, backdoor users, modified configs

```bash
# Citrix NetScaler example — pull logs for exploitation indicators:
grep -E "(SAML|SAMLRequest|AssertionConsumerService|NSC_TASS)" /var/nslog/ns.log |
  grep -i "error\|overflow\|leak\|corrupt" > citrix_anomalies.txt

# Check for unexpected admin account creation:
grep "USERADD\|group change\|adduser\|passwd" /var/nslog/ns.log |
  awk -v date="<ADVISORY_DATE>" '$1 >= date'

# Verify config integrity against baseline:
diff <(nsconmsg -d current -g config) known_good_config.txt
```

**For server/application CVEs (Exchange, Apache, etc.):**
- Review web server access logs for exploit-pattern requests
- Check for webshells in web root directories
- Review process execution logs for unusual spawned processes
- Check scheduled tasks and startup items for persistence
- Review user/group changes during the exposure window

### 2.3 — Review authentication and session logs

For session hijacking CVEs (Citrix Bleed class):
- Review all sessions established after CVE public disclosure
- Identify sessions from unusual geographies, unusual IP reputation, or outside business hours
- Correlate session identity with downstream system access — what did the session do?
- Look for privileged account access immediately following gateway authentication

### 2.4 — Forensic evidence preservation

Before patching removes evidence:
- Preserve appliance logs, memory dumps where available
- Preserve network flow data for the exposure window
- Set SIEM log retention holds on affected asset scope
- If active compromise is suspected: **do not patch before imaging** — coordinate with IR

### 2.5 — Escalation criteria: vulnerability response → active breach response

Escalate to full breach IR playbook immediately if any of the following are confirmed:

1. C2 beaconing or data exfiltration confirmed from an affected asset
2. Unauthorized credential usage confirmed from appliance session logs
3. Webshell or persistence mechanism found on affected host
4. Lateral movement originating from an affected gateway or server
5. CTI confirms bank-specific data or credentials on criminal markets
6. Ransomware precursor activity detected (staging, credential harvesting at scale)

### 2.6 — Third-party / vendor exposure sub-track
**Owners: IR · Legal/Compliance · Third-Party Risk Management**  
**Activate when: CVE affects widely-used third-party software (MFT, payroll, HR, cloud storage, analytics)**

> **Why this matters:** The MOVEit campaign (CVE-2023-34362) breached Deutsche Bank, ING, Postbank, and Comdirect through a single shared third-party managed file transfer vendor — not bank-owned assets. Tenable showed no bank exposure. For any CVE affecting software commonly operated by vendors on behalf of the bank, this sub-track is mandatory alongside the primary IR track.

**Step 1 — Identify vendors in scope:** Query Third-Party Risk Management for all vendors using the affected software. Do not rely solely on VM asset inventory — it covers bank-managed assets only.

**Step 2 — Notify and require attestation (≤24 hours):** IR (with Legal) sends formal written notification requesting: (a) confirmation of whether they run the affected version; (b) patch status and timeline; (c) confirmation bank data was not accessed or exfiltrated; (d) incident investigation results within 48 hours.

**Step 3 — Scope the data exposure:** Classify data transiting or residing with each vendor: PII, financial account data, payment data, credentials, internal documents. This drives regulatory notification assessment independently of bank asset status.

**Step 4 — Validate vendor response:** Do not accept self-attestation alone for high-risk vendors. Request forensic evidence. Escalate to contract-level audit rights if response is inadequate or delayed.

---

## Section 8 — Phase 3: Network Mitigation

**⏱ T+2 to T+8 hours**  
**Owners: Net/FW · IR (coordination) · AppD**

> Compensating controls reduce exposure but do not eliminate it. They run in parallel with VM patching — not instead of it.

### 3.1 — Determine appropriate controls per CVE type

| CVE type | Primary compensating control | Secondary |
|----------|------------------------------|-----------|
| Unauthenticated RCE on internet-facing appliance | Restrict to trusted IP ranges; take offline if risk justifies | WAF virtual patch; IPS signature |
| Authentication bypass / session hijacking | Terminate all active sessions; force re-auth; geofencing | Step-up MFA on downstream systems |
| Memory disclosure (Citrix Bleed class) | WAF rules blocking crafted payloads; rate limit affected endpoints | Session invalidation; rotate session secrets |
| Privilege escalation (internal) | Restrict lateral movement; segment affected hosts | Temporarily disable affected service |
| Supply chain / build pipeline | Block package versions; pause CI/CD | Credential rotation |

### 3.2 — Implement emergency firewall / WAF / ACL rules

```
# All emergency changes must include:
# - CVE reference in change description
# - Change window and approver
# - Business impact assessment
# - Rollback procedure
# - Planned removal date (not permanent by default)
```

### 3.3 — Session invalidation (for session hijacking CVEs)

- Terminate all active VPN/gateway sessions established before compensating control applied
- Force re-authentication for all users
- Rotate session signing keys/secrets on appliance if technically feasible
- Implement step-up MFA for privileged access traversing the affected gateway

---

## Section 9 — Phase 4: Monitoring & Leadership Updates

**⏱ Throughout incident lifecycle**  
**Owner: IR**

### 4.1 — Status dashboard (updated every 4 hours)

Maintained by IR, covers:
- Total exposed assets (from VM) vs. patched count vs. unpatched
- Compensating controls in place
- Threat hunt status (in progress / complete / findings)
- CTI assessment status
- Escalation decisions made

### 4.2 — Leadership update cadence

| Timing | Content |
|--------|---------|
| T+0 (initial notification) | CVE identified, exposure confirmed, IR open, VM patching in progress |
| T+24h | Patch progress %, threat hunt status, compensating controls, no/possible/confirmed compromise |
| T+72h | Comprehensive update — patch completion, investigation findings, closure projection |
| **Immediate** | Any confirmed indicator of active compromise — do not wait for scheduled update |

### 4.3 — Regulatory notification assessment

Assess at T+0 and revisit if investigation findings change:
- **NY DFS Part 500:** 72-hour notification for cybersecurity events
- **FFIEC final rule:** 36-hour notification for computer-security incidents rising to notification incident level
- **GLBA:** assess under applicable provisions
- Engage legal counsel at first notification assessment

---

## Section 10 — Phase 5: Closure & Lessons Learned

### 5.1 — Closure criteria (all must be met)

- [ ] VM confirms 100% of exposed assets patched or formally risk-accepted with compensating controls
- [ ] SOC confirms threat hunt complete — all hypotheses tested, results documented
- [ ] AppD confirms appliance investigation complete — no indicators of compromise found (or active breach response is managing confirmed findings separately)
- [ ] CTI confirms no bank-specific intelligence on dark web or FS-ISAC
- [ ] Compensating controls removed or formally accepted as permanent
- [ ] Leadership sign-off on closure

### 5.2 — Post-incident review (within 5 business days of closure)

PIR agenda:
- Timeline: advisory receipt → IR activation → compensating controls → patch complete → closure
- Dwell time between exposure and detection of exposure
- Patch deployment velocity vs. exploit window duration
- Effectiveness of compensating controls
- Threat hunt coverage gaps
- Lessons for playbook and tooling improvement

**Key metric to measure:** Days from CVE KEV listing to 100% bank remediation. Target: ≤14 days for internet-facing assets.

---

## Section 11 — Technology-Specific Reference: Top 6 CVE Families

---

### Citrix NetScaler ADC / Gateway — Memory disclosure / session token theft
*CVE-2023-4966, CVE-2025-5777, CVE-2026-3055 and similar (Citrix Bleed family)*

**AppD investigation priorities:**
- Pull `/var/nslog/ns.log` and `/var/nslog/httprequest.log` for full exposure window
- Review SAML auth entries for crafted payload indicators (malformed SAMLRequest, missing AssertionConsumerServiceURL)
- Identify all sessions established during the window — what did each session access downstream?
- Check for new/modified nsapimgr users, cron jobs, shell scripts in `/nsconfig/`
- Run config integrity check against known-good NSconfig baseline

**SOC hunt focus:** Authentication from unusual IPs for users who authenticated via Citrix. VPN sessions outside user's historical pattern (geography, hours, device). Privileged access to AD immediately following Citrix auth. Lateral movement from NetScaler internal interface IP range.

**Network mitigation:** Restrict to trusted IP ranges; enable geofencing; terminate and invalidate all active ICA sessions. For SAML IDP CVEs: temporarily disable SAML IDP or restrict to known IdP IPs.

---

### Ivanti Connect Secure / Policy Secure — Authentication bypass / RCE chain
*CVE-2023-46805, CVE-2024-21887, CVE-2024-21893, CVE-2025-22457*

> ⚠️ **CISA confirmed Ivanti's Integrity Checker Tool (ICT) fails to detect compromise.** A negative ICT result does not mean a clean system. Independent memory and disk forensics are required. CISA recommends factory reset + config restore from known-good backup for actively exploited versions — not patch-in-place.

**AppD investigation priorities:**
- Review `/data/var/log/log.events` and `/var/log/` for exploitation indicators
- Check for webshell deployment in `/data/var/dlbin/`, `/home/`, or web root
- Verify all VPN user sessions during window — identify downstream access
- Check for persistence via modified startup scripts, cron jobs, or LDAP plugin alterations
- Run ICT tool, but **treat negative result as unconfirmed** — proceed with independent review regardless

**SOC hunt focus:** Nation-state actors (Volt Typhoon/UNC5221) use living-off-the-land binaries and avoid traditional malware. Hunt for: slow LDAP queries from VPN gateway IPs; credential access to AD at unusual hours; outbound connections to typosquatted domains or unusual cloud storage; commands via web interfaces bypassing admin workflows.

**Network mitigation:** Restrict management interface to out-of-band management VLAN. Limit SSL VPN outbound connections to required services. If exploitation is confirmed and patch unavailable: factory reset + restore from known-good backup per CISA guidance.

---

### Fortinet FortiOS / FortiGate SSL-VPN — Out-of-bounds write / RCE
*CVE-2024-21762 (CVSS 9.6), CVE-2023-27997 (CVSS 9.8), CVE-2022-42475*

**AppD investigation priorities:**
- Export `/var/log/log`, traffic log, and SSL-VPN log for the exposure window
- If FortiAnalyzer is deployed, pull centralized logs — retains more history and harder to tamper with
- Check for unauthorized admin accounts in `config system admin`
- Verify running config against last approved backup in FortiManager
- Known persistence technique: attackers modify SSL-VPN filesystem (`/data/etc/`, `/migadmin/`) to survive firmware upgrades — check for unexpected files even after patching

**SOC hunt focus:** HTTPS to management IP from non-admin source IPs. New admin accounts not created via approved change workflow. Config changes during non-change windows. Outbound connections from firewall management interface to unexpected destinations. FortiGate compromise frequently precedes AD credential harvesting then ransomware staging.

**Network mitigation:** Disable SSL-VPN if not business-critical, or restrict to specific trusted IP ranges. Restrict management interface to dedicated OOB management VLAN. CVE-2024-21762 specifically requires disabling SSL-VPN as a temporary workaround (not a WAF rule) — confirm per advisory.

---

### Apache Log4j2 / Log4Shell — JNDI injection / unauthenticated RCE
*CVE-2021-44228 (CVSS 10.0) — embedded library class*

> ⚠️ **Tenable scans alone are insufficient.** See Phase 1, step 1.5 for SBOM-driven discovery. A negative Tenable result does not rule out exposure — the vulnerable JAR may be nested inside an application WAR file or container layer invisible to a network scan.

**AppD investigation priorities:**
- Run Grype, Syft, or OWASP Dependency-Check against all container images, WAR/JAR archives, and build artifacts
- Query application teams for self-declaration (Track C of SBOM process)
- Review web server and application logs for JNDI lookup strings in HTTP headers: `${jndi:ldap://`, `${jndi:dns://`, obfuscated variants using `${${lower:j}ndi:`
- Check for unexpected outbound DNS and LDAP connections from application hosts — these indicate successful JNDI callback

**SOC hunt focus:** JNDI injection strings in WAF/application logs. Outbound LDAP (port 389, 636) or RMI (port 1099) connections from application servers to external IPs. DNS queries to unusual domains from application servers. Unexpected process spawns from Java runtime (`java` spawning `curl`, `wget`, `bash`, or PowerShell).

**Network mitigation:** Block outbound LDAP, LDAPS, RMI, and DNS-over-HTTPS from application server network segments where not required — this breaks the JNDI callback mechanism. Deploy WAF rules rejecting JNDI lookup patterns. Log4Shell remains on CISA KEV years post-disclosure — re-run discovery on legacy systems and vendor software periodically.

---

### Palo Alto PAN-OS — Command injection / root RCE on firewall
*CVE-2024-3400 (CVSS 10.0), CVE-2026-40982 (state-sponsored zero-day)*

**AppD investigation priorities:**
- Export and review `system.log`, `threat.log`, and `traffic.log` for exposure window
- Check for GlobalProtect exploitation attempts
- Look for unauthorized admin account creation or config changes outside change windows
- Verify running config against known-good backup
- Check for persistence mechanisms (malicious extensions, modified boot sequence)

**SOC hunt focus:** Unusual management plane access. New admin accounts not created via approved workflow. Config changes during non-change windows. Outbound connections from firewall management IP to unexpected destinations.

**Network mitigation:** Restrict management plane access to dedicated management network. Disable GlobalProtect portal access if temporarily acceptable. Apply vendor-provided temporary mitigations (interface disable, feature flags) per advisory.

---

### MOVEit Transfer / Managed File Transfer — SQL injection / data exfiltration
*CVE-2023-34362 and follow-on MOVEit CVEs (Cl0p/FIN11)*

> ⚠️ **Primary risk is third-party exposure.** The Cl0p campaign breached multiple major European banks through shared third-party vendors, not bank-owned assets. Activate Phase 2.6 third-party sub-track immediately for any MFT CVE.

**AppD investigation priorities (bank-owned MFT):**
- Review MOVEit Transfer web application logs (`%ProgramFiles%\MOVEit Transfer\Logs\` on Windows) for POST requests to `/api/v1/token` or `/guestaccess.aspx` at unusual times
- Check for webshell files in MOVEit web root (`human2.aspx` and variants were deployed in original campaign)
- Review all file transfer activity during window — identify what data was accessed or downloaded
- Check database for unexpected changes to system tables

**SOC hunt focus:** Unusual SQL queries to MOVEit database from application service account. Outbound data transfers significantly larger than baseline. Inbound connections to MOVEit from unexpected external IPs. HTTP 200 responses to affected endpoints from unusual source IPs.

**Third-party track (Phase 2.6):** Identify all vendors using MOVEit or equivalent MFT software on the bank's behalf. Formal written notification within 24 hours of KEV listing. Scope data exposure by vendor for regulatory notification assessment.

---

## Section 12 — Metrics

| Metric | Target | Owner |
|--------|--------|-------|
| Time: KEV listing → IR activation | ≤ 4h after VM confirms exposure | IR |
| Time: IR activation → leadership notification | ≤ 2h | IR |
| Time: IR activation → compensating controls (internet-facing) | ≤ 8h | Net/FW |
| Time: vendor notification (third-party CVE) | ≤ 24h of KEV listing | IR + Legal |
| SBOM/library discovery complete (embedded CVE) | ≤ 24h of activation | VM + AppD |
| Time: 100% patch — internet-facing assets | ≤ 14 days | VM |
| Threat hunt completion | ≤ 72h | SOC |
| Appliance investigation completion | ≤ 48h | AppD |
| IR track closure (no compromise) | ≤ 21 days post-patch | IR |
| Post-incident review | ≤ 5 business days post-closure | IR |

---

## References

- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NIST SP 800-61r3 — Incident Response Recommendations (CSF 2.0)](https://www.nist.gov/publications/incident-response-recommendations-and-considerations-cybersecurity-risk-management)
- [NIST CSF 2.0 Financial Services Profile](https://www.nist.gov/cybersecurity-framework)
- [FFIEC Cybersecurity Incident Notification Final Rule](https://www.ffiec.gov)
- [NY DFS Part 500 Cybersecurity Regulation](https://www.dfs.ny.gov/industry_guidance/cybersecurity)
- [CISA BOD 22-01 — Reducing Risk of Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities)
- [CISA Advisory AA24-060B — Ivanti Connect Secure / Policy Secure](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-060b)
- [Mandiant/Google Cloud — Ivanti CVE-2025-22457 China-nexus exploitation](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-exploiting-critical-ivanti-vulnerability)
- [Unit 42 — Citrix Bleed CVE-2023-4966 Threat Brief](https://unit42.paloaltonetworks.com/threat-brief-cve-2023-4966-netscaler-citrix-bleed/)
- [Mandiant/Google Cloud — Citrix NetScaler Investigation](https://cloud.google.com/blog/topics/threat-intelligence/session-hijacking-citrix-cve-2023-4966/)
- [FortiGuard Labs — Fortinet FortiOS Exploitation](https://www.fortiguard.com/threat-signal-report/6134)
- [ENISA Threat Landscape: Finance Sector 2024](https://www.enisa.europa.eu/publications/enisa-threat-landscape-finance-2024)

---

*Critical Vulnerability as Cyber Incident — IR Playbook v1.1 · Financial Institution*  
*Updated: 2026-05-14 · Aligned: NIST SP 800-61r3 · CSF 2.0 · FFIEC · NY DFS Part 500*  
*Changes in v1.1: Third-party/MOVEit sub-track (Phase 2.6); Ivanti ICT bypass warning; Fortinet FortiOS tech card; Log4Shell SBOM discovery (Phase 1.5); top-6 CVE family tech sections*

