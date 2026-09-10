# NIS2, KRITIS, and the German Implementation

EU NIS2 Directive (2022/2555), German implementation via the **NIS2 Implementation Act (NIS2UmsG)** in force since 5/6 December 2025, and the **KRITIS-Dachgesetz** in force since 17 March 2026.

## NIS2 in 60 seconds

NIS2 replaced the original NIS Directive. Broader scope, harder requirements, real fines.

**Sectoral scope** (entity must be in scope **and** meet size thresholds — generally medium-sized or above):

- **Sectors of high criticality (Annex I):** energy, transport, banking, financial market infrastructure, health, drinking water, waste water, digital infrastructure (incl. cloud providers, DNS, TLDs, data centres), ICT service management B2B, public administration, space.
- **Other critical sectors (Annex II):** postal/courier, waste management, chemicals, food, manufacturing (medical devices, computers/electronics, electrical, machinery, vehicles), digital providers (marketplaces, search engines, social platforms), R&D.

**Entities are classified as either Essential or Important.** Essential entities get stricter supervision (proactive audits); Important entities get reactive supervision.

## Article 21 — the ten security measures

Every in-scope entity must implement, at minimum:

1. Risk analysis and information system security policies
2. Incident handling
3. Business continuity (backup, disaster recovery, crisis management)
4. Supply chain security
5. Security in network and information system acquisition, development, and maintenance
6. Policies on assessing the effectiveness of risk management measures
7. Basic cyber hygiene and training
8. Cryptography
9. HR security, access control, asset management
10. Multi-factor authentication, secured voice/video/text comms, secured emergency comms

Article 21(2)(e) — secure development — is where cloud audits land. Item 4 — supply chain — captures the cloud-provider relationship explicitly.

## Reporting timeline (Article 23)

- **Early warning** within 24 hours of becoming aware of a significant incident.
- **Incident notification** within 72 hours, with initial assessment.
- **Intermediate report** on request.
- **Final report** within 1 month.

## Penalties

Up to **€10 million or 2% of global annual turnover** for Essential entities (whichever is higher). €7M / 1.4% for Important entities. Personal liability for management bodies in DE under §38 BSIG.

## Germany: NIS2UmsG + KRITIS-Dachgesetz

Germany did not adopt a standalone NIS2 law. Instead it amended the **BSIG (BSI Act)**, layering NIS2 categories on top of the existing KRITIS framework. Result: a more granular and in places more stringent regime than the EU baseline.

### Key dates and milestones

| Date | Event |
|---|---|
| 6 December 2025 | NIS2UmsG enters into force (amends BSIG) |
| 6 January 2026 | BSI registration portal opens for new NIS2 entities |
| 6 March 2026 | Registration deadline for existing KRITIS operators in the new portal; KRITIS-Dachgesetz enters into force |
| July 2026 | National authorities identify "critical facilities" under the KRITIS-Dachgesetz |
| September 2026 | EU vulnerability reporting platform goes live |
| From 2027 | First evidence of implementation due (3 years after BSIG entry into force, per §39 (1)) |
| Every 3 years | Recurring evidence cycle |
| December 2027 | CRA full applicability for products placed on market |

### Categories (BSIG)

- **Besonders wichtige Einrichtungen** (Particularly Important Entities) — equivalent to NIS2 Essential.
- **Wichtige Einrichtungen** (Important Entities) — equivalent to NIS2 Important.
- **Kritische Anlagen** (Critical Facilities) — the legacy KRITIS classification, now nested under the above and additionally subject to the KRITIS-Dachgesetz (physical resilience).

A KRITIS operator is typically **also** a Particularly Important Entity under NIS2.

### Audit cycle

Previously: every 2 years. Under new BSIG: **every 3 years**. The BSI is directly notifying existing operators of their individual deadlines.

### Evidence

§39 BSIG: initial evidence of implementation due no later than the date the BSI sets at registration, but no later than 3 years after the law's entry into force. So for new registrants, count to ~December 2028 as the latest first deadline.

Evidence options:
- ISO 27001 certificate (with cloud scoping documented per ISO 27017)
- BSI C5 attestation (for the cloud-provider side)
- IT-Grundschutz certificate
- Sector-specific (e.g. B3S — Branchenspezifische Sicherheitsstandards)

For cloud-heavy environments, the typical audit stack is: ISO 27001 (umbrella) + ISO 27017 (cloud-specific controls) + ISO 27018 (PII in cloud) + sector overlay.

### KRITIS-Dachgesetz (the "umbrella act") — what's new

Effective 17 March 2026, focuses on **physical and operational resilience** of critical facilities. Cybersecurity remains under the BSIG; physical security and continuity sit under the Dachgesetz.

For cloud assessors this matters because:

- The legal entity operating the KRITIS facility may now have to demonstrate that **the cloud workloads supporting the critical service** are resilient against physical events affecting the cloud provider (multi-region, multi-AZ, documented fail-over).
- Vendor lock-in becomes a documented risk to be assessed.
- Hyperscaler region selection becomes a regulated decision, not just a cost/latency one.

### Cloud-specific NIS2 audit focus areas

When auditing a NIS2 in-scope cloud environment, the obligations translate to concrete technical checks:

| Article 21 measure | Cloud control to verify |
|---|---|
| Risk analysis | Documented cloud risk register, including IAM/data/network risks per service |
| Incident handling | CloudTrail/Activity Log/Audit Log retention ≥ 1 year, alerting pipeline to SOC, incident playbooks for cloud-specific scenarios |
| Business continuity | Multi-region deployment for critical workloads, tested DR, backup with separate IAM trust boundary |
| Supply chain | Documented assessment of cloud provider (SOC 2 / C5 / ISO 27017 in evidence file), DPA in place, sub-processor list |
| Acquisition/dev | IaC scanned in CI (Checkov/tfsec/KICS), branch protection, signed commits for IaC repos |
| Effectiveness assessment | Continuous compliance (Security Hub / Defender for Cloud / SCC), exception register with owners |
| Cyber hygiene | Hardening baselines (CIS), patch cadence on guest OS and container images |
| Cryptography | TLS 1.2+ everywhere, customer-managed keys (CMK/CMEK) for sensitive data, key rotation policy |
| HR / access / assets | RBAC reviewed quarterly, joiners/movers/leavers automated, asset inventory complete (AWS Config/Resource Graph/Asset Inventory) |
| MFA + secure comms | MFA on all human identities, phishing-resistant for admin, Privileged Access Workstations for break-glass |

The platform audit checklists in this repo are structured so you can pull a NIS2-aligned subset of checks for the report.

## CRA — Cyber Resilience Act (related, not the same)

NIS2 covers **operators**. The CRA (Regulation 2024/2847) covers **products with digital elements** placed on the EU market. From December 2027, all such products need to meet essential cybersecurity requirements.

For cloud customers building products that run in their cloud and ship to EU customers, both apply. For pure cloud-operator engagements, focus on NIS2.

## References

- [NIS2 Directive (EUR-Lex)](https://eur-lex.europa.eu/eli/dir/2022/2555/oj)
- [German BSIG (consolidated, in German)](https://www.gesetze-im-internet.de/bsig_2009/)
- [BSI NIS2 portal (registration + guidance)](https://www.bsi.bund.de/nis2)
- [OpenKRITIS NIS2-DE tracker](https://www.openkritis.de/eu/eu-nis-2-germany.html)
- [BSI C5:2020 catalogue](https://www.bsi.bund.de/c5)
- [BSI Grundschutz Kompendium (IT-Grundschutz Modules)](https://www.bsi.bund.de/grundschutz)

## Practical scoping advice for German engagements

- For DACH-region engagements, when the customer says "Pentest unter BSI Grundschutz" they almost always mean a configuration review of cloud workloads against the relevant Grundschutz modules (OPS.2.2, OPS.2.3, APP.1.4, CON.8, SYS.1.6).
- For C5 attestations, the cloud provider gets audited, not the customer. But customers consuming the provider need to map provider controls to their own ISMS — your audit should include this mapping if the customer is on the C5 path.
- The KRITIS audit cycle change (2y → 3y) means more time for thorough assessments. Customers may not realise their next deadline has shifted; check.
