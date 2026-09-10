# US & Global Frameworks

The non-EU side of the regulatory map. What applies to whom, what it asks for, and what to do about it on a cloud engagement.

## United States

### FedRAMP

Federal Risk and Authorization Management Program. Mandatory for any cloud service offering used by US federal agencies.

- **Three impact levels:** Low, Moderate, High. Most federal SaaS lands on Moderate.
- **Controls baseline:** NIST SP 800-53 Rev. 5 with FedRAMP overlays.
- **Authorization path:** Agency ATO (single sponsor) or JAB P-ATO (broader). Both require a 3PAO assessment.
- **Continuous monitoring:** Monthly POA&M updates, annual assessment, penetration testing required.
- **Pen-test requirement:** Annual independent penetration test against the boundary. Must include external, internal, web app, and (where applicable) mobile / API surfaces. See [FedRAMP Penetration Test Guidance](https://www.fedramp.gov/documents-templates/).

Cloud assessment angle: FedRAMP boundaries are tightly defined. The penetration test scope is the boundary, not the customer's cloud usage. Don't pentest the customer's data in the SaaS — pentest the SaaS provider's own AWS GovCloud / Azure Government boundary.

### FISMA + NIST SP 800-53

The baseline NIST 800-53 controls underpin FedRAMP. Same controls, broader application (any federal system, not just cloud).

### CMMC 2.0

Cybersecurity Maturity Model Certification for the Defense Industrial Base. Three levels:

- **Level 1** (Foundational): 17 practices from NIST SP 800-171, self-attested.
- **Level 2** (Advanced): 110 practices from 800-171, third-party assessed for non-Federal Contract Information / CUI handling.
- **Level 3** (Expert): subset of NIST SP 800-172 controls, government-assessed.

Cloud relevance: any DIB contractor processing CUI in cloud must use a FedRAMP-Moderate (or higher) authorized cloud, **and** meet CMMC L2/L3 controls in their own usage layer.

### SOC 2

AICPA Trust Services Criteria (TSC): Security, Availability, Processing Integrity, Confidentiality, Privacy. Voluntary but de-facto required for B2B SaaS.

- **Type I:** controls designed appropriately at a point in time.
- **Type II:** controls operated effectively over a 6–12 month observation period.
- **Penetration testing** is not strictly required but is universally expected as evidence under CC4.1 / CC7.1.

A SOC 2 audit report is not a security assessment; it's an attestation. The pentest sits *inside* it as evidence. When customers say "we need a pentest for SOC 2," what they need is a credible report that the SOC 2 auditor will accept as evidence of testing.

### HIPAA / HITECH

Health Insurance Portability and Accountability Act. **Security Rule** is the technical part:

- Administrative, physical, and technical safeguards for electronic PHI (ePHI).
- Specific cloud relevance: encryption at rest and in transit, audit logging, access controls, BAA (Business Associate Agreement) with the cloud provider.
- All three hyperscalers offer HIPAA-eligible services with a BAA — the customer is responsible for using only those services for PHI.

Cloud audit angle: enumerate every service touching PHI, verify each is HIPAA-eligible at that provider, confirm BAA covers them, verify encryption settings, audit IAM access to PHI-containing resources.

### PCI DSS v4.0

Card data. The same rules apply whether on-prem or in cloud, but cloud changes how you scope.

- **Cardholder Data Environment (CDE) scoping:** any system that stores, processes, transmits CHD, plus anything connected to those systems.
- **Segmentation:** properly designed VPC/VNet/VPC isolation lets you reduce CDE scope dramatically.
- **Annual external pentest + quarterly external ASV scan.** Internal pentest at least annually for in-scope systems.
- **Service Provider attestation:** the cloud provider's PCI DSS AoC covers their layer. Customer is responsible for their own scope above that.

PCI 4.0 brought authenticated scanning, MFA on all admin access (not just remote), and more frequent risk assessments. Effective March 2024 for "future-dated" requirements (became mandatory March 2025).

### FFIEC CAT + GLBA + NYDFS 23 NYCRR 500 + SEC Reg S-P

US financial sector. Each is its own regime; they overlap.

- **FFIEC CAT** (Cybersecurity Assessment Tool): self-assessment used by federal banking regulators.
- **GLBA Safeguards Rule:** 16 CFR Part 314. Encryption, MFA, designated qualified individual, annual report to the board, **continuous monitoring or annual pentest + biannual vulnerability assessment**. Updated 2023.
- **NYDFS 23 NYCRR 500:** Annual pentest, biannual vulnerability assessment, CISO reporting, board oversight. Amended Nov 2023.
- **SEC Reg S-P:** Updated May 2024, requires incident notification to affected individuals within 30 days.

These overlap heavily; in practice an annual pentest + monthly/quarterly vuln scanning + documented IR drills covers most of them.

## United Kingdom

### NCSC Cloud Security Principles

14 principles. Voluntary but the de-facto cloud security baseline for UK government and most regulated industries.

### CBEST + PRA SS1/21

UK financial sector threat-led testing, predecessor to TIBER-EU and similar in approach. Run by the Bank of England's PRA for firms it deems systemically important. The PRA's Supervisory Statement SS1/21 sets expectations on operational resilience.

For multi-jurisdictional firms, a CBEST test can typically be coordinated with a TIBER-EU test to reduce duplication — provided the regulators agree.

### Telecommunications Security Act 2021 + Telecoms Security Code of Practice

Telecoms operators in the UK. Heavy on supply chain (the "Huawei" act). Requires annual security audits and reporting to Ofcom.

### NCSC GovAssure

UK government cloud assessment framework, replacing the old G-Cloud assurance regime in stages. Maps to the 14 Cloud Security Principles. For HMG and broader public sector use.

## Global / cross-cutting

### ISO/IEC 27001 + 27017 + 27018 + 27701

The big ISO bundle for cloud:

- **27001:** ISMS (governance umbrella).
- **27017:** cloud-specific security controls — code of practice. Use this for the cloud-specific overlay.
- **27018:** PII processing in cloud. Required if you're a cloud service provider processing PII.
- **27701:** Privacy Information Management. Adds GDPR-relevant management requirements on top of 27001.

For cloud assessments under ISO 27001 scope, 27017 is your control reference for the technical layer. The 2022 update to 27001 changed Annex A to 93 controls in 4 themes; 27017 remains the cloud companion.

### CSA STAR + CCM

CSA's certification scheme based on the Cloud Controls Matrix. Three levels:

- **STAR Level 1 (Self-Assessment):** CSA STAR Registry, free.
- **STAR Level 2 (Third-Party Audit):** CCM+ISO 27001 assessment. Provider-side certification.
- **STAR Continuous:** automated continuous attestation.

For customer-side teams, the CCM (v4 current as of 2026) is the single best mapping document. Use it as your spine for any cloud audit.

### NIST Cybersecurity Framework (CSF) 2.0

Updated Feb 2024. Six functions now: Govern, Identify, Protect, Detect, Respond, Recover. Used widely as the executive-facing structure for any cybersecurity program.

Not a control catalogue — use 800-53 for that. Use CSF to organise reporting.

### NIST SP 800-204A/B/C/D + SP 800-218 (SSDF)

For modern cloud-native architectures:
- **800-204A:** microservices security.
- **800-204B:** service mesh security.
- **800-204C:** API security.
- **800-204D:** software supply chain security for CI/CD.
- **800-218 (SSDF):** Secure Software Development Framework. Required for any vendor selling software to the US federal government per OMB M-22-18.

If you do CI/CD or container assessments, these are the references.

### COBIT 2019 + ITIL

Governance and operations frameworks. Not security-specific. Useful only when reporting up to executive risk committees that speak this language.

## CSP-specific compliance reports

For audits, these are the CSP-published attestations to ask for and read:

- **AWS Artifact** (portal): SOC 1/2/3, PCI, ISO 27001/17/18, FedRAMP, BSI C5, HIPAA, IRAP, MTCS, etc.
- **Azure Service Trust Portal:** same range, including BSI C5, ENS-Spain, IT-Grundschutz, EU Cloud CoC.
- **GCP Compliance Reports Manager:** same range, including BSI C5, FedRAMP, ISO 27001/17/18.

Read the **applicable services list** in each. A provider holds ISO 27017 — but does the *specific service* the customer uses sit inside that certification scope? Often not.

## Penetration testing rules

Customer-side pentesting on the major CSPs:

- **AWS:** [Customer Penetration Testing policy](https://aws.amazon.com/security/penetration-testing/). Eight pre-approved services. Anything else needs the Simulated Events form (response within 7 business days). Prohibited: DoS, DDoS, port flooding, request flooding, DNS zone walking.
- **Azure:** [Microsoft Cloud Pentest Rules of Engagement](https://www.microsoft.com/en-us/msrc/pentest-rules-of-engagement). No pre-approval for own subscriptions. Notification required for stress tests, large simulation events. Prohibited: DoS/DDoS that affects shared infrastructure.
- **GCP:** [Customer testing policy](https://cloud.google.com/security/testing). No pre-approval. Must comply with AUP. Prohibited: violating other customers' resources, DoS against Google infrastructure.

Always read the current version. They change.
