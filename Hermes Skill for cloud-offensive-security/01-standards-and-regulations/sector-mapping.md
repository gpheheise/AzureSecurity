# Sector Mapping — Which Regulation Applies Where

Use this when scoping an engagement. The customer's sector + region determines the regulatory overlay, which determines the audit baseline, which determines the report structure.

## Master matrix

| Sector | EU mandatory | EU optional/sector | UK | US federal | US sector/state | APAC notable |
|---|---|---|---|---|---|---|
| **Banks / credit institutions** | DORA + NIS2 + GDPR | EBA Guidelines on ICT risk, EU-FIDA (under negotiation) | CBEST, PRA SS2/21, FCA SYSC 13/15 | FFIEC CAT, GLBA, OCC heightened standards | NYDFS 23 NYCRR 500, Massachusetts 201 CMR 17 | HKMA C-RAF/iCAST (HK), MAS TRM (SG), APRA CPS 234 (AU) |
| **Insurance / reinsurance** | DORA + NIS2 + GDPR | Solvency II ORSA cyber annex, EIOPA Guidelines on ICT risk | PRA SS2/21, FCA | NAIC Model Law 668, NYDFS Cybersecurity Reg | State insurance dept variations | MAS Insurance, APRA CPS 234 |
| **Investment firms / asset managers** | DORA + MiFID II + NIS2 | ESMA guidelines | FCA SYSC, CASS | SEC Reg SCI, SEC Reg S-P, Investment Advisers Cybersecurity Rule | NY DFS | MAS, SFC HK |
| **Payment institutions / e-money** | DORA + PSD2 (transitioning to PSD3 + PSR) + NIS2 | EBA RTS on SCA & CSC | FCA Payment Services Reg | OCC, state money transmitter laws | NYDFS | MAS PSA, HK Stored Value Facility, RBI PSS Act |
| **Crypto-asset service providers** | DORA + MiCA + NIS2 + EU AML | EBA guidance | FCA registration | SEC (case-by-case), CFTC, FinCEN | NYDFS BitLicense | MAS, HK SFC, JFSA |
| **Healthcare providers** | NIS2 + GDPR + EU MDR/IVDR (devices) | EHDS (under implementation), sector codes | DSPT, NHS DTAC, NHS Cloud guidance | HIPAA/HITECH, FDA pre/post-market cybersecurity guidance | State (CCPA-CPRA, Texas HB 4) | PDPC HK, MyHealth Records (AU), MOH SG |
| **Pharma / medical device manufacturers** | NIS2 + GMP, ISO 13485, ISO 14971 | EU MDR/IVDR cybersecurity (Annex I) | MHRA | FDA pre-market and post-market cybersecurity guidance, IEC 81001-5-1 | State | TGA (AU), HSA (SG), PMDA (JP) |
| **Energy (electricity, gas, oil, district heating)** | NIS2 + EU Energy Network Code on Cybersecurity (active 2026) | RED-S delegated act | OFGEM CAF, NIS Regs 2018 | NERC CIP, TSA Pipeline Security Directives, FERC | State PUCs | AEMO (AU), EMA (SG) |
| **Water (drinking, waste, irrigation)** | NIS2 + Drinking Water Directive | Sector codes | DEFRA Water Sector CAF | America's Water Infrastructure Act 2018 (EPA), CIRCIA | State utility regs | – |
| **Transport (aviation, rail, road, maritime)** | NIS2 + EASA Part-IS (aviation), ERA TSI (rail) | EU Cybersecurity Strategy for Aviation | CAA CAP 1753 (aviation), DfT for rail/road, MCA maritime | TSA SD on aviation/rail/pipeline, FAA Part-IS equiv, USCG MCRM | – | CASA (AU), HKCAD (HK) |
| **Digital infrastructure (cloud, DNS, TLDs, data centres, CDN, content trust services)** | NIS2 + eIDAS 2 (trust services) + EUCS (when adopted) | EU-FIDA candidate | NCSC Cloud Principles, GovAssure | FedRAMP for federal, voluntary StateRAMP | CIRCIA | IRAP (AU), MTCS (SG), HKMA cloud, IRAP-equiv (JP) |
| **Telecoms** | NIS2 + EECC + EU 5G Toolbox | ENISA telecom guidelines | TSA 2021, Telecom Security Code of Practice | TSA, FCC | State PUCs | OFCA (HK), IMDA (SG), ACMA (AU) |
| **Public administration / govt** | NIS2 (where in scope) + GDPR + EU-CC | National variants (BSI Grundschutz, ANSSI SecNumCloud) | NCSC GovAssure, GovS 007, Cabinet Office SPF | FedRAMP, FISMA, CMMC, OMB M-22-09 | StateRAMP, state CISOs | ISM (AU), IM8 / GovTech (SG), GCIO (HK), JIPDEC (JP) |
| **Defense / DIB** | EU Defence Industrial Strategy (under develop.) | NATO AC/35 D/2003 | List X, Defence Cyber Protection Partnership | CMMC 2.0, DFARS 252.204-7012, ITAR | – | DSPF (AU), DSTA (SG) |
| **Manufacturing (auto, machinery, electronics, chemicals)** | NIS2 (specific subsectors) + CRA (products) | ISO/SAE 21434 (auto), IEC 62443 (OT) | NIS Regs (where critical), CAA for auto | TSA SD for pipelines, sector-specific | – | – |
| **Food / beverage / agriculture** | NIS2 (manufacturers + critical distributors) | Sector codes | FSA cyber guidance, NIS Regs | FDA FSMA cybersecurity guidance, CISA Food/Ag Sector Profile | – | – |

Read this matrix as "in addition to" — most entities are hit by multiple regimes simultaneously. A German bank running cloud workloads in AWS Frankfurt that processes EU customer data is subject to DORA + NIS2 (typically as Essential) + GDPR + BSI requirements + (if PCI scope) PCI DSS + (if US customers) GLBA + (if NY presence) NYDFS 23 NYCRR 500 + (if it ships software) CRA.

## Cloud-specific framework selection by sector

When you need to decide which technical baseline to audit against, this is the practical mapping:

| Sector | Primary cloud audit baseline | Secondary | Sector overlay |
|---|---|---|---|
| Finance EU | CIS Benchmark + CSA CCM v4 | ISO 27017/27018 | DORA RTS on ICT risk, EBA Guidelines |
| Finance US | CIS Benchmark + AWS/Azure/GCP Foundational Security Best Practices | NIST 800-53 | FFIEC CAT, NYDFS-mapped controls |
| Health EU | CIS Benchmark + CSA CCM | ISO 27017 + ISO 27799 | GDPR DPIA, sector code |
| Health US | CIS Benchmark + HITRUST CSF | NIST 800-66r2 | HIPAA Security Rule mapping |
| KRITIS DE | CIS Benchmark + BSI C5 + IT-Grundschutz | CSA CCM | B3S (sector-specific) |
| Energy | CIS Benchmark + ENISA Energy Sector Cloud guidance | IEC 62443 (for OT touchpoints) | NERC CIP cloud guidance, ENTSO-E |
| Telecoms | CIS Benchmark + ENISA telecom security guidelines | NIST 800-53 | Sector-specific national codes |
| Defense / DIB | CIS Benchmark + NIST 800-171 + DoD CC SRG | CMMC L2/L3 | ITAR controls |
| Public admin | CIS Benchmark + national cloud framework (BSI C5 / SecNumCloud / NCSC) | – | – |
| Cloud Service Provider (their own audit) | CSA CCM + ISO 27017/27018 | BSI C5, FedRAMP | – |

## Pentest mandates explicit in regulation

When a regulation **requires** pentesting (not just risk assessment), in scope:

| Regime | Frequency | Type | Notes |
|---|---|---|---|
| DORA (significant entities) | Every 3 years | TLPT per TIBER-EU | Live production, cloud control plane in scope |
| DORA (all in-scope) | Annual | Operational resilience testing | Vuln scans + pentests + scenario testing |
| FedRAMP | Annual | Independent | 3PAO performs |
| PCI DSS 4.0 | Annual + on significant change | External + internal | Quarterly external ASV scans separate |
| NYDFS 23 NYCRR 500 | Annual | Pentest | Plus biannual vuln assessment |
| GLBA Safeguards Rule | Annual or continuous monitoring | Either pentest or continuous monitoring | 2023 amendment |
| HIPAA | "Regularly" — interpreted as annual | Vuln assessment + pentest | Under §164.308(a)(8) |
| UK PRA SS2/21 (Op Res) | At minimum annual | Vulnerability + scenario testing | CBEST for systemically important firms |
| MAS TRM (SG) | At least annual for high-risk | Pentest + vuln assessment | Plus red team for systemically important |
| APRA CPS 234 (AU) | At least annual | Pentest equivalent | "Systematic testing of cyber controls" |
| HKMA C-RAF/iCAST | Periodic (~3 yr cycle) | Intelligence-led red team | Tier ratings dictate frequency |

## Cross-border considerations

If the customer operates across regions, the engagement needs to satisfy the strictest applicable framework. Practically:

- **EU + US:** DORA TLPT + FedRAMP Pentest are different exercises with different scopes. Don't conflate. Coordinate vendors but don't shortcut.
- **EU + UK:** CBEST and TIBER-EU recognise each other in practice. The PRA and ECB / national TLPT authorities co-ordinate for cross-border banks.
- **APAC:** HKMA iCAST and MAS-CAT can sometimes substitute for each other under regulator coordination. Always confirm.
- **Multi-region engagements** want a single methodology with regional sub-reports. Lead with TIBER-EU; it's the most rigorous and other regulators accept it.

## Don't-do list

A few items that trip up scoping repeatedly:

1. **Treating SOC 2 as a compliance regime.** It's an attestation. The auditor's expectations are what matter, not a published rulebook.
2. **Assuming a CSP attestation covers the customer's usage.** ISO 27001 on AWS doesn't make the customer's AWS account ISO 27001. They have to do their own ISMS.
3. **Mapping pentest findings to ISO 27001 controls.** ISO 27001 is too high-level. Map to 27017/27018, CCM, or 800-53 instead. Reference 27001 only in the executive summary.
4. **Forgetting cloud-specific data residency.** GDPR + Schrems II constraints aren't a footnote. Region selection is a control.
5. **Mixing "cloud provider audit" with "customer cloud usage audit."** The customer doesn't audit AWS; they audit their own use of AWS. AWS gets audited by AWS's auditors (whose reports the customer relies on).
