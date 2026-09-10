# DORA, TLPT, and TIBER-EU

EU Regulation 2022/2554, the **Digital Operational Resilience Act**. Applicable since 17 January 2025. Now in full implementation phase.

## Who's in scope

DORA applies to virtually the entire EU financial sector:

- Credit institutions
- Investment firms (incl. proprietary traders, MTFs, OTFs)
- Insurance and reinsurance undertakings
- Payment institutions and e-money institutions
- Crypto-asset service providers (MiCA)
- Central counterparties (CCPs), trade repositories, central securities depositories
- Crowdfunding service providers
- Trading venues, data reporting service providers
- **Critical ICT third-party service providers (CTPPs)** designated by ESAs — this is the cloud hyperscaler hook

For US/UK readers: if your firm sells ICT services into EU financial entities and you get CTPP-designated, DORA applies directly to your operations.

## The five pillars

1. **ICT risk management** (Articles 5–16). Board-level accountability. Documented framework.
2. **ICT incident reporting** (Articles 17–23). Three-stage reporting: initial ≤4h after classification, intermediate ≤72h, final ≤1 month.
3. **Digital operational resilience testing** (Articles 24–27). Annual basic + every-3-year TLPT for significant entities.
4. **ICT third-party risk** (Articles 28–44). Includes the CTPP designation regime.
5. **Information sharing** (Article 45). Voluntary, but encouraged.

This document is about pillar 3.

## TLPT — the part that creates pentest work

### Legal basis

- **Article 24**: scope of operational resilience testing (annual, all critical/important functions).
- **Article 25**: testing programme requirements — independence, methodology, vulnerability remediation.
- **Article 26**: **TLPT obligation** for entities meeting significance thresholds (defined in the [RTS on TLPT](https://eur-lex.europa.eu/eli/reg_del/2025/1190), published 18 June 2025, effective 8 July 2025).
- **Article 27**: TLPT execution standards — alignment with TIBER-EU is the default route.

### Significance criteria

The RTS sets quantitative and qualitative thresholds. As a rule of thumb, entities are caught if they:

- Are SSM-supervised "Significant Institutions" (the big banks), or
- Are systemically important based on size, interconnectedness, complexity, cross-border activity, or
- Are central market infrastructures (CCPs, CSDs, trading venues with critical market share).

National competent authorities (NCAs) and the ECB (for SSM) confirm scope by formal letter. **If you haven't received a letter, you're probably not in scope yet** — but check with the NCA before assuming.

### Frequency

**At least every 3 years.** First TLPT under DORA should already be planned or in execution for in-scope entities. A TIBER-EU test conducted after 17 Jan 2025 against the updated TIBER-EU-DORA-aligned guides counts toward the cycle.

### Pooled TLPT (Article 26(5))

Multiple entities sharing the same critical ICT provider can run a joint TLPT against that provider, sharing costs. Common pattern: several banks pooling for a CTPP test against a hyperscaler or a critical SaaS.

## TIBER-EU as the execution framework

TIBER-EU pre-dates DORA but the ECB has formally positioned it as the implementation framework. The **TIBER-EU SSM Implementation Guide** (Nov 2025) makes this explicit for ECB-supervised institutions.

National-level implementations and authorities (as of mid-2026):

| Country | Authority | Status |
|---|---|---|
| Germany | Bundesbank + BaFin | Active (TIBER-DE) |
| Netherlands | DNB | Active (TIBER-NL, longest-running) |
| France | Banque de France / ACPR | Active (TIBER-FR) |
| Luxembourg | BCL + CSSF | Active (TIBER-LU) |
| Belgium | NBB | Active (TIBER-BE) |
| Ireland | Central Bank of Ireland | Active (TIBER-IE) |
| ECB / SSM banks | ECB DG-Macroprudential | Active per SSM Implementation Guide |

If the entity sits in a country where the NCA has not adopted TIBER-EU, DORA's RTS criteria still apply directly. Practically, those NCAs are converging on TIBER-EU anyway.

### The five TIBER-EU phases (DORA-aligned)

#### 1. Preparation phase

- The entity forms a **White Team** (3–7 senior staff, typically CISO, head of resilience, head of legal, sometimes one board member).
- TLPT authority confirms scope and approves the project plan.
- Tester independence verified. **The threat intelligence (TI) provider and the red team must be different organizations** — no exceptions.
- Insurance, indemnification, and stop conditions formalised.
- "Crown jewels" identified and translated to critical/important functions.

#### 2. Targeted Threat Intelligence (TTI) phase

- Independent TI provider produces a Targeted Threat Intelligence Report.
- Inputs: entity profile, sector, geography, tech stack, history of incidents, known adversaries.
- Output: realistic threat actor profiles, mapped TTPs (using MITRE ATT&CK), and 3–5 candidate attack scenarios.
- Approved by White Team and TLPT authority.

#### 3. Red Team Test Plan

- The red team consumes the TTI report and converts it into an executable test plan.
- Scenarios map to ATT&CK techniques. Each scenario has objectives, success criteria, and a kill-chain outline.
- Cloud-specific scenarios commonly include: stolen identity provider credentials, leaked CI/CD secrets, supply-chain compromise of a third-party SaaS, exposed S3/Storage Account, SSRF to IMDS in a public web app.
- Plan signed off by all parties before active testing.

#### 4. Active red team test (typically 12–16 weeks)

- Covert. Live production. Only the White Team knows.
- Initial access methods spelled out in the plan. Common ones: phishing, leaked secret simulation (the entity "plants" a credential in a public repo for the TI to find), assumed-breach laptop, exposed cloud endpoint.
- Cloud control plane is fair game — Entra ID, AWS root organisations, GCP organisation IAM.
- Daily / weekly checkpoints with White Team for safety only, not for tactical guidance.

#### 5. Closure phase

- **Replay workshop** (purple team). Red team walks the Blue Team through every step. Detection coverage scored per ATT&CK technique.
- Root-cause analysis on missed detections.
- **Attestation** issued by the TLPT authority once remediation plan is in place.
- Aggregated/anonymised findings shared in sector circles (e.g. via Euro Cyber Resilience Board, FS-ISAC).

## What this means operationally for cloud testers

The cloud parts of a DORA TLPT typically span:

- **Identity provider compromise.** Entra ID, Okta, Ping. Test for legacy auth, dormant service principals, over-permissioned apps, conditional-access bypass paths (see [Mollema + Bader research](https://github.com/f-bader/EntraTokenAid)).
- **CI/CD compromise.** GitHub Actions, GitLab Runners, Azure DevOps pipelines with OIDC trust to cloud. Christophe Tafani-Dereeper's work on OIDC abuse is the reference.
- **Cloud control plane abuse.** Cross-account/cross-subscription via trust misconfigurations. Pacu, CloudFox, AzureHound for path discovery.
- **Data exfil from cloud storage.** S3, Storage Accounts, GCS. Validate detective controls (GuardDuty S3 protection, Defender for Storage, GCS audit logs).
- **Detection assessment against critical functions.** Can the SOC see lateral movement Entra ID → Azure subscriptions → critical workload? Time-to-detect, time-to-respond.

## Documentation a TLPT report must contain

Per the RTS and TIBER-EU guides:

1. Executive summary signed by the senior responsible officer of the testing entity.
2. Scope statement covering all critical/important functions tested.
3. Detailed attack narrative (each scenario, each phase).
4. Detection assessment with timing.
5. Findings list with severity, business impact, MITRE ATT&CK mapping, and remediation.
6. Comparison vs. TTI baseline (was the predicted threat representative?).
7. Remediation plan with owner, deadline, evidence requirements.
8. Attestation form for the TLPT authority.

## References

- [DORA full text (EUR-Lex)](https://eur-lex.europa.eu/eli/reg/2022/2554/oj)
- [DORA TLPT RTS (Reg. 2025/1190)](https://eur-lex.europa.eu/eli/reg_del/2025/1190)
- [TIBER-EU framework documentation](https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu)
- [TIBER-EU SSM Implementation Guide (Nov 2025)](https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu/html/index.en.html) — bookmark for ECB-supervised institutions
- [TIBER.info](https://tiber.info) — community resource maintaining current status across all NCAs

## Common pitfalls (from real engagements)

- **Mixing TI and red team vendors.** Hard violation. The RTS will reject the test.
- **Testing only sandbox / pre-prod.** Doesn't satisfy Article 26. Production or it doesn't count.
- **White Team too large.** Becomes impossible to keep covert. Keep it tight.
- **Forgetting the cloud control plane.** Critical functions today run on cloud-native services. If the test doesn't include attempted control-plane compromise, the regulator will ask why.
- **Inadequate threat intelligence.** "Generic ransomware TTPs" doesn't satisfy "targeted". The TI must be entity-specific.
