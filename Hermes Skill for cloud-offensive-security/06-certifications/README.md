# Certifications

Cloud security certifications split into three tiers by audience and depth. Pick based on the role, not the badge count.

## Tier 1: Management and Foundational

For leadership, GRC, architects, and anyone who needs vendor-neutral cloud security literacy without hands-on offensive depth.

| Cert | Vendor | Format | Cost (USD) | Focus |
|---|---|---|---|---|
| CCSP | ISC2 | 4hr proctored, 125 MCQ | ~$599 | Vendor-neutral cloud security, architecture, governance, compliance. Requires 5yr IT exp (1yr cloud). The strategic credential for cloud security leadership. |
| CCSK v5 | Cloud Security Alliance | 2hr online, 60 MCQ | ~$395 | CSA Security Guidance, CCM, ENISA. Foundational and globally recognized. No experience requirement. |
| ISC2 CC | ISC2 | 2hr, 100 MCQ | Free (with One Million in Cybersecurity initiative) | Entry-level security baseline. Useful for non-technical staff entering the field. |
| AWS Certified Cloud Practitioner | AWS | 90min, 65 MCQ | $100 | AWS basics. Skip if you're already doing real AWS work, take the SCS-C02 instead. |
| Azure AZ-900 | Microsoft | 60min, 40-60 MCQ | $99 | Azure fundamentals. Same logic as the AWS one. Stepping stone only. |
| Google Cloud Digital Leader | Google | 90min, 50-60 MCQ | $99 | GCP business value angle. Skim-level. |

## Tier 2: Platform Practitioner (defender-leaning, useful for offensive context)

Vendor security certs. Required reading even for offensive work because you need to know what defenders see, what controls exist, and which knobs are turned.

| Cert | Vendor | Code | Cost (USD) | Notes |
|---|---|---|---|---|
| AWS Security Specialty | AWS | SCS-C02 | $300 | The reference cert for AWS security. Covers IAM, detection, infrastructure, data protection, IR. Heavy on services (GuardDuty, Macie, Inspector, Detective, Security Hub). Hands-on AWS experience required to pass realistically. |
| Azure Security Engineer | Microsoft | AZ-500 | $165 | Retiring August 31, 2026. Microsoft is consolidating into SC-100 + SC-200 + SC-300. If you're starting now, plan around the SC-series. |
| Microsoft Cybersecurity Architect | Microsoft | SC-100 | $165 | Strategic security architect role across Microsoft cloud. Builds on SC-200/SC-300. |
| Microsoft Security Operations Analyst | Microsoft | SC-200 | $165 | Defender, Sentinel, threat hunting. Useful for understanding what's logged and what triggers alerts during your red team work. |
| Microsoft Identity and Access Administrator | Microsoft | SC-300 | $165 | Entra ID deep dive. Critical for any Azure/M365 offensive work. Conditional Access, identity protection, app registrations. |
| Google Professional Cloud Security Engineer | Google | PCSE | $200 | GCP-specific. IAM, VPC, KMS, SCC, GKE security. Less mature ecosystem than AWS/Azure certs but the only Google-issued security cert at this depth. |

## Tier 3: Offensive / Red Team

The certs that actually map to engagement work. Hands-on exams, real labs, no multiple choice or minimal.

### Cloud-specific offensive

| Cert | Vendor | Focus | Cost (USD) | Format |
|---|---|---|---|---|
| **CARTP** (Certified Azure Red Team Professional) | Altered Security | Azure + Entra ID red team baseline. Hybrid attacks, app reg abuse, CA bypass, persistence. | ~$629 (course+lab+exam) | 24hr practical exam |
| **CARTE** (Certified Azure Red Team Expert) | Altered Security | Advanced Azure: deeper persistence, federation, B2B abuse, advanced CA bypass. Builds on CARTP. | ~$1499 | 48hr practical exam |
| **ACRTP** (AWS Cloud Red Team Professional) | Pwned Labs | AWS red team operations end-to-end. Recon through exfil in realistic environments. | ~$799 | Practical exam |
| **MCRTP** (Microsoft Cloud Red Team Professional) | Pwned Labs | Entra ID, M365, Azure. Tyler Ramsbey's curriculum. | ~$799 | Practical exam |
| **GCRTP** (Google Cloud Red Team Professional) | Pwned Labs | GCP offensive ops. Currently the only GCP-focused red team cert worth the name. | ~$799 | Practical exam |
| **M-CRTP3** (Microsoft Cloud Red Team Professional, advanced) | Pwned Labs | Advanced Microsoft cloud. Builds on MCRTP. | ~$999 | Practical exam |
| **MCRTE** (Microsoft Cloud Red Team Expert) | Pwned Labs | Expert tier. Hardest of the Microsoft cloud series. | ~$1299 | Multi-day practical |
| **GIAC GCPN** | SANS | Cloud penetration testing across providers. Pairs with SEC588. | $999 (exam only) | Open-book proctored |
| **eCPTX** | INE | Cloud and advanced AD attack paths. | ~$400 | 48hr practical |

### Adjacent on-prem to cloud (hybrid attack chains)

| Cert | Vendor | Why it matters for cloud |
|---|---|---|
| CRTP (Certified Red Team Professional) | Altered Security | AD attacks. The foundation for any hybrid identity work. AADConnect, federation, Azure AD Connect compromise all start from AD. |
| CRTE (Certified Red Team Expert) | Altered Security | Advanced AD. Forest trust, cross-domain, attack at scale. Critical context for tier-0 cloud control plane work. |
| CRTM (Certified Red Team Master) | Altered Security | The highest in the AD red team series. |
| OSCP | OffSec | Generic offensive baseline. Not cloud but assumed knowledge. |
| OSEP | OffSec | Evasion-focused. Useful for cloud control plane stealth. |
| CRTO (Certified Red Team Operator) | Zero-Point Security | C2 ops with Cobalt Strike. The defender-tooling-aware operator cert. |

### Specialty

| Cert | Vendor | Focus |
|---|---|---|
| Kubernetes CKS | CNCF | Kubernetes security. Required if you're testing EKS/AKS/GKE seriously. |
| GIAC GCSA | SANS | Cloud security automation. DevSecOps angle. |
| GIAC GCLD | SANS | Cloud security essentials, defender side but solid baseline. |

## Recommended sequencing

Depends on where you're starting and where you want to be.

### Starting from on-prem pentest background

1. CCSP or CCSK for vocabulary and governance baseline (skip if you've already done DORA/NIS2 work and know the vocab).
2. AWS SCS-C02 OR Azure SC-300+SC-200 OR Google PCSE depending on your client base.
3. CARTP and ACRTP/MCRTP for first hands-on red team cert in your primary platform.
4. Cross-train: pick up the other two platforms' practitioner cert (Tier 2).
5. CARTE, MCRTE, or the advanced Pwned Labs certs for senior IC track.

### Starting from cloud admin/engineer background

1. SCS-C02 / AZ-500 / PCSE depending on your current role.
2. OSCP first (don't skip foundational offensive).
3. CRTP for AD baseline.
4. CARTP for first cloud red team cert.
5. Branch into ACRTP/MCRTP/GCRTP for cross-platform.

### Starting from management/architect track

1. CCSP for credibility.
2. SC-100 if Microsoft-heavy environment.
3. Pick one tier-2 platform cert to keep your hands close to the work.
4. Skip tier 3 unless transitioning to IC.

## DACH / German market notes

For DACH and German enterprise context:

- **BSI requirements**: BSI doesn't issue or mandate specific commercial certs but the C5 (Cloud Computing Compliance Criteria Catalogue) auditor profile expects CCSP/CCSK-level knowledge.
- **DORA TLPT**: ECB TIBER-EU framework expects red team providers with demonstrable cloud red team experience. Pwned Labs and Altered Security certs are the most operationally relevant. ISO/IEC 27001 lead auditor or CCSP for the testing organization credentials.
- **KRITIS audits**: KRITIS prüfende Stellen guidance prefers ISO 27001 LA, BSI IS-Penetrationstester (German-specific), and sector-relevant operational credentials. The BSI IS-Penetrationstester profile is internal to BSI-zertifizierte Prüfdienstleister and not a public cert.
- **NIS2**: No specific cert mandate at EU level. Sector regulators (BaFin, BNetzA) reference ISO 27001 and CCSP/CCSK frequently.

## Cost reality

Cert costs add up fast. Rough order of magnitude for a full offensive cloud track (one platform deep, two platforms shallow):

```
SCS-C02:        $300
AZ-500/SC-200:  $165
PCSE:           $200
CARTP:          $629
ACRTP:          $799
MCRTP:          $799
CRTP:           $499
OSCP:           $1599
                ------
Approx total:   ~$4990 (excluding training time)
```

Most consultancies will cover cert costs for staff. For independents, prioritize Pwned Labs and Altered Security over SANS GIAC on cost/value.

## What I don't recommend

- **Cert chasing for its own sake**. The Pwned Labs and Altered Security certs are valuable because the labs teach you something. If you're not learning, stop.
- **EC-Council certs (CEH, CPENT, CCSE)**. Industry reputation is mixed at best in serious offensive work. Skip.
- **Generic "cloud" certs from no-name providers**. Stick to vendor-issued (AWS/Azure/Google), CSA, ISC2, GIAC, Pwned Labs, Altered Security, OffSec, Zero-Point Security.

## See also

- [07-training-and-labs](../07-training-and-labs/README.md) for the lab platforms behind these certs.
- [08-community](../08-community/README.md) for the people who built or teach most of them.
