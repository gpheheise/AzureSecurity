# Azure / Entra ID / M365

Azure is three things stacked on top of each other and pentesters keep treating them as one. Don't. They have different boundaries, different auth models, different logging surfaces:

- **Entra ID (formerly Azure AD)** — the identity plane. Tenants, users, apps, service principals, conditional access, MFA, federation. Same tenant backs Microsoft 365.
- **Azure Resource Manager (ARM)** — the resource plane. Subscriptions, resource groups, VMs, storage, Key Vault, networking. Authorised via Entra principals + RBAC.
- **Microsoft 365** — the productivity plane. Exchange Online, SharePoint, Teams, OneDrive. Backed by the same Entra tenant; uses its own permission model on top (Exchange roles, SharePoint permissions).

A tenant compromise is not a subscription compromise and a subscription compromise is not a tenant compromise. Cross-plane pivots are where the kills happen.

## What's in this section

| File | Purpose |
|------|---------|
| [cookbook.md](cookbook.md) | Recon → exfil kill chain across Entra/ARM/M365 |
| [audit-checklist.md](audit-checklist.md) | Manual audit commands, CIS Azure Foundations v3 aligned, mapped to findings |
| [findings-mapping.md](findings-mapping.md) | F-AZ-* finding catalog with template |

## Scope before you start

| Scope variant | Includes | Excludes |
|---------------|----------|----------|
| Entra-only assessment | Tenant config, CA policies, app registrations, MFA, federation, PIM | Subscription resources, M365 service config |
| Azure platform pentest | Subscriptions, RBAC, VMs, storage, Key Vault, AKS | Tenant-level config beyond what's needed for RBAC |
| M365 security assessment | Exchange Online, SharePoint, Teams, OneDrive, Defender for O365 | Custom apps on Azure infra |
| Cloud red team | All of the above plus on-prem pivot via AADConnect | Out of scope unless explicit |

Pull the tenant ID, subscription count, and a list of enterprise applications before scoping. A tenant with 800 enterprise apps and three GA accounts is not the same engagement as a tenant with 12 apps and twenty Owners.

## Microsoft testing policy

Microsoft does **not require pre-approval** for pentests against your own tenant. The [Microsoft Cloud Unified Penetration Testing Rules of Engagement](https://www.microsoft.com/en-us/msrc/pentest-rules-of-engagement) define what's allowed:

- Allowed: testing apps and services you own/control, simulated attacks against your resources.
- Forbidden: DoS, intensive fuzzing against the platform itself, accessing other tenants' data, social engineering against Microsoft employees.
- Phishing simulations against your own users are allowed but use the [Attack Simulator](https://learn.microsoft.com/microsoft-365/security/office-365-security/attack-simulation-training-get-started) if you want them to appear in defender telemetry intentionally.

For TIBER-EU / DORA TLPT on Microsoft-resident workloads: testing your own tenant is fine; testing Microsoft's platform is not. See [../01-standards-and-regulations/eu-dora-tlpt.md](../01-standards-and-regulations/eu-dora-tlpt.md).

## Tool stack

Day-one install list. See [../05-tooling/](../05-tooling/) for the full catalog and install commands.

| Tool | What it does | When |
|------|--------------|------|
| [ROADtools](https://github.com/dirkjanm/ROADtools) | Entra ID enumeration via internal Graph (roadrecon) | Always, day one. |
| [AzureHound](https://github.com/SpecterOps/AzureHound) | BloodHound collector for Entra + ARM | Day one if you have any creds. |
| [BloodHound CE](https://github.com/SpecterOps/BloodHound) | Graph analysis | Pair with AzureHound. |
| [GraphRunner](https://github.com/dafthack/GraphRunner) | M365 post-exploitation via Graph | Once you have a user token. |
| [MicroBurst](https://github.com/NetSPI/MicroBurst) | Azure recon + storage account enum | Unauth recon. |
| [TokenTacticsV2](https://github.com/f-bader/TokenTacticsV2) | Token manipulation, FOCI abuse, CAE | When you have a refresh token. |
| [MFASweep](https://github.com/dafthack/MFASweep) | Identify protocols that bypass MFA per user | Initial access phase. |
| [AADInternals](https://github.com/Gerenios/AADInternals) | Swiss army knife — federation, ADFS, AADConnect, identity | Advanced. |
| [Stormspotter](https://github.com/Azure/Stormspotter) | Microsoft's own Azure graph tool | Alternative to AzureHound for ARM. |
| [BARK](https://github.com/BloodHoundAD/BARK) | PowerShell module for Graph + ARM abuse | Manual exploitation. |
| [PowerZure](https://github.com/hausec/PowerZure) | Azure attack scripts | Legacy but useful patterns. |
| [Prowler](https://github.com/prowler-cloud/prowler) | Audit + benchmark scan (also covers Azure) | Audits, baselining. |

## German market context

DACH enterprise clients typically run multi-tenant M365 + Azure setups, often with on-prem ADFS or AADConnect still in place. DACH regulators (BaFin, BSI) care about: tenant-level admin sprawl, federation trust chains, M365 data residency, Defender for Cloud coverage, and Log Analytics retention vs the requirements in the relevant Aufsichtsschreiben. KRITIS operators on Azure need to demonstrate logging and access control mapped to the BSI C5 catalog. The audit checklist flags C5 control IDs where relevant.
