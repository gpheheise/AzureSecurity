# MITRE ATT&CK Cloud Mapping

This maps the repo's kill-chain structure to the MITRE ATT&CK Cloud techniques, so you can tie cookbook actions to a framework clients and SOCs recognize. Useful for scoping coverage, building detection requirements, and writing the "techniques exercised" section of a red team or TLPT report.

Aligned to the ATT&CK Enterprise Cloud matrix (platforms: Office Suite, Identity Provider, SaaS, IaaS). The matrix evolves; the canonical, current source is:

- Enterprise Cloud matrix: https://attack.mitre.org/matrices/enterprise/cloud/
- IaaS sub-matrix: https://attack.mitre.org/matrices/enterprise/cloud/iaas/
- ATT&CK Navigator (build a coverage layer): https://mitre-attack.github.io/attack-navigator/

Reference point for this doc: ATT&CK v18.x (current as of early 2026). Verify technique IDs against the live matrix before quoting in a deliverable, since sub-techniques are occasionally added or restructured.

## Kill chain to ATT&CK tactic crosswalk

The repo cookbooks use a linear kill chain. ATT&CK tactics are not strictly linear, but they map as follows:

| Repo phase | ATT&CK tactic(s) |
|---|---|
| Recon | Reconnaissance, Resource Development |
| Initial Access | Initial Access, Execution |
| Enumeration | Discovery |
| Privilege Escalation | Privilege Escalation, Credential Access |
| Lateral Movement | Lateral Movement |
| Persistence | Persistence, Defense Evasion |
| Data Exfiltration | Collection, Exfiltration, Impact |

## Techniques by tactic

Each table lists the techniques most relevant to cloud offensive work and where the repo covers them. `IaaS` = AWS/Azure/GCP infrastructure, `IdP` = Identity Provider (Entra ID, etc.), `Office` = Office Suite (M365), `SaaS` = software-as-a-service.

### Reconnaissance

| Technique | ID | Platforms | Covered in |
|---|---|---|---|
| Search Open Websites/Domains | T1593 | All | Cookbook recon |
| Search Open Technical Databases | T1596 | All | Cookbook recon |
| Active Scanning | T1595 | IaaS | Cookbook recon |
| Gather Victim Network Information | T1590 | IaaS | Cookbook recon |

### Initial Access

| Technique | ID | Platforms | Covered in |
|---|---|---|---|
| Valid Accounts: Cloud Accounts | T1078.004 | IaaS, IdP, Office, SaaS | All cookbooks, initial access |
| Valid Accounts: Default Accounts | T1078.001 | IaaS | AWS/GCP cookbook |
| Exploit Public-Facing Application | T1190 | IaaS | AWS cookbook (SSRF to IMDS) |
| Phishing | T1566 | IdP, Office | Azure cookbook (device code, consent) |
| Steal Application Access Token | T1528 | IdP, Office, SaaS | Azure cookbook (consent phishing) |
| Trusted Relationship | T1199 | IaaS, IdP, SaaS | Azure/GCP (federation, cross-tenant) |

### Execution

| Technique | ID | Platforms | Covered in |
|---|---|---|---|
| Serverless Execution | T1648 | IaaS, SaaS | AWS (Lambda), GCP (Functions) |
| Cloud Administration Command | T1651 | IaaS | AWS (SSM RunCommand), Azure (RunCommand) |
| Command and Scripting Interpreter | T1059 | IaaS | All cookbooks |

### Persistence

| Technique | ID | Platforms | Covered in |
|---|---|---|---|
| Account Manipulation: Additional Cloud Credentials | T1098.001 | IaaS, IdP | All cookbooks, persistence |
| Account Manipulation: Additional Cloud Roles | T1098.003 | IaaS, IdP | AWS/GCP IAM, Azure RBAC |
| Account Manipulation: Device Registration | T1098.005 | IdP | Azure cookbook |
| Create Account: Cloud Account | T1136.003 | IaaS, IdP | All cookbooks |
| Modify Authentication Process: Hybrid Identity | T1556.007 | IdP | Azure (AADConnect, federation) |
| Modify Authentication Process: Conditional Access Policies | T1556.009 | IdP | Azure (CA tampering) |
| Valid Accounts: Cloud Accounts | T1078.004 | All | All cookbooks |

### Privilege Escalation

| Technique | ID | Platforms | Covered in |
|---|---|---|---|
| Abuse Elevation Control Mechanism | T1548 | IaaS, IdP | AWS (21 paths), GCP (30 paths) |
| Account Manipulation | T1098 | IaaS, IdP | All cookbooks, privesc |
| Valid Accounts: Cloud Accounts | T1078.004 | All | All cookbooks |
| Domain Policy Modification: Trust Modification | T1484.002 | IdP | Azure (federation trust) |

### Credential Access

| Technique | ID | Platforms | Covered in |
|---|---|---|---|
| Unsecured Credentials: Cloud Instance Metadata API | T1552.005 | IaaS | AWS (IMDS), GCP (metadata) |
| Unsecured Credentials: Credentials in Files | T1552.001 | IaaS | All (config, state files) |
| Unsecured Credentials: Private Keys | T1552.004 | IaaS, IdP | GCP (SA keys), Azure (certs) |
| Credentials from Password Stores: Cloud Secrets Management Stores | T1555.006 | IaaS | AWS (Secrets Mgr), Azure (Key Vault), GCP (Secret Mgr) |
| Forge Web Credentials: SAML Tokens | T1606.002 | IdP | Azure (Golden SAML) |
| Forge Web Credentials: Web Cookies | T1606.001 | IdP, SaaS | Azure (token theft) |
| Steal Application Access Token | T1528 | IdP, Office | Azure (consent) |
| Brute Force | T1110 | IdP | Azure (password spray) |
| MFA Request Generation | T1621 | IdP | Azure (MFA fatigue) |

### Discovery (Enumeration)

| Technique | ID | Platforms | Covered in |
|---|---|---|---|
| Cloud Service Discovery | T1526 | IaaS, IdP, Office, SaaS | All cookbooks, enum |
| Cloud Infrastructure Discovery | T1580 | IaaS | All cookbooks, enum |
| Cloud Service Dashboard | T1538 | IaaS, IdP, Office | All cookbooks |
| Cloud Storage Object Discovery | T1619 | IaaS | AWS (S3), GCP (GCS) |
| Account Discovery: Cloud Account | T1087.004 | IaaS, IdP, Office | All cookbooks |
| Permission Groups Discovery: Cloud Groups | T1069.003 | IaaS, IdP, Office | All cookbooks |
| Container and Resource Discovery | T1613 | Containers | EKS/AKS/GKE sections |

### Lateral Movement

| Technique | ID | Platforms | Covered in |
|---|---|---|---|
| Use Alternate Authentication Material: Application Access Token | T1550.001 | IdP, Office, SaaS | Azure cookbook |
| Use Alternate Authentication Material: Web Session Cookie | T1550.004 | IdP, SaaS | Azure cookbook |
| Remote Services: Cloud Services | T1021.007 | IaaS, IdP | All cookbooks, lateral |
| Trusted Relationship | T1199 | IaaS, IdP, SaaS | Azure/GCP (cross-tenant, cross-project) |
| Valid Accounts: Cloud Accounts | T1078.004 | All | All cookbooks |

### Defense Evasion

| Technique | ID | Platforms | Covered in |
|---|---|---|---|
| Impair Defenses: Disable or Modify Cloud Logs | T1562.008 | IaaS, IdP, Office | All cookbooks (OpSec notes) |
| Modify Cloud Compute Infrastructure | T1578 | IaaS | AWS/Azure/GCP cookbooks |
| Create Snapshot | T1578.001 | IaaS | AWS (EBS snapshot exfil) |
| Create Cloud Instance | T1578.002 | IaaS | AWS/Azure/GCP |
| Revert Cloud Instance | T1578.004 | IaaS | All |
| Unused/Unsupported Cloud Regions | T1535 | IaaS | AWS (region abuse) |
| Use Alternate Authentication Material | T1550 | IdP, Office | Azure cookbook |

### Collection

| Technique | ID | Platforms | Covered in |
|---|---|---|---|
| Data from Cloud Storage | T1530 | IaaS | AWS (S3), Azure (Blob), GCP (GCS) |
| Data from Information Repositories | T1213 | Office, SaaS | Azure (SharePoint, Teams) |
| Email Collection: Remote Email Collection | T1114.002 | Office | Azure (Graph mail) |
| Automated Collection | T1119 | IaaS, Office | All cookbooks, exfil |

### Exfiltration

| Technique | ID | Platforms | Covered in |
|---|---|---|---|
| Transfer Data to Cloud Account | T1537 | IaaS | AWS/Azure/GCP exfil |
| Exfiltration Over Web Service: Exfiltration to Cloud Storage | T1567.002 | IaaS, Office | All cookbooks, exfil |
| Exfiltration Over Web Service | T1567 | All | All cookbooks |

### Impact

| Technique | ID | Platforms | Covered in |
|---|---|---|---|
| Data Destruction | T1485 | IaaS | Findings (Key Vault purge, etc.) |
| Data Encrypted for Impact | T1486 | IaaS | Threat scenarios (ransomware) |
| Resource Hijacking | T1496 | IaaS | Threat scenarios (cryptomining) |
| Account Access Removal | T1531 | IaaS, IdP | Threat scenarios |

## Container techniques (cross-cutting)

Relevant when EKS, AKS, or GKE is in scope. ATT&CK has a dedicated Containers matrix.

| Technique | ID | Covered in |
|---|---|---|
| Deploy Container | T1610 | K8s sections |
| Escape to Host | T1611 | K8s sections (node breakout) |
| Container and Resource Discovery | T1613 | K8s sections |
| Container Administration Command | T1609 | K8s sections |
| Implant Internal Image | T1525 | K8s sections (registry abuse) |

## Using this in reports

For a red team or TLPT deliverable:

1. As you execute, log each action against its technique ID.
2. Build an ATT&CK Navigator layer (JSON) marking techniques attempted, succeeded, and detected.
3. Hand the layer to the blue team. The gap between "attempted" and "detected" is the detection coverage finding.
4. For TLPT under TIBER-EU, the technique-to-detection mapping is part of the Purple Teaming / replay phase.

This turns "we got domain admin" into "we exercised T1098.001, T1548, T1078.004, and T1556.009, of which the SOC detected one," which is the language regulators and mature clients expect.
