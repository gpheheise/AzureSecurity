# Glossary

Acronyms and terms used across this repo, grouped by area. Cloud offensive work is dense with abbreviations. This is the decoder ring.

## Engagement types and frameworks

| Term | Meaning |
|---|---|
| **Pentest** | Penetration test. Find and demonstrate vulnerabilities in a defined scope. |
| **Red Team** | Goal-driven adversary emulation. Tests detection and response, not just vulnerabilities. |
| **Purple Team** | Red and blue working together, often live, to improve detections in real time. |
| **TLPT** | Threat-Led Penetration Testing. Intelligence-driven red team, mandated under DORA. |
| **TIBER-EU** | Threat Intelligence-Based Ethical Red teaming. The ECB framework that operationalizes TLPT. |
| **RoE** | Rules of Engagement. The agreed boundaries, timing, and constraints of a test. |
| **CTI** | Cyber Threat Intelligence. Feeds the threat scenarios in a TLPT. |
| **White Team** | The small group at the target org aware a red team is running. |
| **Blue Team** | The defenders. SOC, detection engineers, incident responders. |

## Regulations and standards

| Term | Meaning |
|---|---|
| **DORA** | Digital Operational Resilience Act. EU regulation for financial-sector ICT resilience. In force since 17 Jan 2025. |
| **NIS2** | Network and Information Security Directive 2. EU cybersecurity directive across critical sectors. |
| **NIS2UmsG** | The German national law implementing NIS2 (NIS-2-Umsetzungsgesetz). |
| **KRITIS** | Kritische Infrastrukturen. German critical-infrastructure regulation. |
| **KRITIS-Dachgesetz** | The German critical-infrastructure umbrella law. |
| **BSI** | Bundesamt fur Sicherheit in der Informationstechnik. Germany's federal cybersecurity authority. |
| **BSI C5** | Cloud Computing Compliance Criteria Catalogue. BSI's cloud security baseline. |
| **IT-Grundschutz** | BSI's baseline-protection methodology and module catalog. |
| **BaFin** | Bundesanstalt fur Finanzdienstleistungsaufsicht. German federal financial supervisory authority. |
| **NCA** | National Competent Authority. The regulator overseeing DORA in each EU member state. |
| **CBEST** | UK threat-led testing framework run by the Bank of England. |
| **FedRAMP** | US Federal Risk and Authorization Management Program for cloud services. |
| **FISMA** | US Federal Information Security Modernization Act. |
| **CMMC** | Cybersecurity Maturity Model Certification. US defense supply chain. |
| **SOC 2** | Service Organization Control 2. AICPA trust-services audit report. |
| **PCI DSS** | Payment Card Industry Data Security Standard. |
| **HIPAA** | US Health Insurance Portability and Accountability Act. |
| **NIST CSF** | NIST Cybersecurity Framework. |
| **CIS** | Center for Internet Security. Publishes the CIS Benchmarks. |
| **CSA CCM** | Cloud Security Alliance Cloud Controls Matrix. |
| **GDPR / DSGVO** | EU General Data Protection Regulation (Datenschutz-Grundverordnung). |

## Identity and access

| Term | Meaning |
|---|---|
| **IAM** | Identity and Access Management. |
| **IdP** | Identity Provider. Issues authentication tokens (Entra ID, Okta, Ping, Google). |
| **SSO** | Single Sign-On. |
| **MFA** | Multi-Factor Authentication. |
| **CA** | Conditional Access. Entra ID policy engine governing how and when access is granted. |
| **PIM** | Privileged Identity Management. Entra ID just-in-time role elevation. |
| **RBAC** | Role-Based Access Control. |
| **SP** | Service Principal. The identity of an application in Entra ID. |
| **MI** | Managed Identity. An Azure-managed service principal attached to a resource. |
| **SA** | Service Account. A non-human identity (used heavily in GCP and Kubernetes). |
| **FIC** | Federated Identity Credential. Lets an app authenticate from an external IdP without a secret. |
| **DWD** | Domain-Wide Delegation. A GCP service account permitted to impersonate Workspace users. |
| **WIF** | Workload Identity Federation. Exchanges external tokens for cloud credentials without long-lived keys. |
| **IRSA** | IAM Roles for Service Accounts. The AWS mechanism binding EKS pods to IAM roles. |
| **SCIM** | System for Cross-domain Identity Management. User-provisioning protocol. |
| **SAML** | Security Assertion Markup Language. Federation protocol. |
| **OIDC** | OpenID Connect. Identity layer on top of OAuth 2.0. |
| **JWT** | JSON Web Token. |
| **PRT** | Primary Refresh Token. A high-value Entra ID token issued to registered devices. |

## AWS

| Term | Meaning |
|---|---|
| **IMDS** | Instance Metadata Service. The 169.254.169.254 endpoint serving instance credentials. |
| **IMDSv1 / v2** | Token-less (v1) vs session-token-required (v2) metadata access. |
| **STS** | Security Token Service. Issues temporary AWS credentials. |
| **SCP** | Service Control Policy. Org-level guardrail limiting what accounts can do. |
| **EC2** | Elastic Compute Cloud. AWS virtual machines. |
| **EKS** | Elastic Kubernetes Service. |
| **RDS** | Relational Database Service. |
| **KMS** | Key Management Service. |
| **CMK** | Customer Master Key (now "KMS key"). |
| **EBS** | Elastic Block Store. |
| **S3** | Simple Storage Service. |
| **SSRF** | Server-Side Request Forgery. The classic path to IMDS credential theft. |
| **ARN** | Amazon Resource Name. |

## Azure / Entra ID / M365

| Term | Meaning |
|---|---|
| **Entra ID** | Microsoft's cloud identity service (formerly Azure AD). |
| **ARM** | Azure Resource Manager. The Azure control plane for resources. |
| **M365** | Microsoft 365. The productivity and collaboration suite. |
| **AKS** | Azure Kubernetes Service. |
| **NSG** | Network Security Group. Azure's stateful firewall ruleset. |
| **KV** | Key Vault. Azure secrets and key store. |
| **AADConnect** | Azure AD Connect. Syncs on-prem AD to Entra ID (now "Entra Connect"). |
| **ADFS** | Active Directory Federation Services. On-prem federation server. |
| **UAL** | Unified Audit Log. The M365 audit log. |
| **Graph** | Microsoft Graph API. The unified API for M365 and Entra ID. |

## GCP

| Term | Meaning |
|---|---|
| **GCS** | Google Cloud Storage. |
| **GKE** | Google Kubernetes Engine. |
| **GCE** | Google Compute Engine. |
| **VPC SC** | VPC Service Controls. Perimeter controls limiting data movement between projects. |
| **CMEK** | Customer-Managed Encryption Keys. |
| **IAP** | Identity-Aware Proxy. |
| **SCC** | Security Command Center. Google's CSPM and threat detection. |
| **Workspace** | Google Workspace. The productivity suite (formerly G Suite). |

## Kubernetes and containers

| Term | Meaning |
|---|---|
| **K8s** | Kubernetes. |
| **RBAC** | Role-Based Access Control (Kubernetes authorization model). |
| **KSA** | Kubernetes Service Account. |
| **GSA** | Google Service Account (bound to a KSA via Workload Identity in GKE). |
| **CRB** | ClusterRoleBinding. |
| **Pod** | The smallest deployable Kubernetes unit. |

## Tooling and detection

| Term | Meaning |
|---|---|
| **CSPM** | Cloud Security Posture Management. Continuous configuration conformity scanning. |
| **CWPP** | Cloud Workload Protection Platform. |
| **CNAPP** | Cloud-Native Application Protection Platform. CSPM + CWPP combined. |
| **SIEM** | Security Information and Event Management. |
| **SOC** | Security Operations Center. |
| **C2** | Command and Control. Attacker infrastructure for controlling compromised assets. |
| **TTP** | Tactics, Techniques, and Procedures. |
| **ATT&CK** | MITRE's adversary tactics and techniques knowledge base. |
| **IaC** | Infrastructure as Code (Terraform, CloudFormation, Bicep, etc.). |
| **CI/CD** | Continuous Integration / Continuous Deployment. |
| **PoC** | Proof of Concept. |
| **CVE** | Common Vulnerabilities and Exposures. |
| **CVSS** | Common Vulnerability Scoring System. |
| **CWE** | Common Weakness Enumeration. |
| **PD** | Person-Day. Unit of effort estimation. |

## Attack-specific

| Term | Meaning |
|---|---|
| **Kerberoasting** | Requesting service tickets to crack service-account passwords offline. |
| **AS-REP Roasting** | Cracking the encrypted portion of an AS-REP for accounts without pre-auth. |
| **XST** | Cross-Site Tracing. Abuse of the HTTP TRACE method. |
| **IDOR** | Insecure Direct Object Reference. |
| **Consent Phishing** | Tricking a user into granting an attacker's OAuth app access to their data. |
| **Privesc** | Privilege Escalation. |
| **Lateral Movement** | Moving from one compromised asset to another. |
| **Persistence** | Maintaining access across reboots, credential changes, and detection. |
| **Living off the Land** | Using built-in, legitimate tooling to avoid detection. |
