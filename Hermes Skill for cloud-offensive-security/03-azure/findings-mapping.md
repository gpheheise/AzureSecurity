# Azure — Findings Mapping

Catalog of Azure / Entra / M365 findings used across cookbook and audit checklist. Naming: `F-AZ-<DOMAIN>-<NNN>`.

Domains: IAM (Entra identity), RBAC (Azure resource auth), STO (storage), KV (Key Vault), NET (networking), VM (compute), AKS (Kubernetes), DB (databases), LOG (logging/monitoring), HYB (hybrid identity), MI (managed identities), PERS (persistence/backdoor), EXF (exfil), RECON (informational).

Severity guidance — adjust to context:
- **Critical**: tenant compromise, mass data exposure, irreversible.
- **High**: subscription/workload compromise, privesc primitive, sensitive data leak.
- **Medium**: weakens defense in depth, requires chain.
- **Low**: hygiene, information disclosure, would not lead to compromise alone.

---

## IAM (Entra ID)

| ID | Title | Sev | CVSS-ish | C5 | NIS2 |
|----|-------|-----|----------|----|------|
| F-AZ-IAM-001 | Excessive Global Administrator role assignments | High | 7.5 | IDM-09 | Art.21(2)(i) |
| F-AZ-IAM-002 | Missing or misconfigured break-glass accounts | High | 7.0 | IDM-08 | Art.21(2)(c) |
| F-AZ-IAM-003 | MFA not enforced for privileged roles | High | 8.0 | IDM-10 | Art.21(2)(i) |
| F-AZ-IAM-004 | Legacy authentication not blocked by CA | High | 7.5 | IDM-10 | Art.21(2)(i) |
| F-AZ-IAM-005 | No CA policy requires MFA for administrators | High | 8.5 | IDM-10 | Art.21(2)(i) |
| F-AZ-IAM-006 | No CA policy requires MFA for Azure Management | High | 7.5 | IDM-10 | Art.21(2)(i) |
| F-AZ-IAM-007 | Privileged Identity Management (PIM) not used | Medium | 5.5 | IDM-08 | Art.21(2)(i) |
| F-AZ-IAM-008 | User consent for applications not restricted | High | 7.5 | IDM-11 | Art.21(2)(e) |
| F-AZ-IAM-009 | Guest invitation policy too permissive | Medium | 5.0 | IDM-12 | Art.21(2)(d) |
| F-AZ-IAM-010 | Device code flow not blocked by CA | Medium | 6.5 | IDM-10 | Art.21(2)(i) |
| F-AZ-IAM-011 | On-prem-synced accounts hold Global Admin | Critical | 9.0 | IDM-08 | Art.21(2)(i) |
| F-AZ-IAM-012 | Service principals with excessive Graph permissions | High | 8.0 | IDM-11 | Art.21(2)(i) |
| F-AZ-IAM-013 | App registrations with long-lived secrets / no rotation | Medium | 5.5 | IDM-11 | Art.21(2)(i) |
| F-AZ-IAM-014 | Self-service group management enabled (creates privesc paths) | Low | 3.5 | IDM-12 | Art.21(2)(d) |

## RBAC (Azure resource auth)

| ID | Title | Sev | Notes |
|----|-------|-----|-------|
| F-AZ-RBAC-001 | Excessive Owner role assignments on subscription | High | More than 2-3 Owners per sub |
| F-AZ-RBAC-002 | Custom role with overly broad permissions | High | `*` actions or wildcards in critical providers |
| F-AZ-RBAC-003 | Classic administrators present on subscription | Medium | Pre-RBAC legacy admins |
| F-AZ-RBAC-004 | Role assignment scope too broad | Medium | Subscription-scope vs. RG-scope |
| F-AZ-RBAC-005 | Service principal assigned subscription Owner | High | SP with sub Owner = bypass GA boundary |
| F-AZ-RBAC-006 | Broad Management Group role assignment | High | Contributor/Owner at MG scope inherits to every subscription below |

## Storage Accounts

| ID | Title | Sev |
|----|-------|-----|
| F-AZ-STO-001 | Storage account allows HTTP (secure transfer disabled) | High |
| F-AZ-STO-002 | Storage account minimum TLS version below 1.2 | Medium |
| F-AZ-STO-003 | Storage account public network access enabled | High |
| F-AZ-STO-004 | Anonymous container/blob access enabled | Critical (if data sensitive) |
| F-AZ-STO-005 | Storage account keys not subject to rotation policy | Medium |
| F-AZ-STO-006 | Storage account soft delete disabled | Medium |
| F-AZ-STO-007 | No immutability policy on compliance-critical containers | Medium |
| F-AZ-STO-008 | Microsoft Defender for Storage not enabled | Medium |
| F-AZ-STO-009 | Storage account allows shared key auth instead of Entra ID only | Medium |
| F-AZ-STO-010 | Storage account key access not restricted (no key vault integration) | Medium |

## Key Vault

| ID | Title | Sev |
|----|-------|-----|
| F-AZ-KV-001 | Key Vault purge protection disabled | High |
| F-AZ-KV-002 | Key Vault publicly accessible (no private endpoint, no IP restrictions) | High |
| F-AZ-KV-003 | Key Vault still using access policies instead of RBAC | Medium |
| F-AZ-KV-004 | Key Vault diagnostic logs not configured | Medium |
| F-AZ-KV-005 | Key Vault secrets / keys without expiration date | Low |
| F-AZ-KV-006 | Excessive Key Vault administrators / vault-level owners | High |
| F-AZ-KV-007 | Secrets stored in Key Vault never rotated | Medium |

## Networking

| ID | Title | Sev |
|----|-------|-----|
| F-AZ-NET-001 | NSG allows unrestricted inbound traffic from internet | High |
| F-AZ-NET-002 | RDP (3389) or SSH (22) exposed to internet | High |
| F-AZ-NET-003 | Network Watcher not enabled in all regions with workloads | Low |
| F-AZ-NET-004 | NSG flow logs not configured or retention < 90 days | Medium |
| F-AZ-NET-005 | WAF disabled or in detection-only mode on internet AppGW | High |
| F-AZ-NET-006 | DDoS Protection Standard not configured for critical resources | Low |
| F-AZ-NET-007 | Service Endpoints / Private Endpoints not used for PaaS | Medium |
| F-AZ-NET-008 | Bastion not deployed; direct management plane exposure | Medium |

## Compute (VMs)

| ID | Title | Sev |
|----|-------|-----|
| F-AZ-VM-001 | VM disks not encrypted with customer-managed keys (where policy requires) | Medium |
| F-AZ-VM-002 | Just-in-Time VM access not configured for management ports | Medium |
| F-AZ-VM-003 | Managed Identity over-privileged | High |
| F-AZ-VM-004 | User-Assigned Managed Identity attached to publicly accessible VM | High |
| F-AZ-VM-005 | Patch management not configured (Azure Update Manager) | Medium |
| F-AZ-VM-006 | Microsoft Defender for Servers not enabled | Medium |
| F-AZ-VM-007 | Boot diagnostics disabled (forensic readiness) | Low |
| F-AZ-VM-008 | VM extensions installed from untrusted sources | Medium |

## Managed identities

| ID | Title | Sev |
|----|-------|-----|
| F-AZ-MI-001 | User-assigned managed identity shared across workloads (over-broad blast radius) | High |
| F-AZ-MI-002 | Managed identity granted privileged directory / ARM roles enabling escalation | High |

## AKS

| ID | Title | Sev |
|----|-------|-----|
| F-AZ-AKS-001 | AKS cluster not integrated with Entra RBAC | High |
| F-AZ-AKS-002 | AKS API server publicly accessible (no IP allowlist, not private) | High |
| F-AZ-AKS-003 | AKS cluster running unsupported Kubernetes version | High |
| F-AZ-AKS-004 | AKS network policy not enforced | Medium |
| F-AZ-AKS-005 | Azure Policy add-on for AKS disabled | Medium |
| F-AZ-AKS-006 | Defender for Containers not enabled | Medium |
| F-AZ-AKS-007 | AKS cluster admin kubeconfig used instead of Entra-mapped users | Medium |

## Databases

| ID | Title | Sev |
|----|-------|-----|
| F-AZ-DB-001 | Database (SQL / PostgreSQL / MySQL) publicly accessible | High |
| F-AZ-DB-002 | Azure SQL auditing not enabled | Medium |
| F-AZ-DB-003 | Defender for SQL / open-source DBs not enabled | Medium |
| F-AZ-DB-004 | Transparent Data Encryption disabled | Medium |
| F-AZ-DB-005 | SQL Server Entra-only authentication not enforced | Medium |
| F-AZ-DB-006 | Cosmos DB firewall not restrictive (allow all) | High |

## Logging + Monitoring

| ID | Title | Sev |
|----|-------|-----|
| F-AZ-LOG-001 | Activity logs not exported to long-term storage | Medium |
| F-AZ-LOG-002 | Defender for Cloud plans not enabled across required services | Medium |
| F-AZ-LOG-003 | No SIEM coverage for Azure (Sentinel not deployed) | Medium |
| F-AZ-LOG-004 | M365 Unified Audit Log not enabled or retention < 1 year | High |
| F-AZ-LOG-005 | Resource diagnostic settings missing on critical resources | Medium |
| F-AZ-LOG-006 | No activity log alerts for critical configuration changes | Medium |
| F-AZ-LOG-007 | Sentinel UEBA / risk analytics not enabled | Low |

## Hybrid identity

| ID | Title | Sev |
|----|-------|-----|
| F-AZ-HYB-001 | Entra Connect / AADConnect server not hardened (Tier 0 isolation missing) | Critical |
| F-AZ-HYB-002 | Seamless SSO computer account (AZUREADSSOACC$) not protected / no Kerberos password rotation | High |
| F-AZ-HYB-003 | Pass-Through Authentication agents not isolated | High |
| F-AZ-HYB-004 | ADFS server not Tier 0 / privileged | High |
| F-AZ-HYB-005 | Federation trust certificates approaching expiry or weak | Medium |

## Persistence (red team findings)

| ID | Title | Sev |
|----|-------|-----|
| F-AZ-PERS-001 | App secret / cert lifetime not enforced (long-lived creds) | Medium |
| F-AZ-PERS-002 | Federated Identity Credential creation not monitored / alerted | Medium |
| F-AZ-PERS-003 | Federation domain changes not alerted | High |
| F-AZ-PERS-004 | App ownership changes not alerted | Medium |

## Data exfil

| ID | Title | Sev |
|----|-------|-----|
| F-AZ-EXF-001 | No DLP policy on egress from M365 or storage | Medium |
| F-AZ-EXF-002 | Exchange transport rules allow auto-forward to external | High |
| F-AZ-EXF-003 | OneDrive / SharePoint external sharing not restricted | Medium |

## Recon (informational)

| ID | Title | Sev |
|----|-------|-----|
| F-AZ-RECON-001 | Tenant metadata disclosure (always-on, low impact alone) | Info |
| F-AZ-RECON-002 | Excessive subdomain disclosure for Azure resources | Low |

---


## Finding template — example

```markdown
### F-AZ-IAM-008 — User Consent for Applications Not Restricted

| Field | Value |
|------|------|
| Severity | High |
| CVSSv3.1 (estimated) | 7.5 |
| Affected Asset | Microsoft Entra ID Tenant `<TENANT_GUID>` |
| Tooling | Microsoft Graph PowerShell, ROADrecon |
| Status | Open |

**Description**

The Microsoft Entra ID tenant has the user consent policy set to the default `ManagePermissionGrantsForSelf.microsoft-user-default-legacy`. This setting allows any user to grant permissions to arbitrary applications without requiring administrator consent. Users can grant applications permissions such as `Mail.Read`, `Files.Read.All`, and `User.Read.All` without additional review.

**Risk**

This configuration enables attackers to gain persistence and data access in the tenant through OAuth Consent Phishing (also known as the Illicit Consent Grant Attack). An attacker registers a malicious application and lures a user into granting consent. Upon consent, the attacker receives a refresh token that grants persistent access to the user's data, surviving password changes and MFA resets.

The technique is actively used by APT groups (including Midnight Blizzard) and is considered standard tradecraft in cloud red teaming. It bypasses classic authentication controls because the application is legitimately authenticated using the consent granted by the user.

**Evidence**

```
PS> Get-MgPolicyAuthorizationPolicy | Select PermissionGrantPolicyIdsAssignedToDefaultUserRole

PermissionGrantPolicyIdsAssignedToDefaultUserRole
-------------------------------------------------
{ManagePermissionGrantsForSelf.microsoft-user-default-legacy}
```

**Recommendation**

Configure the consent policy to `ManagePermissionGrantsForSelf.microsoft-user-default-low`:

```
PS> Update-MgPolicyAuthorizationPolicy -PermissionGrantPolicyIdsAssignedToDefaultUserRole `
      @("ManagePermissionGrantsForSelf.microsoft-user-default-low")
```

This setting only allows users to consent to applications from verified publishers requesting low-impact permissions. All other permissions require administrator approval via the Admin Consent Workflow (which should also be enabled, so users can request consent for higher-privileged applications without being able to grant it themselves).

**References**

- Microsoft: [Configure user consent settings](https://learn.microsoft.com/entra/identity/enterprise-apps/configure-user-consent)
- MITRE ATT&CK: T1528 (Steal Application Access Token)
```
