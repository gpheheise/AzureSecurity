# GCP — Findings Mapping

Naming: `F-GCP-<DOMAIN>-<NNN>`. Domains: IAM, STO (Storage), COMP (Compute), GKE, SQL, NET (Networking), KMS, LOG (Logging), WS (Workspace), EXF (Exfil), RECON.

---

## IAM

| ID | Title | Sev |
|----|-------|-----|
| F-GCP-IAM-001 | Broad project-level role grants (over-scoped Editor/Owner) | High |
| F-GCP-IAM-002 | User-managed SA keys not rotated within 90 days | Medium |
| F-GCP-IAM-003 | Overly permissive SA roles (custom or predefined) | High |
| F-GCP-IAM-004 | SA impersonation paths exist (privesc primitive) | High |
| F-GCP-IAM-005 | Deployment Manager Google APIs SA over-privileged (project editor) | High |
| F-GCP-IAM-006 | Cloud Build SA holds editor with no source restrictions | High |
| F-GCP-IAM-007 | Cross-project SA bindings create lateral movement paths | High |
| F-GCP-IAM-010 | Excessive org-level admins (orgAdmin, billingAdmin, policyAdmin) | High |
| F-GCP-IAM-011 | Service account holds project Owner role | High |
| F-GCP-IAM-012 | SA key creation not restricted by org policy | Medium |
| F-GCP-IAM-013 | iam.serviceAccountUser / TokenCreator granted at project level | High |
| F-GCP-IAM-014 | Default Compute SA with editor role used by production workloads | High |
| F-GCP-IAM-015 | Primitive roles (Owner/Editor/Viewer) widely used | Medium |
| F-GCP-IAM-016 | IAM Conditions not used to scope privileged roles | Medium |
| F-GCP-IAM-017 | Workforce / federated identity not used; long-lived SA keys preferred | Medium |

## Workspace / Cloud Identity

| ID | Title | Sev |
|----|-------|-----|
| F-GCP-WS-001 | Service account with Domain-Wide Delegation holds broad Workspace scopes | Critical |
| F-GCP-WS-002 | Workspace MFA not enforced (2-Step Verification) | High |
| F-GCP-WS-003 | OAuth third-party apps not restricted (consent phishing risk) | High |
| F-GCP-WS-004 | Workspace super admin accounts not protected with hardware keys | High |
| F-GCP-WS-005 | Workspace audit logs not exported to long-term storage | Medium |
| F-GCP-WS-006 | Context-Aware Access not configured for sensitive apps | Medium |

## Storage (GCS)

| ID | Title | Sev |
|----|-------|-----|
| F-GCP-STO-001 | Public GCS bucket (allUsers in IAM) | Critical (if data sensitive) |
| F-GCP-STO-002 | Bucket accessible to allAuthenticatedUsers | High |
| F-GCP-STO-003 | Uniform Bucket-Level Access not enabled | Medium |
| F-GCP-STO-004 | Bucket logging not configured | Medium |
| F-GCP-STO-005 | Object versioning disabled on critical buckets | Medium |
| F-GCP-STO-006 | No retention policy on compliance-required buckets | Medium |
| F-GCP-STO-007 | CMEK not configured on buckets requiring customer key control | Medium |
| F-GCP-STO-008 | Bucket allows broad signedURL operations | Low |

## Compute Engine

| ID | Title | Sev |
|----|-------|-----|
| F-GCP-COMP-001 | Legacy v1 metadata endpoint accessible | High |
| F-GCP-COMP-002 | OS Login not enforced | Medium |
| F-GCP-COMP-003 | Project-wide SSH keys not blocked on production VMs | Medium |
| F-GCP-COMP-004 | Unnecessary IP forwarding enabled on VMs | Low |
| F-GCP-COMP-005 | Shielded VM features not enabled | Medium |
| F-GCP-COMP-006 | Confidential Compute not enabled for sensitive workloads | Low (context-dependent) |
| F-GCP-COMP-007 | VM disks not encrypted with CMEK where required | Medium |
| F-GCP-COMP-008 | VM uses default Compute SA with editor role | High |
| F-GCP-COMP-009 | VM SA uses cloud-platform scope when narrower scopes would suffice | Medium |

## GKE

| ID | Title | Sev |
|----|-------|-----|
| F-GCP-GKE-001 | Metadata endpoint accessible from pods without Workload Identity | High |
| F-GCP-GKE-002 | Workload Identity not enabled | High |
| F-GCP-GKE-003 | GKE cluster running EOL version | High |
| F-GCP-GKE-004 | GKE control plane publicly accessible (no master authorized networks) | High |
| F-GCP-GKE-005 | Shielded GKE nodes not enabled | Medium |
| F-GCP-GKE-006 | Binary Authorization not enforced | Medium |
| F-GCP-GKE-007 | GKE network policy not enabled | Medium |
| F-GCP-GKE-008 | GKE RBAC not integrated with Google Groups | Low |
| F-GCP-GKE-009 | Auto-upgrade disabled on production clusters | Medium |

## Cloud SQL

| ID | Title | Sev |
|----|-------|-----|
| F-GCP-SQL-001 | Cloud SQL publicly accessible (broad authorized networks) | High |
| F-GCP-SQL-002 | Cloud SQL does not require SSL/TLS | High |
| F-GCP-SQL-003 | Cloud SQL automated backups disabled | Medium |
| F-GCP-SQL-004 | Cloud SQL database flags not configured for security/audit | Medium |
| F-GCP-SQL-005 | Cloud SQL not encrypted with CMEK | Low (context-dependent) |
| F-GCP-SQL-006 | Default root password / weak admin password | High |

## Networking

| ID | Title | Sev |
|----|-------|-----|
| F-GCP-NET-001 | VPC Service Controls not deployed for sensitive projects | Medium |
| F-GCP-NET-002 | Default VPC not removed | Low |
| F-GCP-NET-003 | Firewall allows broad ingress from internet (0.0.0.0/0 on management ports) | High |
| F-GCP-NET-004 | VPC Flow Logs not enabled | Medium |
| F-GCP-NET-005 | DNSSEC not enabled on Cloud DNS zones | Medium |
| F-GCP-NET-006 | Private Google Access not enabled on private subnets | Low |
| F-GCP-NET-007 | Cloud Armor / WAF not deployed in front of public services | Medium |

## KMS

| ID | Title | Sev |
|----|-------|-----|
| F-GCP-KMS-001 | Cloud KMS keys not rotated | Medium |
| F-GCP-KMS-002 | KMS key access overly broad (cryptoKeyEncrypterDecrypter granted to broad principals) | High |
| F-GCP-KMS-003 | External Key Manager (EKM) not used for sovereignty-required workloads | Low (context) |

## Logging + Monitoring

| ID | Title | Sev |
|----|-------|-----|
| F-GCP-LOG-001 | Logs not retained ≥ 1 year (no GCS / BQ sink for long-term storage) | Medium |
| F-GCP-LOG-002 | Data Access audit logs not enabled (DATA_READ / DATA_WRITE / ADMIN_READ) | Medium |
| F-GCP-LOG-003 | No log-based alerts for critical config changes | Medium |
| F-GCP-LOG-004 | Security Command Center not configured | Medium |
| F-GCP-LOG-005 | No SIEM coverage / no Chronicle or external SIEM integration | Medium |

## Exfil + DLP

| ID | Title | Sev |
|----|-------|-----|
| F-GCP-EXF-001 | No DLP scan on egress data (Cloud DLP not deployed for sensitive flows) | Medium |
| F-GCP-EXF-002 | Gmail / Drive external sharing not restricted in Workspace | Medium |
| F-GCP-EXF-003 | BigQuery exports to external GCS / non-perimeter projects allowed | Medium |

## Recon (Informational)

| ID | Title | Sev |
|----|-------|-----|
| F-GCP-RECON-001 | Project ID / org metadata exposed publicly | Info |
| F-GCP-RECON-002 | Excessive subdomain disclosure for GCP resources | Low |

---


## Finding template — example

```markdown
### F-GCP-IAM-013 — Service Account Token Creator Role Granted at Project Level

| Field | Value |
|------|------|
| Severity | High |
| CVSSv3.1 (estimated) | 8.1 |
| Affected Asset | GCP Project `<PROJECT_ID>` |
| Tooling | gcloud CLI, manual IAM policy review |
| Status | Open |

**Description**

In project `<PROJECT_ID>`, the role `roles/iam.serviceAccountTokenCreator` is granted to the group `developers@target.com` at the project level. This role allows all members of the group to impersonate any service account in the project and generate access tokens on their behalf (`iam.serviceAccounts.getAccessToken`).

The project contains several service accounts with elevated privileges, including `prod-deployment-sa@<PROJECT_ID>.iam.gserviceaccount.com` which holds `roles/owner` at project level.

**Risk**

Any developer in the group can impersonate `prod-deployment-sa` and thereby exercise all owner permissions on the project, including read/write access to all resources, modification of the IAM policy, and deletion of audit logs.

This configuration bypasses the principle of least privilege and represents a direct privilege escalation path. In practice, users with `roles/iam.serviceAccountTokenCreator` at project scope can elevate to project owner via any sufficiently privileged service account.

**Evidence**

```
$ gcloud projects test-iam-permissions <PROJECT_ID> \
    --permissions=iam.serviceAccounts.getAccessToken
permissions:
- iam.serviceAccounts.getAccessToken

$ gcloud auth print-access-token \
    --impersonate-service-account=prod-deployment-sa@<PROJECT_ID>.iam.gserviceaccount.com
WARNING: This command is using service account impersonation. All API calls will be executed as [prod-deployment-sa@<PROJECT_ID>.iam.gserviceaccount.com].
ya29.c.b0AS...
```

**Recommendation**

1. Remove the project-wide `roles/iam.serviceAccountTokenCreator` assignment.
2. If impersonation is required, assign the role at the service account level (not project level) and only for specific service accounts:

```
gcloud iam service-accounts add-iam-policy-binding $TARGET_SA \
  --member="group:specific-team@target.com" \
  --role="roles/iam.serviceAccountTokenCreator"
```

3. Use IAM Conditions to restrict impersonation by time or context.
4. Enable the org policy `iam.disableServiceAccountKeyCreation` to prevent long-lived SA keys.
5. Monitor `iam.googleapis.com/serviceAccounts/getAccessToken` audit logs for anomalous impersonation activity.

**References**

- Google Cloud: [Service account impersonation](https://cloud.google.com/iam/docs/service-account-impersonation)
- Rhino Security Labs: [GCP IAM Privilege Escalation](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation)
- MITRE ATT&CK: T1078.004 (Valid Accounts: Cloud Accounts)
```
