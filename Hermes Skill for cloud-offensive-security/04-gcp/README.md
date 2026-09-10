# Google Cloud Platform

GCP gets less attention from the offensive community than AWS or Azure, which is exactly why it's worth knowing well. Three things to understand before everything else:

1. **The org > folder > project > resource hierarchy** is the security model. RBAC inherits down. Get this wrong at the org node and the rest of the hardening is theater.
2. **Service accounts are the user accounts that matter.** Almost all production workloads run as SAs. Almost all GCP privesc paths are SA impersonation paths.
3. **IAM Conditions and VPC Service Controls** are GCP's two most under-used controls. When they're missing, broad permissions become exploitable. When they're present, the same permissions are harmless.

## What's in this section

| File | Purpose |
|------|---------|
| [cookbook.md](cookbook.md) | Recon → exfil kill chain for GCP / Workspace |
| [audit-checklist.md](audit-checklist.md) | CIS GCP Foundations v3 aligned audit commands |
| [findings-mapping.md](findings-mapping.md) | F-GCP-* finding catalog |

## Scope before you start

| Scope variant | Includes | Excludes |
|---------------|----------|----------|
| GCP project pentest | One or a few projects, no org-level changes | Workspace, other orgs |
| GCP organisation audit | Org policies, folder structure, all projects | Workspace identity |
| Workspace identity assessment | Cloud Identity / Workspace, federation, MFA, SSO | GCP resources |
| Cloud red team | Org + Workspace + on-prem if synced | Out of scope unless explicit |

Pull the org ID, folder hierarchy, project count, and a list of billing accounts before scoping. A flat single-project setup is not the same engagement as a 60-project org with 4 folders.

## Google testing policy

Google does **not require pre-approval** for testing your own GCP resources. The policy is governed by the [Google Cloud Acceptable Use Policy](https://cloud.google.com/terms/aup) and the [Customer Pentest Statement](https://cloud.google.com/security/pentest):

- Allowed: testing your own resources, simulated attacks on workloads you control.
- Forbidden: testing Google's infrastructure, traffic that violates AUP (DoS, intensive crypto mining, spam, etc.), accessing other customers' data.
- Use [GCP Marketplace's bug bounty test accounts](https://bughunters.google.com/) for hypotheticals against Google infra.

For pentest of services running on GCP that are subject to PCI DSS / SOC 2 / etc., the customer-side scope is the customer's responsibility. Google's [shared responsibility model](https://cloud.google.com/architecture/framework/security/shared-responsibility-shared-fate) gives the boundary.

## Tool stack

| Tool | Purpose | Notes |
|------|---------|-------|
| [gcloud CLI](https://cloud.google.com/sdk/docs/install) | Primary interaction | Day one. |
| [gcloud Shell](https://cloud.google.com/shell) | Browser-based, pre-authed | If you've compromised a console session. |
| [Prowler](https://github.com/prowler-cloud/prowler) | Multi-cloud audit (GCP included) | Day one. |
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | Audit | Alternative to Prowler. |
| [GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute) | Unauth GCS bucket discovery | Recon. |
| [GCP-IAM-Privilege-Escalation](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation) | Reference for ~30 GCP privesc paths | Required reading. |
| [GCPHound](https://github.com/anglepoise-tech/gcphound) | BloodHound-style graph for GCP | Newer, evolving. |
| [Stratus Red Team](https://github.com/DataDog/stratus-red-team) | Attack emulation (multi-cloud incl. GCP) | Audit + detection testing. |
| [enumerate-iam (gcp branch)](https://github.com/andresriancho/enumerate-iam) | Permission enumeration via API probes | Initial enum. |
| [gcp_enum.sh / gcp_scanner](https://github.com/google/gcp_scanner) | Google's own attacker-perspective enum | Surprisingly useful. |
| [Hayat](https://github.com/DenizParlak/hayat) | GCP auditing tool | Lightweight check. |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) + [gitleaks](https://github.com/gitleaks/gitleaks) | Secrets in code / SA keys leaked | Always. |

## German market context

GCP adoption in DACH is lower than AWS or Azure but growing in regulated finance and KRITIS sectors via Google Cloud Frankfurt + sovereign cloud offerings (T-Systems' partner cloud, GCP Sovereign Controls). For BaFin / BSI scrutiny on GCP workloads, the relevant frameworks are still C5 + KRITIS + DORA. The audit checklist flags C5 IDs where they apply.
