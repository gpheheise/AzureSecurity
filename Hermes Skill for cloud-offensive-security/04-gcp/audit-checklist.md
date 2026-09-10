# GCP Audit Checklist

CIS Google Cloud Platform Foundation Benchmark v3.0.0 aligned. Each item: manual command, what to look for, finding ID.

Context setup:

```bash
gcloud auth login
gcloud config set project $PROJECT_ID
export PROJECT_ID=$(gcloud config get-value project)
export ORG_ID=$(gcloud organizations list --format="value(name)" | head -1)
```

---

## 1. IAM

### 1.1 Organisation-level policy admin restricted

```bash
gcloud organizations get-iam-policy $ORG_ID --format=json | \
  jq '.bindings[] | select(.role | contains("Owner") or contains("OrganizationAdmin") or contains("BillingAccountAdmin"))'
```

Org admins, Org policy admins, and billing admins should be ≤ 3 each. Watch for `domain:` bindings (entire domain has the role).

**Maps to:** F-GCP-IAM-010 (Excessive org-level admins).

### 1.2 Project Owners count and type

```bash
gcloud projects get-iam-policy $PROJECT_ID --format=json | \
  jq '.bindings[] | select(.role == "roles/owner") | .members'
```

Owners should be a small group of humans + zero service accounts. SA with `roles/owner` = backdoor candidate.

**Maps to:** F-GCP-IAM-011 (Service account holds project Owner role).

### 1.3 User-managed service account keys

```bash
# Find user-managed (rather than Google-managed) SA keys
for sa in $(gcloud iam service-accounts list --format="value(email)"); do
  gcloud iam service-accounts keys list --iam-account=$sa --format=json | \
    jq -r ".[] | select(.keyType == \"USER_MANAGED\") | \"$sa : \" + .name + \" : \" + .validAfterTime"
done
```

User-managed keys = long-lived secrets. CIS recommends rotating every 90 days. Keys older than 90 days = finding.

**Maps to:** F-GCP-IAM-002 (User-managed SA keys not rotated within 90 days).

### 1.4 SA key creation policy

```bash
# Org policy: iam.disableServiceAccountKeyCreation
gcloud resource-manager org-policies describe iam.disableServiceAccountKeyCreation --organization=$ORG_ID
```

If `enforced: false` or policy missing, anyone with `iam.serviceAccountKeyAdmin` can mint keys. Org policy should enforce this org-wide and projects should request exemption per-need.

**Maps to:** F-GCP-IAM-012 (SA key creation not restricted by org policy).

### 1.5 SA impersonation paths

```bash
# Search for principals with iam.serviceAccounts.actAs / getAccessToken
for proj in $(gcloud projects list --format="value(projectId)"); do
  policy=$(gcloud projects get-iam-policy $proj --format=json)
  echo "$policy" | jq -r ".bindings[] | select(.role == \"roles/iam.serviceAccountUser\" or .role == \"roles/iam.serviceAccountTokenCreator\") | \"$proj : \" + .role + \" : \" + (.members | join(\",\"))"
done
```

Watch for: broad project-level `serviceAccountUser` or `serviceAccountTokenCreator` (covers ALL SAs in the project). Should be granted at SA-level, not project-level.

**Maps to:** F-GCP-IAM-013 (Service Account User/Token Creator granted at project level).

### 1.6 Default service accounts in use

```bash
# Default Compute Engine SA: $PROJECT_NUMBER-compute@developer.gserviceaccount.com
# Default App Engine SA: $PROJECT_ID@appspot.gserviceaccount.com
# Both have roles/editor by default — should be replaced with least-priv SAs

# Find resources using default SAs
gcloud compute instances list --format="value(serviceAccounts.email)" | grep -E 'compute@developer|appspot'
```

Production workloads using the default Compute SA = inherits editor on the project.

**Maps to:** F-GCP-IAM-014 (Default SAs with editor role used by production resources).

### 1.7 Primitive roles (Owner, Editor, Viewer)

CIS 1.8 — primitive roles are the broadest scope and should be avoided. Use predefined / custom roles.

```bash
for proj in $(gcloud projects list --format="value(projectId)"); do
  count=$(gcloud projects get-iam-policy $proj --format=json | \
    jq '[.bindings[] | select(.role | startswith("roles/owner") or startswith("roles/editor") or startswith("roles/viewer")) | .members[]] | length')
  echo "$proj : $count primitive role members"
done
```

**Maps to:** F-GCP-IAM-015 (Primitive roles widely used).

### 1.8 IAM Conditions used for time/IP-bound access

Look for `roles/iam.securityReviewer`, `roles/iam.securityAdmin` granted without conditions.

```bash
gcloud projects get-iam-policy $PROJECT_ID --format=json | \
  jq '.bindings[] | select(.role | contains("admin") or contains("Admin")) | {role:.role, conditions:.condition, members:.members}'
```

`conditions: null` on admin roles = always-on standing privilege. With IAM Conditions, you can require resource path matching, time windows, or membership checks.

**Maps to:** F-GCP-IAM-016 (IAM Conditions not used to scope privileged roles).

### 1.9 Workspace user MFA

```bash
# Workspace admin needed; via Workspace Admin SDK
# Look in admin.google.com → Security → Authentication → 2-step verification
# Should be enforced for all users
```

**Maps to:** F-GCP-WS-002 (Workspace MFA not enforced).

### 1.10 Workspace OAuth app allowlist

In Workspace admin: Security → API Controls → App access control. Default = unrestricted. Recommended = "Allow only trusted apps". Audit which apps are in the allowed list and check for over-broad consent (gmail, drive, full directory).

**Maps to:** F-GCP-WS-003 (OAuth third-party apps not restricted).

---

## 2. Cloud Storage

### 2.1 Buckets accessible to allUsers / allAuthenticatedUsers

```bash
for proj in $(gcloud projects list --format="value(projectId)"); do
  for b in $(gcloud storage buckets list --project=$proj --format="value(name)" 2>/dev/null); do
    policy=$(gcloud storage buckets get-iam-policy gs://$b --format=json 2>/dev/null)
    if echo "$policy" | jq -e '.bindings[] | .members[] | select(. == "allUsers" or . == "allAuthenticatedUsers")' >/dev/null; then
      echo "PUBLIC: $b"
    fi
  done
done
```

**Maps to:** F-GCP-STO-001 (Public GCS bucket), F-GCP-STO-002 (Bucket accessible to allAuthenticatedUsers).

### 2.2 Uniform bucket-level access

CIS 5.2. Without UBLA, both bucket IAM and per-object ACLs apply — chaos.

```bash
gcloud storage buckets list --format="table(name, iamConfiguration.uniformBucketLevelAccess.enabled)"
```

**Maps to:** F-GCP-STO-003 (Uniform Bucket-Level Access not enabled).

### 2.3 Bucket logging

```bash
gcloud storage buckets list --format="table(name, logging.logBucket, logging.logObjectPrefix)"
```

Missing logBucket = no per-bucket data-access trail.

**Maps to:** F-GCP-STO-004 (Bucket logging not configured).

### 2.4 Object versioning

```bash
gcloud storage buckets list --format="table(name, versioning.enabled)"
```

Disabled = no protection against ransomware overwrites.

**Maps to:** F-GCP-STO-005 (Object versioning disabled on critical buckets).

### 2.5 Retention policy / bucket lock

For compliance-critical buckets (audit logs, financial records):

```bash
gcloud storage buckets describe gs://$BUCKET --format=json | jq '.retentionPolicy'
```

**Maps to:** F-GCP-STO-006 (No retention policy on compliance-required buckets).

### 2.6 CMEK on critical buckets

```bash
gcloud storage buckets list --format="table(name, encryption.defaultKmsKeyName)"
```

Empty defaultKmsKeyName = Google-managed encryption (fine for most). CMEK required for some regulated data (KRITIS / DORA / PCI level 1).

**Maps to:** F-GCP-STO-007 (CMEK not configured on buckets requiring customer key control).

---

## 3. Compute Engine

### 3.1 OS Login enforced

```bash
gcloud compute project-info describe --format="value(commonInstanceMetadata.items)" | grep enable-oslogin
gcloud resource-manager org-policies describe compute.requireOsLogin --organization=$ORG_ID
```

OS Login replaces SSH key metadata with IAM-managed access. Required for any audit-aware setup.

**Maps to:** F-GCP-COMP-002 (OS Login not enforced).

### 3.2 Block project-wide SSH keys

```bash
gcloud compute instances list --format="table(name, metadata.items.filter('block-project-ssh-keys'))"
```

Production VMs should block project-wide keys (i.e. only OS Login or instance-specific keys).

**Maps to:** F-GCP-COMP-003 (Project-wide SSH keys not blocked).

### 3.3 IP forwarding

```bash
gcloud compute instances list --format="table(name, canIpForward)"
```

IP forwarding lets a VM act as a router. Few legitimate use cases. Default off.

**Maps to:** F-GCP-COMP-004 (Unnecessary IP forwarding enabled).

### 3.4 Shielded VM

```bash
gcloud compute instances list --format="table(name, shieldedInstanceConfig.enableSecureBoot, shieldedInstanceConfig.enableVtpm, shieldedInstanceConfig.enableIntegrityMonitoring)"
```

All three true = Shielded VM. Without, VM is vulnerable to rootkit / boot-time attacks.

**Maps to:** F-GCP-COMP-005 (Shielded VM not enabled).

### 3.5 Confidential Compute

For regulated workloads handling encrypted-in-use data:

```bash
gcloud compute instances list --format="table(name, confidentialInstanceConfig.enableConfidentialCompute)"
```

**Maps to:** F-GCP-COMP-006 (Confidential Compute not enabled for sensitive workloads).

### 3.6 Disk encryption with CMEK

```bash
gcloud compute disks list --format="table(name, diskEncryptionKey.kmsKeyName)"
```

Empty = Google-managed. For sectors mandating customer key control, finding.

**Maps to:** F-GCP-COMP-007 (VM disks not encrypted with CMEK where required).

### 3.7 Metadata server v1 disabled

```bash
gcloud compute instances list --format="table(name, metadataFingerprint, metadata.items)"
# Look for legacy metadata flag (rare on new VMs)
```

**Maps to:** F-GCP-COMP-001 (Legacy v1 metadata endpoint accessible).

### 3.8 Default service account in use

```bash
gcloud compute instances list --format="table(name, serviceAccounts.email)"
```

`<NUMBER>-compute@developer.gserviceaccount.com` = default Compute SA, has editor. Production VMs should use dedicated least-priv SAs.

**Maps to:** F-GCP-COMP-008 (VM uses default Compute SA with editor role).

### 3.9 Cloud Scopes for SA tokens

```bash
gcloud compute instances list --format="table(name, serviceAccounts.scopes)"
```

`https://www.googleapis.com/auth/cloud-platform` = full access to everything the SA can do. Should be restricted to specific scopes per-VM.

**Maps to:** F-GCP-COMP-009 (VM uses cloud-platform scope when narrower scopes would suffice).

---

## 4. Networking

### 4.1 Default VPC removed

```bash
for proj in $(gcloud projects list --format="value(projectId)"); do
  if gcloud compute networks list --project=$proj --filter="name=default" --format="value(name)" | grep -q default; then
    echo "DEFAULT VPC EXISTS: $proj"
  fi
done
```

Default VPC includes default firewall rules (allow internal, allow icmp from anywhere, allow ssh+rdp+icmp).

**Maps to:** F-GCP-NET-002 (Default VPC not removed).

### 4.2 Firewall rules — broad ingress

```bash
gcloud compute firewall-rules list --format="table(name, direction, sourceRanges, allowed.IPProtocol, allowed.ports)"

# Filter for the worst
gcloud compute firewall-rules list --format=json | \
  jq '.[] | select(.direction == "INGRESS" and (.sourceRanges // []) | index("0.0.0.0/0")) | {name, allowed}'
```

Watch for 0.0.0.0/0 on any port other than 80/443 — particularly 22, 3389, 5432, 1433, 3306, 6379, 9200, 27017.

**Maps to:** F-GCP-NET-003 (Firewall allows broad ingress from internet).

### 4.3 VPC Flow Logs

```bash
gcloud compute networks subnets list --format="table(name, region, network, enableFlowLogs)"
```

Missing for production subnets = no network forensics.

**Maps to:** F-GCP-NET-004 (VPC Flow Logs not enabled).

### 4.4 Cloud DNS DNSSEC

```bash
gcloud dns managed-zones list --format="table(name, dnsName, dnssecConfig.state)"
```

DNSSEC `off` = DNS spoofing possible.

**Maps to:** F-GCP-NET-005 (DNSSEC not enabled on Cloud DNS zones).

### 4.5 VPC Service Controls perimeters

```bash
gcloud access-context-manager perimeters list --policy=$POLICY_ID
gcloud access-context-manager perimeters describe $PERIMETER --policy=$POLICY_ID
```

For projects holding regulated data, VPC SC prevents data exfil even with valid IAM. Missing = no exfil control.

**Maps to:** F-GCP-NET-001 (VPC Service Controls not deployed).

### 4.6 Private Google Access

```bash
gcloud compute networks subnets list --format="table(name, privateIpGoogleAccess)"
```

If VMs need Google API access without public IPs, PGA must be enabled.

**Maps to:** F-GCP-NET-006 (Private Google Access not enabled on private subnets).

---

## 5. Cloud SQL

### 5.1 Public IP + authorized networks

```bash
gcloud sql instances list --format="table(name, ipAddresses, settings.ipConfiguration.authorizedNetworks)"
```

Public IP + `0.0.0.0/0` in authorized networks = SQL login surface for the internet.

**Maps to:** F-GCP-SQL-001 (Cloud SQL publicly accessible / broad authorized networks).

### 5.2 SSL/TLS required

```bash
gcloud sql instances list --format="table(name, settings.ipConfiguration.requireSsl)"
```

`requireSsl: false` = TLS optional.

**Maps to:** F-GCP-SQL-002 (Cloud SQL does not require SSL).

### 5.3 Automated backups

```bash
gcloud sql instances list --format="table(name, settings.backupConfiguration.enabled, settings.backupConfiguration.startTime)"
```

**Maps to:** F-GCP-SQL-003 (Cloud SQL automated backups disabled).

### 5.4 SQL flag audit

```bash
for inst in $(gcloud sql instances list --format="value(name)"); do
  gcloud sql instances describe $inst --format="value(settings.databaseFlags)"
done
```

For PostgreSQL: `log_connections=on`, `log_disconnections=on`, `log_min_messages=warning`, `log_min_error_statement=error`, `log_statement=ddl`.
For MySQL: `slow_query_log=on`, `log_output=FILE`, `general_log` for forensics.
For SQL Server: `external scripts enabled = off`, `cross db ownership chaining = off`, `contained database authentication = off`.

**Maps to:** F-GCP-SQL-004 (Cloud SQL database flags not configured for security).

### 5.5 CMEK

```bash
gcloud sql instances list --format="table(name, diskEncryptionConfiguration.kmsKeyName)"
```

**Maps to:** F-GCP-SQL-005 (Cloud SQL not encrypted with CMEK).

---

## 6. GKE

### 6.1 Cluster version

```bash
gcloud container clusters list --format="table(name, location, currentMasterVersion, status)"
```

Auto-upgrade off + version EOL = finding.

**Maps to:** F-GCP-GKE-003 (GKE cluster running EOL version).

### 6.2 Private cluster

```bash
gcloud container clusters list --format="table(name, privateClusterConfig.enablePrivateNodes, privateClusterConfig.enablePrivateEndpoint, masterAuthorizedNetworksConfig.cidrBlocks)"
```

Public endpoint + no master authorized networks = public k8s API server.

**Maps to:** F-GCP-GKE-004 (GKE control plane publicly accessible).

### 6.3 Workload Identity

```bash
gcloud container clusters list --format="table(name, workloadIdentityConfig.workloadPool)"
```

Empty = nodes use node SA → pods inherit it. Should be enabled and pods should use Workload Identity bindings.

**Maps to:** F-GCP-GKE-002 (Workload Identity not enabled).

### 6.4 Shielded GKE nodes

```bash
gcloud container clusters list --format="table(name, shieldedNodes.enabled)"
```

**Maps to:** F-GCP-GKE-005 (Shielded GKE nodes not enabled).

### 6.5 Binary Authorization

```bash
gcloud container clusters list --format="table(name, binaryAuthorization.evaluationMode)"
```

`DISABLED` = no image signing enforcement.

**Maps to:** F-GCP-GKE-006 (Binary Authorization not enforced).

### 6.6 GKE network policy

```bash
gcloud container clusters list --format="table(name, networkPolicy.enabled, networkPolicy.provider)"
```

**Maps to:** F-GCP-GKE-007 (GKE network policy not enabled).

### 6.7 RBAC + Google groups for GKE

```bash
gcloud container clusters list --format="table(name, authenticatorGroupsConfig.securityGroup)"
```

If using Google Groups for RBAC mapping, securityGroup should be set.

**Maps to:** F-GCP-GKE-008 (GKE RBAC not integrated with Google Groups).

---

## 7. Logging + Monitoring

### 7.1 Cloud Audit Logs — all services

```bash
gcloud projects get-iam-policy $PROJECT_ID --format=json | jq '.auditConfigs'
```

Should include `allServices` with `DATA_READ`, `DATA_WRITE`, `ADMIN_READ` logged. Default: only ADMIN_WRITE for some services.

**Maps to:** F-GCP-LOG-002 (Data Access audit logs not enabled).

### 7.2 Log sink to long-term storage

```bash
gcloud logging sinks list
gcloud logging sinks describe $SINK
```

Need at least one sink to GCS bucket (with retention) or BigQuery dataset for long-term forensics. Default in-Logging retention is 30 days for `_Default` bucket.

**Maps to:** F-GCP-LOG-001 (Logs not retained ≥ 1 year).

### 7.3 Log-based metrics + alerts on critical events

```bash
gcloud logging metrics list
gcloud alpha monitoring policies list
```

CIS expects alerts for: project ownership changes, audit config changes, custom role changes, VPC firewall changes, route changes, SQL config changes, storage IAM changes.

**Maps to:** F-GCP-LOG-003 (No log-based alerts for critical config changes).

### 7.4 Cloud KMS key rotation

```bash
for ring in $(gcloud kms keyrings list --location=global --format="value(name)"); do
  gcloud kms keys list --keyring=$(basename $ring) --location=global --format="table(name, rotationPeriod, nextRotationTime)"
done
```

Empty rotationPeriod on signing/encryption keys = no rotation. Recommended ≤ 90 days for symmetric keys.

**Maps to:** F-GCP-KMS-001 (Cloud KMS keys not rotated).

### 7.5 KMS key access policy

```bash
for ring in $(gcloud kms keyrings list --location=global --format="value(name)"); do
  for key in $(gcloud kms keys list --keyring=$(basename $ring) --location=global --format="value(name)"); do
    gcloud kms keys get-iam-policy $key --keyring=$(basename $ring) --location=global
  done
done
```

Watch for `roles/cloudkms.cryptoKeyEncrypterDecrypter` granted broadly. Should be SA-scoped, ideally with IAM Conditions.

**Maps to:** F-GCP-KMS-002 (KMS key access overly broad).

### 7.6 Security Command Center enabled

SCC is GCP's central security/finding hub. Standard tier is free. Premium tier ($$$) for full features.

```bash
gcloud scc settings services list --organization=$ORG_ID
```

Without SCC, you have no central view of misconfig findings across projects.

**Maps to:** F-GCP-LOG-004 (Security Command Center not configured).

---

## 8. Automation

```bash
# Prowler GCP
prowler gcp --output-formats json-asff html

# ScoutSuite GCP
python3 scout.py gcp -A path/to/sa.json --report-dir ./scout-gcp

# gcp_scanner — Google's own
python3 -m src.gcp_scanner -o gcp-scan -k path/to/sa.json

# Hayat
python3 hayat.py
```

Run all three for any major audit; results vary by tool. Triage manually.

---

## Audit ↔ pentest crosswalk

| Audit finding | Pentest evidence |
|---------------|------------------|
| F-GCP-IAM-002 (user-managed keys old) | Cookbook §2 — leaked SA key |
| F-GCP-IAM-013 (project-level token creator) | Cookbook §4 — SA impersonation |
| F-GCP-STO-001 (public bucket) | Cookbook §1 — GCS recon |
| F-GCP-COMP-001 (legacy metadata) | Cookbook §2 — SSRF to metadata |
| F-GCP-GKE-002 (no Workload Identity) | Cookbook §5 — pod inherits node SA |
| F-GCP-WS-001 (DWD broad scope) | Cookbook §5 — Workspace user impersonation |
