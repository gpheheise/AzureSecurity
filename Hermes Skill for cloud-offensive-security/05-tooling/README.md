# Cloud Offensive Tooling

The full catalog. Install commands, what each tool actually does, and when in the kill chain you reach for it. Grouped by platform first because most engagements are single-cloud; multi-cloud tools at the end.

For a fresh attack VM, the minimum baseline is: Python 3.11+, Go 1.22+, .NET 8, PowerShell 7+, Docker, `aws`/`az`/`gcloud` CLIs, BloodHound CE.

```bash
# Quick baseline (Debian/Ubuntu/Kali)
sudo apt update && sudo apt install -y python3-pip python3-venv golang docker.io git pipx jq xq

# AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscli.zip
unzip /tmp/awscli.zip -d /tmp && sudo /tmp/aws/install

# Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# gcloud CLI
curl https://sdk.cloud.google.com | bash && exec -l $SHELL
gcloud components install gke-gcloud-auth-plugin kubectl

# PowerShell 7
sudo apt install -y powershell  # after MS repo added

# pipx for python tooling
pipx ensurepath
```

---

## AWS tooling

### Recon + enumeration

| Tool | Install | What it does |
|------|---------|--------------|
| **[Pacu](https://github.com/RhinoSecurityLabs/pacu)** | `pipx install pacu` | Modular framework. ~50 modules: enum, escalation, persistence. The closest thing to Metasploit for AWS. |
| **[CloudFox](https://github.com/BishopFox/cloudfox)** | `go install github.com/BishopFox/cloudfox@latest` | Situational awareness in an unfamiliar AWS account. Best command: `cloudfox aws all-checks`. |
| **[enumerate-iam](https://github.com/andresriancho/enumerate-iam)** | `git clone … && pip install -r requirements.txt` | Probes all AWS API permissions an access key has. Brute-force but unauth-noisy logging. |
| **[ScoutSuite](https://github.com/nccgroup/ScoutSuite)** | `pipx install scoutsuite` | Multi-cloud audit + recon. HTML reports for free. |
| **[Prowler](https://github.com/prowler-cloud/prowler)** | `pipx install prowler` | The most actively-developed audit tool. CIS / HIPAA / PCI / NIS2 / ISO 27001 frameworks built-in. |
| **[Cloudsplaining](https://github.com/salesforce/cloudsplaining)** | `pipx install cloudsplaining` | IAM policy analyzer. Finds wildcards, broad resource grants, data exfil paths in policies. |
| **[PMapper](https://github.com/nccgroup/PMapper)** | `pipx install principalmapper` | Graphs IAM. Finds privesc paths automatically. Use after CloudFox confirms initial creds. |
| **[awspx](https://github.com/FSecureLABS/awspx)** | `docker pull fsecurelabs/awspx` | Graph-based attack mapping. Less maintained but still useful. |

### Exploitation

| Tool | Install | What it does |
|------|---------|--------------|
| **[aws_pwn](https://github.com/dagrz/aws_pwn)** | `git clone https://github.com/dagrz/aws_pwn` | Reference scripts; mostly historical now but the priv-esc paths file is gold. |
| **[Stratus Red Team](https://github.com/DataDog/stratus-red-team)** | `brew install stratus-red-team` or download from releases | Attack-emulation tool. AWS / Azure / GCP / K8s. Detonates 80+ techniques against your own account for detection testing. |
| **[CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat)** | `pipx install cloudgoat` | Deploys vulnerable AWS scenarios to practice on. |
| **[leonidas](https://github.com/FSecureLABS/leonidas)** | git + Python | AWS attack detection lab — paired technique/detection definitions. |

### Bucket + asset enumeration

| Tool | Install |
|------|---------|
| **[cloud_enum](https://github.com/initstring/cloud_enum)** | `pipx install cloud-enum` |
| **[s3scanner](https://github.com/sa7mon/S3Scanner)** | `pipx install s3scanner` |
| **[Spaces-Finder](https://github.com/appsecco/spaces-finder)** | git |
| **[bucket_finder](https://github.com/digininja/bucket_finder)** | git |

---

## Azure / Entra / M365 tooling

### Recon + enumeration

| Tool | Install | What it does |
|------|---------|--------------|
| **[ROADtools](https://github.com/dirkjanm/ROADtools)** | `pipx install roadrecon roadlib` | The most complete Entra ID enumeration tool. Pulls the whole directory via internal AAD Graph; queryable offline. By Dirk-jan Mollema. |
| **[AzureHound](https://github.com/SpecterOps/AzureHound)** | `go install github.com/SpecterOps/AzureHound@latest` or download binary | BloodHound collector for Entra + ARM. Pair with BloodHound CE. |
| **[BloodHound CE](https://github.com/SpecterOps/BloodHound)** | Docker: `docker run -p 8080:8080 specterops/bloodhound:latest` | Graph analysis UI. New version (CE) merged Enterprise + Open Source codebases. |
| **[Maester](https://maester.dev/)** | `Install-Module Maester` | Tenant-baseline test framework. PowerShell-native, runs Pester tests for CISA / NIST / Microsoft baselines. |
| **[MicroBurst](https://github.com/NetSPI/MicroBurst)** | PowerShell module, `Import-Module ./MicroBurst.psm1` | Karl Fosaaen's collection. Bucket / storage enum, password spraying, post-ex. |
| **[AADInternals](https://github.com/Gerenios/AADInternals)** | `Install-Module AADInternals` | Swiss army knife. Federation, ADFS, AADConnect, tenant primitives. Some functions require admin. |
| **[PowerZure](https://github.com/hausec/PowerZure)** | PowerShell module | Legacy but the patterns are still relevant. |
| **[Stormspotter](https://github.com/Azure/Stormspotter)** | Docker | Microsoft's own Azure graph tool. Less polished than AzureHound but officially supported. |
| **[Prowler (Azure)](https://github.com/prowler-cloud/prowler)** | `pipx install prowler` | Same Prowler, Azure mode. CIS Azure Foundations v3 built in. |

### Exploitation

| Tool | Install | What it does |
|------|---------|--------------|
| **[TokenTacticsV2](https://github.com/f-bader/TokenTacticsV2)** | PowerShell module | Token theft, FOCI client swap, CAE bypass, conditional-access analysis. Fabian Bader's actively-maintained successor to TokenTactics. |
| **[GraphRunner](https://github.com/dafthack/GraphRunner)** | PowerShell module | M365 post-ex. Search mailboxes / Teams / OneDrive, dump everything reachable. Beau Bullock (TrustedSec). |
| **[BARK](https://github.com/BloodHoundAD/BARK)** | PowerShell module | "BloodHound Attack Research Kit". Manual exploit primitives for Azure + Entra. |
| **[MFASweep](https://github.com/dafthack/MFASweep)** | PowerShell module | Identify which protocols accept auth without MFA, per user. Beau Bullock. |
| **[MSOLSpray](https://github.com/dafthack/MSOLSpray)** | PowerShell script | Password spraying via AAD Graph. Smart-lockout aware. |
| **[Invoke-MultiMFA](https://github.com/dafthack/MFASweep)** | Same module as MFASweep | MFA bypass identification. |
| **[ROPCI](https://github.com/loftwise/ROPCI)** | git | Token theft via ROPC (Resource Owner Password Credentials) flow — rare bypass for service accounts. |

### Post-ex / persistence

| Tool | Install |
|------|---------|
| **[Invoke-Phant0m](https://github.com/hlldz/Invoke-Phant0m)** | PowerShell |
| **[o365recon](https://github.com/nyxgeek/o365recon)** | PowerShell |
| **[onedrive_user_enum](https://github.com/nyxgeek/onedrive_user_enum)** | Python |
| **[Invoke-AzureADRecon](https://github.com/nccgroup/AzureADRecon)** | PowerShell |

---

## GCP / Workspace tooling

### Recon + enumeration

| Tool | Install | What it does |
|------|---------|--------------|
| **[GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute)** | `pip install -r requirements.txt` | Bucket existence + per-bucket permission check (the `testIamPermissions` API). |
| **[gcp_scanner](https://github.com/google/gcp_scanner)** | `pip install -r requirements.txt` | Google's own attacker-perspective enumeration. Reads token-accessible resources project-by-project. |
| **[GCP-IAM-Privilege-Escalation](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation)** | git | Not a tool; reference repo. 30+ documented privesc paths with PoC scripts. |
| **[GCPHound](https://github.com/anglepoise-tech/gcphound)** | git | BloodHound-style graph for GCP. Newer, evolving. |
| **[Hayat](https://github.com/DenizParlak/hayat)** | Python | Lightweight GCP auditor. |
| **[Prowler (GCP)](https://github.com/prowler-cloud/prowler)** | `pipx install prowler` | GCP CIS benchmark + others. |
| **[ScoutSuite (GCP)](https://github.com/nccgroup/ScoutSuite)** | `pipx install scoutsuite` | Multi-cloud audit. |

### Exploitation

| Tool | Install | What it does |
|------|---------|--------------|
| **[GCP IAM Privesc PoCs](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation)** | git | All the exploit scripts for the 30 paths. |
| **[oauth2l](https://github.com/google/oauth2l)** | `go install github.com/google/oauth2l@latest` | Token fetching, including JWT-bearer flows (Domain-Wide Delegation impersonation). |
| **[GCPGoat](https://github.com/ine-labs/GCPGoat)** | Terraform | Deploys vulnerable GCP setup to practice on. |

---

## Multi-cloud / cross-cutting

### Audit + benchmarking

| Tool | Coverage |
|------|----------|
| **[Prowler v4](https://github.com/prowler-cloud/prowler)** | AWS, Azure, GCP, K8s — actively maintained, the broadest single-tool option. |
| **[ScoutSuite](https://github.com/nccgroup/ScoutSuite)** | AWS, Azure, GCP, OCI, Alibaba, Aliyun. |
| **[CloudSploit](https://github.com/aquasecurity/cloudsploit)** | AWS, Azure, GCP, OCI, GitHub. |
| **[CheckOV](https://github.com/bridgecrewio/checkov)** | Terraform + CloudFormation + ARM + K8s static analysis. Pair with audits to catch new misconfig before deployment. |
| **[steampipe](https://github.com/turbot/steampipe)** | Query cloud APIs as SQL. Surprisingly powerful for ad-hoc audit ("show me every EC2 instance without an IMDSv2 requirement"). |
| **[cartography](https://github.com/cartography-cncf/cartography)** | Asset graph across AWS / Azure / GCP / GitHub / etc. Neo4j-based. |

### Red team / emulation

| Tool | Use |
|------|-----|
| **[Stratus Red Team](https://github.com/DataDog/stratus-red-team)** | Detonates 80+ multi-cloud techniques. Test detections against MITRE ATT&CK. |
| **[Leonidas](https://github.com/FSecureLABS/leonidas)** | AWS technique-detection pairs. |
| **[Pacu (modules cover S3, EC2, IAM, Lambda etc.)](https://github.com/RhinoSecurityLabs/pacu)** | AWS-only red-team framework. |

### Container + Kubernetes (often co-deployed with cloud)

| Tool | Use |
|------|-----|
| **[kube-hunter](https://github.com/aquasecurity/kube-hunter)** | K8s recon, exploitable misconfigs. |
| **[KubeHound](https://github.com/DataDog/KubeHound)** | BloodHound for Kubernetes RBAC. Datadog. |
| **[kubectl-who-can](https://github.com/aquasecurity/kubectl-who-can)** | Quick RBAC queries. |
| **[Peirates](https://github.com/inguardians/peirates)** | Pod escape + lateral. |
| **[Bust-a-kube](https://github.com/darkbitio/bust-a-kube)** | Cluster cred grab. |
| **[trivy](https://github.com/aquasecurity/trivy)** | Image / IaC scanning. |
| **[grype](https://github.com/anchore/grype)** | Vuln scanner for images and SBOMs. |

### Secret scanning (initial-access primitive)

| Tool | Use |
|------|-----|
| **[trufflehog](https://github.com/trufflesecurity/trufflehog)** | The standard. Scans git, S3, Slack, GitHub. |
| **[gitleaks](https://github.com/gitleaks/gitleaks)** | Faster, lighter. |
| **[noseyparker](https://github.com/praetorian-inc/noseyparker)** | Rule-based, blazing fast, good for huge repos. |

### CI/CD pentesting

| Tool | Use |
|------|-----|
| **[gato-x](https://github.com/AdnaneKhan/gato)** | GitHub Actions / GitLab CI attack tool. |
| **[octoscan](https://github.com/synacktiv/octoscan)** | Audit GitHub Actions workflows for security issues. |
| **[zizmor](https://github.com/woodruffw/zizmor)** | Static analysis for GitHub Actions. |
| **[Chain-Bench](https://github.com/aquasecurity/chain-bench)** | CIS Software Supply Chain Security benchmark. |

### Cloud Shell / Console attack

| Tool | Use |
|------|-----|
| **[AWS Cloud Shell post-ex techniques](https://hackingthe.cloud/aws/post_exploitation/use-aws-cloudshell-to-persist-access/)** | Reference, not tool. |
| **[Azure Cloud Shell privilege references](https://www.netspi.com/blog/technical-blog/cloud-pentesting/leveraging-azure-cloud-shell-as-a-pentester/)** | Reference. |

---

## Bringing it together — a starter dock

For a fresh engagement, this is what gets installed day one:

```bash
# Python tools via pipx (kept isolated)
pipx install pacu prowler scoutsuite cloudsplaining principalmapper s3scanner cloud-enum trufflehog

# Go tools
go install github.com/BishopFox/cloudfox@latest
go install github.com/SpecterOps/AzureHound@latest
go install github.com/google/oauth2l@latest

# PowerShell modules (run in PowerShell 7)
Install-Module -Name AzureAD,Az,Microsoft.Graph,ROADtools,Maester,AADInternals -Force

# Stratus Red Team (binary)
curl -L -o /tmp/stratus.tgz \
  https://github.com/DataDog/stratus-red-team/releases/latest/download/stratus-red-team_$(uname -s)_x86_64.tar.gz
sudo tar xzvf /tmp/stratus.tgz -C /usr/local/bin/ stratus

# BloodHound CE via Docker compose
curl -L https://ghst.ly/getbhce | docker compose -f - up
# UI at http://localhost:8080

# AzureHound (post-Go install)
azurehound --help

# Trivy / Grype
brew install trivy grype  # or apt-package for Ubuntu

# Container goodies
go install github.com/aquasecurity/kube-hunter@latest  # or use the docker image
```

Pin versions for repeatable engagements. Cloud tooling moves fast and CIS benchmarks change yearly; record the tool versions in the report so findings are reproducible.
