# AWS Findings Mapping

Cookbook tests and audit checks mapped to standard finding categories. Use these IDs in your finding repository.

If your existing repository already covers a finding category generically (e.g. you have a generic "Encryption at-rest missing" entry), reuse it. Otherwise, add a new entry to your repository using the IDs and titles below.

## Naming convention

`F-AWS-<DOMAIN>-<NNN>` — domain codes:

- `IAM` — identity and access
- `LOG` — logging and monitoring
- `NET` — networking
- `EC2` — compute (EC2, Auto Scaling)
- `LAM` — serverless (Lambda)
- `S3` — object storage
- `RDS` — relational databases
- `CRY` — cryptography / KMS
- `EKS` — Kubernetes
- `ORG` — organisation / multi-account

## High-impact finding catalog

### IAM (F-AWS-IAM-*)

| ID | Title | Severity | Trigger |
|---|---|---|---|
| F-AWS-IAM-001 | Root account has active access keys | Critical | `AccountAccessKeysPresent=1` |
| F-AWS-IAM-002 | Root account MFA not enabled or not hardware | Critical | `AccountMFAEnabled=0` or virtual MFA only |
| F-AWS-IAM-003 | Root account used recently | High | `password_last_used` ≤ 90d for root |
| F-AWS-IAM-004 | IAM user without MFA | High | Console user with `mfa_active=false` |
| F-AWS-IAM-005 | Access keys not rotated within 90 days | Medium | Key age > 90d |
| F-AWS-IAM-006 | Unused access keys not removed | Medium | Key unused > 90d |
| F-AWS-IAM-007 | Weak password policy | Medium | min < 14, complexity disabled, no rotation |
| F-AWS-IAM-008 | IAM policy with wildcard action and resource | High | `Action: "*"` + `Resource: "*"` |
| F-AWS-IAM-009 | `AdministratorAccess` attached directly to user | Medium | Directly attached managed/inline policy |
| F-AWS-IAM-010 | IAM role with overly permissive trust policy | High | Wildcard principal, missing `ExternalId` |
| F-AWS-IAM-011 | Permission boundaries not in use on privileged roles | Low | No boundary attached |
| F-AWS-IAM-012 | Support role missing | Low | `AWSSupportAccess` not attached anywhere |
| F-AWS-IAM-013 | SSO permission set session duration excessive | Medium | > 4h |
| F-AWS-IAM-014 | MFA not required for SSO access | High | No always-prompt setting |
| F-AWS-IAM-015 | Break-glass user not properly isolated | High | In SSO or no hardware MFA |
| F-AWS-IAM-020 | IAM privilege escalation path identified | Critical | Any of the 21 known paths viable |
| F-AWS-IAM-021 | OIDC trust on GitHub Actions misconfigured | High | Subject filter too permissive |
| F-AWS-IAM-022 | Confused-deputy vulnerability in cross-account role | High | Third-party trust missing `ExternalId` |
| F-AWS-IAM-023 | Inactive IAM users not removed | Low | No activity > 90d |

### Logging (F-AWS-LOG-*)

| ID | Title | Severity | Trigger |
|---|---|---|---|
| F-AWS-LOG-001 | CloudTrail multi-region trail missing | Critical | No `IsMultiRegionTrail=true` trail |
| F-AWS-LOG-002 | CloudTrail data events not captured | High | Management-only or missing S3/Lambda data events |
| F-AWS-LOG-003 | CloudTrail log file validation disabled | High | `LogFileValidationEnabled=false` |
| F-AWS-LOG-004 | CloudTrail bucket access logging disabled | Medium | No server access logs on trail bucket |
| F-AWS-LOG-005 | CloudTrail bucket publicly accessible | Critical | Public ACL or policy |
| F-AWS-LOG-006 | CloudTrail not encrypted with CMK | Medium | `KmsKeyId` not set to CMK |
| F-AWS-LOG-007 | CloudTrail not integrated with CloudWatch Logs | Medium | No CW Logs group |
| F-AWS-LOG-010..023 | CIS-required CloudWatch alarm missing | Medium | Per-alarm |
| F-AWS-LOG-024 | GuardDuty not enabled in all regions | High | At least one region without |
| F-AWS-LOG-025 | GuardDuty S3 Protection disabled | Medium | Feature off |
| F-AWS-LOG-026 | GuardDuty EKS audit log monitoring disabled | Medium | Feature off |
| F-AWS-LOG-027 | GuardDuty Malware Protection disabled | Medium | Feature off |
| F-AWS-LOG-028 | GuardDuty RDS Protection disabled | Medium | Login-activity monitoring off |
| F-AWS-LOG-029 | GuardDuty Lambda Protection disabled | Medium | Network-activity monitoring off |
| F-AWS-LOG-030 | AWS Config not recording all resources / regions | High | Per-region gap |
| F-AWS-LOG-031 | Security Hub not enabled | Medium | Hub not active |
| F-AWS-LOG-032 | Security Hub CIS standard not enabled | Low | Standard off |
| F-AWS-LOG-033 | Findings not routed to ticketing | Low | No EventBridge integration |

### Networking (F-AWS-NET-*)

| ID | Title | Severity | Trigger |
|---|---|---|---|
| F-AWS-NET-001 | Default security group permits traffic | High | Any rule in default SG |
| F-AWS-NET-002 | SSH (22) open to 0.0.0.0/0 | High | SG rule |
| F-AWS-NET-003 | RDP (3389) open to 0.0.0.0/0 | High | SG rule |
| F-AWS-NET-004 | Database port open to 0.0.0.0/0 | Critical | SG rule on 3306/5432/1433/27017/1521 |
| F-AWS-NET-005 | VPC flow logs disabled | Medium | No flow log on VPC |
| F-AWS-NET-006 | Route table allows unintended internet route | Low | 0.0.0.0/0 to IGW unexpectedly |
| F-AWS-NET-007 | No VPC endpoints for S3/DynamoDB | Low | Traffic via NAT |
| F-AWS-NET-008 | ALB/NLB TLS policy outdated | Medium | Pre-TLS 1.2 policy |
| F-AWS-NET-009 | Public ALB without WAF | Low | No web ACL associated |
| F-AWS-NET-010 | ELB access logging disabled | Medium | `access_logs.s3.enabled=false` |

### EC2 (F-AWS-EC2-*)

| ID | Title | Severity | Trigger |
|---|---|---|---|
| F-AWS-EC2-001 | IMDSv1 still enabled (HttpTokens=optional) | High | Per-instance |
| F-AWS-EC2-002 | EBS default encryption disabled | High | Per-region |
| F-AWS-EC2-003 | Unencrypted EBS volumes attached | High | Per-volume |
| F-AWS-EC2-004 | Public IP on backend instance | Medium | Per-instance |
| F-AWS-EC2-005 | SSM Patch Manager not in use | Medium | No scheduled patching |
| F-AWS-EC2-006 | Inbound SSH allowed (no Session Manager) | Medium | SG rule + no SSM agent |

### Lambda (F-AWS-LAM-*)

| ID | Title | Severity | Trigger |
|---|---|---|---|
| F-AWS-LAM-001 | Lambda function policy permits wildcard principal | High | `Principal: "*"` |
| F-AWS-LAM-002 | Secrets stored in Lambda environment variables | High | API keys/passwords in env |
| F-AWS-LAM-003 | Lambda using deprecated runtime | Medium | Pre-LTS |
| F-AWS-LAM-004 | No reserved concurrency on production functions | Low | – |
| F-AWS-LAM-005 | No dead-letter queue / destination | Low | – |
| F-AWS-LAM-006 | Env var encryption with KMS not configured | Medium | No CMK |

### S3 (F-AWS-S3-*)

| ID | Title | Severity | Trigger |
|---|---|---|---|
| F-AWS-S3-001 | Bucket-level public access block weak | Critical | Any of 4 settings false |
| F-AWS-S3-002 | Account-level public access block weak | Critical | Any of 4 settings false |
| F-AWS-S3-003 | Default encryption disabled | High | No SSE-S3/KMS |
| F-AWS-S3-004 | Versioning disabled on critical bucket | Medium | Per-bucket |
| F-AWS-S3-005 | MFA Delete not enabled on critical bucket | Low | Per-bucket |
| F-AWS-S3-006 | Bucket access logging disabled | Medium | – |
| F-AWS-S3-007 | Wildcard principal in bucket policy | Critical | `Principal: "*"` |
| F-AWS-S3-008 | TLS-only not enforced | Medium | No `aws:SecureTransport` deny |
| F-AWS-S3-009 | No lifecycle policy | Low | – |
| F-AWS-S3-010 | Public EBS snapshot | Critical | Group=`all` |
| F-AWS-S3-011 | Unencrypted EBS snapshot | High | – |

### RDS (F-AWS-RDS-*)

| ID | Title | Severity | Trigger |
|---|---|---|---|
| F-AWS-RDS-001 | DB instance publicly accessible | Critical | `PubliclyAccessible=true` |
| F-AWS-RDS-002 | DB storage not encrypted | High | `StorageEncrypted=false` |
| F-AWS-RDS-003 | Backup retention too short | Medium | < 7d |
| F-AWS-RDS-004 | Production DB not Multi-AZ | Low | – |
| F-AWS-RDS-005 | IAM database authentication disabled | Medium | – |
| F-AWS-RDS-006 | Public DB snapshot | Critical | – |
| F-AWS-RDS-007 | Deletion protection disabled | Medium | – |
| F-AWS-RDS-008 | TLS not enforced | Medium | – |
| F-AWS-RDS-009 | DB logs not exported to CloudWatch | Medium | – |

### Cryptography (F-AWS-CRY-*)

| ID | Title | Severity | Trigger |
|---|---|---|---|
| F-AWS-CRY-001 | KMS CMK rotation disabled | Medium | `KeyRotationEnabled=false` |
| F-AWS-CRY-002 | KMS key policy permits wildcard principal | High | – |
| F-AWS-CRY-003 | KMS data events not logged | Medium | – |
| F-AWS-CRY-004 | Pending-deletion CMK not reviewed | Low | – |
| F-AWS-CRY-005 | Imported key without expiry | Low | – |

### EKS / Containers (F-AWS-EKS-*)

| ID | Title | Severity | Trigger |
|---|---|---|---|
| F-AWS-EKS-001 | EKS API endpoint publicly accessible | High | `endpointPublicAccess=true` + open CIDR |
| F-AWS-EKS-002 | EKS control plane logging disabled | High | < 5 log types |
| F-AWS-EKS-003 | EKS secrets not encrypted at rest with KMS | High | No `encryptionConfig` |
| F-AWS-EKS-004 | EKS not using IRSA | Medium | Node IAM role broadly used |
| F-AWS-EKS-005 | Pod Security Standards not enforced | Medium | – |
| F-AWS-EKS-006 | Kubernetes network policies absent | Medium | – |
| F-AWS-EKS-007 | EKS nodes allow IMDSv1 | High | – |

### Organisation (F-AWS-ORG-*)

| ID | Title | Severity | Trigger |
|---|---|---|---|
| F-AWS-ORG-001 | No multi-account organisation structure | Medium | Standalone account |
| F-AWS-ORG-002 | No SCP restricting allowed regions | Medium | – |
| F-AWS-ORG-003 | SCPs don't protect CloudTrail/Config/GuardDuty | High | – |
| F-AWS-ORG-004 | No delegated admin for security services | Medium | – |
| F-AWS-ORG-005 | No Control Tower / Landing Zone | Low | – |


## Finding template

Generic skeleton for any of the catalog entries. Adjust to your repository's house style.

```
### F-AWS-S3-001: Public Access Block Not Enabled on S3 Bucket

**Severity**: Critical (CVSS 8.6)
**Affected Asset**: arn:aws:s3:::company-customer-data
**MITRE ATT&CK**: T1530 — Data from Cloud Storage Object

**Description**
The S3 bucket `company-customer-data` does not have Public Access Block
enabled. All four settings (`BlockPublicAcls`, `IgnorePublicAcls`,
`BlockPublicPolicy`, `RestrictPublicBuckets`) are disabled. This allows
configuration mistakes (such as a permissive bucket policy or ACL) to
result in unintended public read access to the bucket contents.

**Evidence**
$ aws s3api get-public-access-block --bucket company-customer-data
{
    "PublicAccessBlockConfiguration": {
        "BlockPublicAcls": false,
        "IgnorePublicAcls": false,
        "BlockPublicPolicy": false,
        "RestrictPublicBuckets": false
    }
}

**Impact**
A misconfigured bucket policy or ACL could silently expose the personal
data stored in this bucket. Where personal data is processed, this also
represents a compliance gap under privacy regulations such as GDPR
Art. 32 (security of processing).

**Recommendation**
Enable all four Public Access Block settings at both the bucket level
and the account level:

$ aws s3api put-public-access-block --bucket company-customer-data \
    --public-access-block-configuration '{
        "BlockPublicAcls": true,
        "IgnorePublicAcls": true,
        "BlockPublicPolicy": true,
        "RestrictPublicBuckets": true
    }'

$ aws s3control put-public-access-block --account-id 123456789012 \
    --public-access-block-configuration '{
        "BlockPublicAcls": true,
        "IgnorePublicAcls": true,
        "BlockPublicPolicy": true,
        "RestrictPublicBuckets": true
    }'

**References**
- CIS AWS Foundations Benchmark v4.0, Control 2.1.5
- AWS Foundational Security Best Practices: S3.8
- CWE-732: Incorrect Permission Assignment for Critical Resource
```

Apply the same skeleton to every finding. Keep `Description`, `Evidence`, `Impact`, `Recommendation`, `References` in that order.
