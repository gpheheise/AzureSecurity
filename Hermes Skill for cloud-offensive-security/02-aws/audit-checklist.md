# AWS Audit Checklist

Read-only assessment of an AWS account or organisation against CIS AWS Foundations Benchmark v4 + AWS Foundational Security Best Practices + relevant overlays.

Each check has: command, expected state, severity, mapping to standards, and finding template reference.

Required permissions: `SecurityAudit` + `ViewOnlyAccess` IAM policies. For org-wide: read on `organizations:*`, `config:Select*`.

---

## How to use this checklist

1. Run `prowler aws --profile $PROFILE --severity high critical` for the automated baseline.
2. Use this checklist for manual verification of high-impact items + items Prowler misses or marks falsely.
3. Cross-reference with audit-checklist findings into `findings-mapping.md`.

For Prowler:

```bash
pip install prowler
prowler aws --profile $PROFILE \
  --compliance cis_4.0_aws aws_foundational_security_best_practices_aws \
  --output-formats html csv json
```

For ScoutSuite:

```bash
scout aws --profile $PROFILE --report-dir ./scout-report
```

---

## 1. Identity and access management

### 1.1 Root account hygiene

```bash
# Root account access keys
aws iam get-account-summary | jq '.SummaryMap | {RootAccessKeys: .AccountAccessKeysPresent, RootMFA: .AccountMFAEnabled}'
```

| Check | Expected | Severity | CIS | CCM | Finding |
|---|---|---|---|---|---|
| Root has no access keys | `AccountAccessKeysPresent: 0` | Critical | 1.4 | IAM-02 | F-AWS-IAM-001 |
| Root has hardware MFA | `AccountMFAEnabled: 1` + hardware | Critical | 1.5/1.6 | IAM-09 | F-AWS-IAM-002 |
| Root used recently? | Credential report `password_last_used` for root | High | 1.7 | IAM-02 | F-AWS-IAM-003 |

### 1.2 IAM users

```bash
# Credential report — generate then download
aws iam generate-credential-report
aws iam get-credential-report --query Content --output text | base64 -d > cred-report.csv

# Show users without MFA
awk -F, 'NR>1 && $4=="true" && $8=="false" {print $1}' cred-report.csv

# Show keys not rotated in 90 days
awk -F, -v today=$(date +%s) 'NR>1 && $9!="N/A" {
  d=mktime(gsub("[-:T]"," ",$9));
  if ((today-d)/86400 > 90) print $1, "key1 age:", int((today-d)/86400)
}' cred-report.csv
```

| Check | Expected | Severity | CIS | CCM | Finding |
|---|---|---|---|---|---|
| All console users have MFA | `mfa_active=true` | High | 1.10 | IAM-09 | F-AWS-IAM-004 |
| Access keys rotated ≤ 90d | `access_key_*_last_rotated` ≤ 90d | Medium | 1.14 | IAM-04 | F-AWS-IAM-005 |
| Unused access keys removed | `access_key_*_last_used_date` > 90d → disable | Medium | 1.13 | IAM-04 | F-AWS-IAM-006 |
| Strong password policy | min 14 char, complexity, max age 90d, history 24 | Medium | 1.8/1.9 | IAM-05 | F-AWS-IAM-007 |

### 1.3 Policies and roles

```bash
# Users with admin-equivalent privileges
aws iam list-attached-user-policies --user-name $USER | grep -i AdminAccess
aws iam list-user-policies --user-name $USER

# Find roles with overly permissive trust policies
aws iam list-roles --query 'Roles[?contains(to_string(AssumeRolePolicyDocument), `"AWS":"*"`)]'

# Find inline policies with "*" Action AND "*" Resource
aws iam list-policies --scope Local --only-attached | jq -r '.Policies[].Arn' | while read arn; do
  ver=$(aws iam get-policy --policy-arn $arn --query Policy.DefaultVersionId --output text)
  doc=$(aws iam get-policy-version --policy-arn $arn --version-id $ver --query PolicyVersion.Document --output json)
  if echo $doc | jq -e '.Statement[] | select(.Action=="*" and .Resource=="*" and .Effect=="Allow")' >/dev/null; then
    echo "$arn has *:*"
  fi
done
```

| Check | Expected | Severity | CIS | CCM | Finding |
|---|---|---|---|---|---|
| No inline `"*":"*"` policies | None | High | 1.16 | IAM-10 | F-AWS-IAM-008 |
| No `AdministratorAccess` to users | Admin via roles only | Medium | – | IAM-10 | F-AWS-IAM-009 |
| Role trust policies scoped | External principals have `sts:ExternalId` condition | Medium | – | IAM-10 | F-AWS-IAM-010 |
| Permission boundaries on dev roles | Boundary policy in place | Low | – | IAM-10 | F-AWS-IAM-011 |
| No support role unattached | `AWSSupportAccess` attached to a support role | Low | 1.17 | IAM-10 | F-AWS-IAM-012 |

### 1.4 IAM Identity Center / SSO

```bash
# List instances and applications
aws sso-admin list-instances
aws sso-admin list-permission-sets --instance-arn $INSTANCE_ARN

# Session duration per permission set
for ps in $(aws sso-admin list-permission-sets --instance-arn $INSTANCE_ARN --query 'PermissionSets[]' --output text); do
  aws sso-admin describe-permission-set --instance-arn $INSTANCE_ARN --permission-set-arn $ps \
    --query '{Name:PermissionSet.Name, SessionDuration:PermissionSet.SessionDuration}'
done
```

| Check | Expected | Severity | Finding |
|---|---|---|---|
| Permission sets bounded ≤ 4h | `SessionDuration: PT4H` or less | Medium | F-AWS-IAM-013 |
| MFA required for SSO | Trusted device or always-prompt | High | F-AWS-IAM-014 |
| Break-glass user excluded from SSO and has hardware MFA | Yes | High | F-AWS-IAM-015 |

---

## 2. Logging and monitoring

### 2.1 CloudTrail

```bash
# All trails
aws cloudtrail describe-trails --include-shadow-trails

# Detail per trail
for trail in $(aws cloudtrail describe-trails --query 'trailList[].Name' --output text); do
  echo "=== $trail ==="
  aws cloudtrail get-trail --name $trail
  aws cloudtrail get-trail-status --name $trail
  aws cloudtrail get-event-selectors --trail-name $trail
done
```

| Check | Expected | Severity | CIS | CCM | Finding |
|---|---|---|---|---|---|
| At least one multi-region trail | `IsMultiRegionTrail=true` and `IsLogging=true` | Critical | 3.1 | LOG-04 | F-AWS-LOG-001 |
| Trail logs management + data events | `IncludeManagementEvents=true` + data events for S3/Lambda | High | 3.1/3.10/3.11 | LOG-04 | F-AWS-LOG-002 |
| Log file integrity validation | `LogFileValidationEnabled=true` | High | 3.2 | LOG-08 | F-AWS-LOG-003 |
| Trail bucket access logged | Server access logging on the CloudTrail bucket | Medium | 3.6 | LOG-04 | F-AWS-LOG-004 |
| Trail bucket not publicly accessible | Bucket policy + ACL deny public | Critical | 3.3 | DSP-15 | F-AWS-LOG-005 |
| CMK encrypts trail | `KmsKeyId` set, key is CMK | Medium | 3.7 | CEK-04 | F-AWS-LOG-006 |
| CloudWatch Logs integration | `CloudWatchLogsLogGroupArn` set | Medium | 3.4 | LOG-04 | F-AWS-LOG-007 |

### 2.2 CloudWatch alarms (CIS-required)

CIS requires alarms on 14 specific events. Quick check:

```bash
# List metric filters in the CloudTrail log group
aws logs describe-metric-filters --log-group-name $TRAIL_LOG_GROUP
aws cloudwatch describe-alarms
```

Required alarms (CIS 4.1–4.14):

1. Unauthorized API calls
2. Sign-in without MFA
3. Root account use
4. IAM policy changes
5. CloudTrail config changes
6. AWS Console authentication failures
7. KMS CMK deletion/disable
8. S3 bucket policy changes
9. AWS Config configuration changes
10. Security Group changes
11. Network ACL changes
12. Network Gateway changes
13. Route Table changes
14. VPC changes

Severity: Medium each. Finding: F-AWS-LOG-010 through F-AWS-LOG-023.

### 2.3 GuardDuty

```bash
aws guardduty list-detectors
for det in $(aws guardduty list-detectors --query 'DetectorIds[]' --output text); do
  aws guardduty get-detector --detector-id $det
  # Should be enabled in every region
done
```

| Check | Expected | Severity | Finding |
|---|---|---|---|
| GuardDuty enabled all regions | Detector in every region | High | F-AWS-LOG-024 |
| S3 protection enabled | `DataSources.S3Logs.Status=ENABLED` | Medium | F-AWS-LOG-025 |
| Kubernetes audit logs enabled | EKS audit logs to GuardDuty | Medium | F-AWS-LOG-026 |
| Malware Protection enabled | EBS malware scanning on | Medium | F-AWS-LOG-027 |
| RDS Protection enabled | Login activity monitoring | Medium | F-AWS-LOG-028 |
| Lambda Protection enabled | Network activity monitoring | Medium | F-AWS-LOG-029 |

### 2.4 Config + Security Hub

```bash
aws configservice describe-configuration-recorders
aws configservice describe-delivery-channels
aws securityhub describe-hub
aws securityhub get-enabled-standards
```

| Check | Expected | Severity | Finding |
|---|---|---|---|
| Config recording all resources, all regions | `recordingGroup.allSupported=true` | High | F-AWS-LOG-030 |
| Security Hub enabled with AWS FSBP | Standard enabled | Medium | F-AWS-LOG-031 |
| Security Hub CIS standard enabled | Standard enabled | Low | F-AWS-LOG-032 |
| Findings forwarded to ticketing | EventBridge rule to SOAR / SNS | Low | F-AWS-LOG-033 |

---

## 3. Networking

### 3.1 VPC + Security Groups

```bash
# Default security groups allowing traffic
aws ec2 describe-security-groups --filters Name=group-name,Values=default \
  --query 'SecurityGroups[?length(IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]])>`0`]'

# SGs with 0.0.0.0/0 ingress on sensitive ports
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws ec2 describe-security-groups --region $region \
    --query 'SecurityGroups[?IpPermissions[?(FromPort==`22` || FromPort==`3389` || FromPort==`5432` || FromPort==`3306` || FromPort==`1433`) && IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName]' \
    --output table
done

# VPC flow logs
aws ec2 describe-flow-logs
```

| Check | Expected | Severity | CIS | CCM | Finding |
|---|---|---|---|---|---|
| Default SG denies all | No rules in default SG | High | 5.4 | IVS-03 | F-AWS-NET-001 |
| No SSH (22) from 0.0.0.0/0 | None | High | 5.2 | IVS-03 | F-AWS-NET-002 |
| No RDP (3389) from 0.0.0.0/0 | None | High | 5.2 | IVS-03 | F-AWS-NET-003 |
| No DB ports from 0.0.0.0/0 | None | Critical | – | IVS-03 | F-AWS-NET-004 |
| VPC flow logs on all VPCs | Yes | Medium | 3.9 | LOG-04 | F-AWS-NET-005 |
| Route tables reviewed for unintended 0.0.0.0/0 | NAT/IGW only on intended VPCs | Low | – | IVS-03 | F-AWS-NET-006 |
| VPC endpoints for S3/DynamoDB | In place to avoid egress | Low | – | IVS-04 | F-AWS-NET-007 |

### 3.2 NACLs

```bash
aws ec2 describe-network-acls --filters Name=entry.cidr,Values=0.0.0.0/0 \
  --query 'NetworkAcls[?Entries[?CidrBlock==`0.0.0.0/0` && Egress==`false`]]'
```

Mostly informational; SGs do the heavy lifting. Severity: Low.

### 3.3 Load balancers

```bash
# ALBs / NLBs
aws elbv2 describe-load-balancers
# Check TLS policies
for alb in $(aws elbv2 describe-load-balancers --query 'LoadBalancers[?Type==`application`].LoadBalancerArn' --output text); do
  aws elbv2 describe-listeners --load-balancer-arn $alb \
    --query 'Listeners[?Protocol==`HTTPS`].[ListenerArn,SslPolicy]'
done
```

| Check | Expected | Severity | Finding |
|---|---|---|---|
| HTTPS listeners use TLS 1.2+ policy | `ELBSecurityPolicy-TLS13-1-2-*` or stricter | Medium | F-AWS-NET-008 |
| ALB has WAF attached | WAF web ACL associated | Low | F-AWS-NET-009 |
| Access logs enabled | `access_logs.s3.enabled=true` | Medium | F-AWS-NET-010 |

---

## 4. Compute

### 4.1 EC2

```bash
# IMDSv2 enforcement
aws ec2 describe-instances \
  --query 'Reservations[].Instances[?MetadataOptions.HttpTokens!=`required`].[InstanceId,MetadataOptions.HttpTokens]' \
  --output table

# Public IPs assigned
aws ec2 describe-instances \
  --query 'Reservations[].Instances[?PublicIpAddress!=null].[InstanceId,PublicIpAddress]'

# EBS encryption (account-level default + per-volume)
aws ec2 get-ebs-encryption-by-default
aws ec2 describe-volumes --query 'Volumes[?Encrypted==`false`].[VolumeId,State]'

# Old AMIs / unpatched instances
aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,LaunchTime,ImageId]' --output table
```

| Check | Expected | Severity | CIS | Finding |
|---|---|---|---|---|
| IMDSv2 required on all instances | `HttpTokens=required` | High | 5.6 | F-AWS-EC2-001 |
| EBS encryption by default on | True per region | High | 2.2.1 | F-AWS-EC2-002 |
| All EBS volumes encrypted | None unencrypted | High | 2.2.1 | F-AWS-EC2-003 |
| No public IPs on backend instances | Bastion-only model | Medium | – | F-AWS-EC2-004 |
| Patch Manager managed | SSM Patch Manager schedule | Medium | – | F-AWS-EC2-005 |
| SSM Session Manager instead of SSH | No inbound SSH SGs | Medium | – | F-AWS-EC2-006 |

### 4.2 Lambda

```bash
# Functions with public resource policy
aws lambda list-functions --query 'Functions[].FunctionName' --output text | while read fn; do
  policy=$(aws lambda get-policy --function-name $fn 2>/dev/null)
  if echo "$policy" | grep -q '"Principal":"\*"'; then
    echo "$fn has wildcard principal"
  fi
done

# Environment variables — secrets
aws lambda list-functions --query 'Functions[?Environment.Variables].[FunctionName,Environment.Variables]'

# Outdated runtimes
aws lambda list-functions --query 'Functions[?Runtime==`python3.7` || Runtime==`python3.8` || Runtime==`nodejs14.x` || Runtime==`nodejs16.x`]'
```

| Check | Expected | Severity | Finding |
|---|---|---|---|
| No wildcard principals in function policies | All have specific principals | High | F-AWS-LAM-001 |
| No secrets in environment variables | Use Secrets Manager / Parameter Store | High | F-AWS-LAM-002 |
| Supported runtimes only | Current LTS | Medium | F-AWS-LAM-003 |
| Function-level concurrency limits | Reserved concurrency set | Low | F-AWS-LAM-004 |
| Dead-letter queue configured | DLQ set | Low | F-AWS-LAM-005 |
| KMS CMK encrypts env vars | `KMSKeyArn` set | Medium | F-AWS-LAM-006 |

---

## 5. Storage

### 5.1 S3

```bash
# Public buckets
for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  pab=$(aws s3api get-public-access-block --bucket $bucket 2>/dev/null \
    | jq '.PublicAccessBlockConfiguration')
  if [ -z "$pab" ] || echo "$pab" | jq -e 'any(.[]; .==false)' >/dev/null; then
    echo "$bucket: weak public access block"
  fi
done

# Per-bucket detail
for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  echo "=== $bucket ==="
  aws s3api get-bucket-encryption --bucket $bucket 2>/dev/null
  aws s3api get-bucket-versioning --bucket $bucket
  aws s3api get-bucket-logging --bucket $bucket
  aws s3api get-bucket-policy --bucket $bucket 2>/dev/null | jq -r '.Policy' | jq .
  aws s3api get-bucket-acl --bucket $bucket | jq '.Grants[] | select(.Grantee.URI != null)'
done
```

| Check | Expected | Severity | CIS | CCM | Finding |
|---|---|---|---|---|---|
| Bucket public access block all-true | All 4 settings true | Critical | 2.1.5 | DSP-15 | F-AWS-S3-001 |
| Account-level public access block | All 4 settings true | Critical | 2.1.4 | DSP-15 | F-AWS-S3-002 |
| Default encryption enabled | SSE-S3 or SSE-KMS | High | 2.1.1 | CEK-04 | F-AWS-S3-003 |
| Versioning enabled on critical buckets | Logs, backups, IaC state | Medium | 2.1.2 | DSP-16 | F-AWS-S3-004 |
| MFA Delete on critical buckets | Yes for production | Low | 2.1.2 | DSP-16 | F-AWS-S3-005 |
| Server access logging enabled | Logs to a separate bucket | Medium | – | LOG-04 | F-AWS-S3-006 |
| No wildcard principal in bucket policy | None | Critical | – | DSP-15 | F-AWS-S3-007 |
| TLS-only via bucket policy | `aws:SecureTransport=true` enforced | Medium | 2.1.3 | IVS-04 | F-AWS-S3-008 |
| Lifecycle policies for cost + compliance | In place | Low | – | DSP-16 | F-AWS-S3-009 |

### 5.2 RDS / Aurora

```bash
aws rds describe-db-instances \
  --query 'DBInstances[].[DBInstanceIdentifier,PubliclyAccessible,StorageEncrypted,Engine,EngineVersion,MultiAZ]' \
  --output table

aws rds describe-db-clusters \
  --query 'DBClusters[].[DBClusterIdentifier,StorageEncrypted,IAMDatabaseAuthenticationEnabled]'

aws rds describe-db-snapshots \
  --query 'DBSnapshots[?SnapshotType==`manual`].[DBSnapshotIdentifier,Encrypted]'

# Public snapshots (BAD)
aws rds describe-db-snapshots --include-public --snapshot-type public
```

| Check | Expected | Severity | Finding |
|---|---|---|---|
| No publicly accessible DB instances | `PubliclyAccessible=false` | Critical | F-AWS-RDS-001 |
| Storage encrypted | `StorageEncrypted=true` | High | F-AWS-RDS-002 |
| Automated backups enabled | Retention ≥ 7 days | Medium | F-AWS-RDS-003 |
| Multi-AZ for production | `MultiAZ=true` | Low | F-AWS-RDS-004 |
| IAM authentication | `IAMDatabaseAuthenticationEnabled=true` | Medium | F-AWS-RDS-005 |
| No public snapshots | None | Critical | F-AWS-RDS-006 |
| Deletion protection on | True | Medium | F-AWS-RDS-007 |
| TLS enforced | Engine-specific param group setting | Medium | F-AWS-RDS-008 |
| Logs to CloudWatch | Engine logs exported | Medium | F-AWS-RDS-009 |

### 5.3 EBS snapshots

```bash
# Publicly shared snapshots
aws ec2 describe-snapshots --owner-ids self \
  --query 'Snapshots[?CreateVolumePermissions[?Group==`all`]].[SnapshotId,Description]'
```

| Check | Expected | Severity | Finding |
|---|---|---|---|
| No public EBS snapshots | None | Critical | F-AWS-S3-010 |
| Snapshots encrypted | All | High | F-AWS-S3-011 |

---

## 6. Encryption and key management

```bash
# KMS keys
aws kms list-keys --query 'Keys[].KeyId' --output text | while read k; do
  meta=$(aws kms describe-key --key-id $k --query KeyMetadata)
  pol=$(aws kms get-key-policy --key-id $k --policy-name default --query Policy --output text)
  echo "=== $k ==="
  echo "$meta" | jq '{Origin, KeySpec, KeyUsage, KeyState, KeyManager, MultiRegion, AutoRotation: .KeyRotationEnabled}'
  # Wildcard principal in key policy?
  echo "$pol" | jq 'fromjson | .Statement[] | select(.Principal.AWS=="*")'
done

# Rotation
aws kms list-keys --query 'Keys[].KeyId' --output text | while read k; do
  rot=$(aws kms get-key-rotation-status --key-id $k --query KeyRotationEnabled 2>/dev/null)
  echo "$k rotation: $rot"
done
```

| Check | Expected | Severity | CIS | CCM | Finding |
|---|---|---|---|---|---|
| Customer-managed KMS rotation enabled | True for all CMKs | Medium | 3.8 | CEK-08 | F-AWS-CRY-001 |
| Key policies don't have `Principal: *` | None | High | – | CEK-09 | F-AWS-CRY-002 |
| Key usage logged in CloudTrail | Data events on KMS or use Insights | Medium | – | LOG-04 | F-AWS-CRY-003 |
| Pending-deletion keys reviewed | Owner-approved | Low | – | CEK-08 | F-AWS-CRY-004 |
| Imported keys have expiry | If imported, `ValidTo` set | Low | – | CEK-08 | F-AWS-CRY-005 |

---

## 7. EKS / containers

```bash
aws eks list-clusters
for c in $(aws eks list-clusters --query 'clusters[]' --output text); do
  aws eks describe-cluster --name $c --query '{Endpoint: cluster.endpoint, PublicAccess: cluster.resourcesVpcConfig.endpointPublicAccess, PublicCIDRs: cluster.resourcesVpcConfig.publicAccessCidrs, LogTypes: cluster.logging.clusterLogging, EncryptionConfig: cluster.encryptionConfig}'
done
```

| Check | Expected | Severity | Finding |
|---|---|---|---|
| API server endpoint not public, or CIDR-restricted | Private, or `publicAccessCidrs` ≠ 0.0.0.0/0 | High | F-AWS-EKS-001 |
| Control plane logging enabled (all 5 types) | All enabled | High | F-AWS-EKS-002 |
| Secrets encryption with KMS | `encryptionConfig.resources=[secrets]` | High | F-AWS-EKS-003 |
| IRSA in use (not node-role mass-permission) | OIDC provider in use | Medium | F-AWS-EKS-004 |
| Pod Security Standards enforced | `restricted` namespace by default | Medium | F-AWS-EKS-005 |
| Network policies in place | Calico / Cilium / native | Medium | F-AWS-EKS-006 |
| Nodes use IMDSv2 only | Yes | High | F-AWS-EKS-007 |

For ECS, similar logic: task role least privilege, no privileged tasks, awsvpc networking, no host networking unless required.

---

## 8. Organisational / multi-account

```bash
aws organizations describe-organization
aws organizations list-policies --filter SERVICE_CONTROL_POLICY
aws organizations list-accounts
```

| Check | Expected | Severity | Finding |
|---|---|---|---|
| Organization deployed | At least one OU per environment | Medium | F-AWS-ORG-001 |
| SCPs restrict region usage | `aws:RequestedRegion` deny outside allowed | Medium | F-AWS-ORG-002 |
| SCPs deny disabling CloudTrail/Config/GuardDuty | Yes | High | F-AWS-ORG-003 |
| Delegated admin for Security Hub / GuardDuty / Config | Audit account designated | Medium | F-AWS-ORG-004 |
| Control Tower / Landing Zone in use | Yes | Low | F-AWS-ORG-005 |

---

## 9. Cost as a signal

Not strictly security, but worth noting on audits: anomalous spend often correlates with crypto-mining or data exfiltration.

```bash
aws ce get-anomalies --date-interval Start=$(date -d '30 days ago' +%Y-%m-%d),End=$(date +%Y-%m-%d)
aws ce list-cost-allocation-tags
```

---

## Cleanup post-audit

If you ran enumeration scripts that created cache/logs in the customer's account (unlikely for read-only audit), document and remove them. Always confirm at engagement end that no test resources remain. Generate a final inventory delta with:

```bash
aws resourcegroupstaggingapi get-resources --tag-filters Key=createdBy,Values=$YOUR_NAME
```

---

## References

- [CIS AWS Foundations Benchmark v4.0](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS Foundational Security Best Practices standard](https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html)
- [Prowler v4](https://github.com/prowler-cloud/prowler)
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite)
- [PMapper](https://github.com/nccgroup/PMapper)
- [Cloudsplaining](https://github.com/salesforce/cloudsplaining)
