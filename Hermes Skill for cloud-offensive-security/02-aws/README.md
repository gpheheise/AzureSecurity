# 02 — AWS

Offensive and audit playbook for Amazon Web Services.

## Files

- **[cookbook.md](./cookbook.md)** — Kill-chain commands. Recon → Initial Access → Enumeration → Privilege Escalation → Lateral Movement → Persistence → Data Exfiltration. Paste-ready.
- **[audit-checklist.md](./audit-checklist.md)** — Misconfig hunting. Each check has the CLI command, the secure state, and the finding mapping.
- **[findings-mapping.md](./findings-mapping.md)** — Cookbook tests and audit checks mapped to standard finding categories. If you have a finding repository, this is the bridge.

## What makes AWS testing different

- **IAM is the universe.** Almost every escalation in AWS goes through IAM policy combinations. Tools that don't understand identity-based policies, resource-based policies, permission boundaries, SCPs, and session policies will miss the interesting paths.
- **Most permitting is implicit.** `iam:PassRole` looks innocuous; combined with `lambda:CreateFunction` it's account takeover.
- **CloudTrail is the only honest record.** If CloudTrail isn't a multi-region all-management-events trail with log file validation, the customer can't prove what happened. Every engagement starts here.
- **Resource-based policies surprise people.** S3 bucket policies, KMS key policies, SNS topic policies, Lambda function policies — all can grant access from outside the IAM model.
- **STS is everywhere.** Temporary credentials, role chaining, federation, cross-account, identity centre. Understand `AssumeRole` chains; they're how attackers move.
- **GuardDuty and IMDSv2.** Two single-toggle controls that change the attack surface dramatically. Always check.

## Authorization preflight

Before running anything from the cookbook:

```bash
# Confirm your identity in the target account
aws sts get-caller-identity

# Confirm you can read your own user / role
aws iam get-user

# Confirm the account ID matches what's in the engagement letter
aws sts get-caller-identity --query Account --output text
```

If the account ID doesn't match the engagement, stop. Don't cross account boundaries you weren't given.

## AWS testing policy (recap)

Customer-owned testing permitted on: EC2, RDS, CloudFront, Aurora, API Gateway, Lambda, Lightsail, Elastic Beanstalk. Anything else (e.g. WAF, Shield, Route53 zone walking) needs the [Simulated Events form](https://aws.amazon.com/security/penetration-testing/). Prohibited: DoS, DDoS, request flooding, port flooding. See [aws.amazon.com/security/penetration-testing](https://aws.amazon.com/security/penetration-testing/).

## Region defaults

The cookbook commands assume `--region us-east-1` unless otherwise specified. For EU-resident customers, switch to `eu-central-1`, `eu-west-1`, or whichever they primarily use. Some recon (e.g. IAM, organisations, billing) is region-less — those commands work the same way regardless.

## Recommended tool stack

For a typical grey-box engagement:

- **Pacu** — modular AWS exploitation framework. Pick the modules you need; don't run kitchen-sink.
- **CloudFox** — fast read-only enumeration. Output is human-readable.
- **enumerate-iam** — single-purpose IAM permission enumeration.
- **Prowler v4** — audit + compliance benchmarks (use for the audit side, not just pentests).
- **ScoutSuite** — multi-cloud config auditing.
- **PMapper / Cloudsplaining** — IAM graph analysis. PMapper is for escalation paths, Cloudsplaining for "what *can* this principal do."
- **trufflehog / gitleaks** — for the leaked-secret recon angle.
- **Stratus Red Team** — adversary emulation for validating detections post-finding.

See `../05-tooling/README.md` for installation, current versions, and links.
