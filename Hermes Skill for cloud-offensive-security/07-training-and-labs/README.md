# Training and Labs

Hands-on resources for cloud offensive work. Ranked by how much you'll actually learn per hour spent.

## Paid lab platforms (highest signal)

### Pwned Labs

Tyler Ramsbey's platform. The current best-in-class for AWS, Azure, and GCP red team practice. Realistic environments, chained attack paths, no hand-holding.

- **URL**: https://pwnedlabs.io
- **Tracks**: AWS Red Team, Microsoft Cloud Red Team, GCP Red Team, plus advanced and expert tiers.
- **Certs**: ACRTP, MCRTP, GCRTP, M-CRTP3, MCRTE.
- **Pricing**: Subscription model. Pay monthly or per cert path.
- **Strength**: Scenarios match what you'll actually see in engagements. Initial access through exfil, not just isolated technique drills.
- **Weakness**: Newer platform, smaller catalog than HTB. Catalog growing fast.

### Altered Security

Nikhil Mittal's platform. The reference for Azure red team training plus the AD/CRTP series that hybrid cloud work depends on.

- **URL**: https://www.alteredsecurity.com
- **Tracks**: CARTP, CARTE for Azure. CRTP, CRTE, CRTM for AD.
- **Strength**: Course material is dense and exam labs are excellent. Nikhil's research feeds directly into the curriculum.
- **Weakness**: AWS and GCP not covered. Course-led structure, less freeform exploration than HTB.

### Hack The Box

General offensive platform but cloud content has grown significantly. Pro Labs include cloud scenarios (Hailstorm, Trick).

- **URL**: https://www.hackthebox.com
- **Tracks**: HTB Academy modules for AWS, Azure, GCP. CBBH and CWEE paths touch cloud topics.
- **Strength**: Massive overall catalog. Sherlocks (defensive) and labs together.
- **Weakness**: Cloud-specific depth is thinner than Pwned Labs. Boxes are puzzle-flavored, less realistic chain depth.

### SANS SEC588

The instructor-led option. Pairs with GCPN cert.

- **URL**: https://www.sans.org/cyber-security-courses/cloud-penetration-testing/
- **Cost**: ~$8500.
- **When it makes sense**: Employer-funded, want structured curriculum with live instruction, or need GIAC credential for client requirements.
- **When to skip**: If you're paying personally or already self-directed. The same content is reachable via Pwned Labs + reading at a fraction of the cost.

## Free intentionally vulnerable environments

Stand these up in your own account. All open source.

### CloudGoat (Rhino Security Labs)

The AWS practice ground. Scenario-based, each one demonstrates a specific privesc or attack chain.

- **Repo**: https://github.com/RhinoSecurityLabs/cloudgoat
- **Format**: Terraform-deployed scenarios. ~20 scenarios covering IAM privesc, EC2 SSRF to IMDS, Lambda privesc, S3 exposure, CodeBuild abuse.
- **How to use**: Deploy one scenario at a time, attempt it cold, then compare with the writeup.
- **Cost**: Pay AWS for the resources you spin up. Usually < $1 per scenario if you tear down promptly.

### AzureGoat (INE Security / Pavandeep Singh)

Azure equivalent.

- **Repo**: https://github.com/azuregoat/AzureGoat
- **Format**: Terraform-deployed vulnerable Azure infrastructure. Covers web app vulns, container escape, key vault abuse, function apps, blob storage.
- **Caveat**: Less actively maintained than CloudGoat. Test in a dedicated sub.

### GCPGoat (INE Security)

GCP equivalent.

- **Repo**: https://github.com/ine-labs/GCPGoat
- **Format**: Terraform-deployed. Covers Cloud Functions, IAM, GCS, IAP.
- **Caveat**: Smallest of the three Goats but still useful baseline.

### IAM Vulnerable (BishopFox)

AWS IAM privesc training ground specifically. Pure IAM, no infrastructure noise.

- **Repo**: https://github.com/BishopFox/iam-vulnerable
- **Format**: Terraform. Implements all 21 AWS privesc paths from Rhino's original research.
- **Use case**: Pacu/PMapper practice without distractions.

### Sadcloud

AWS misconfigurations for audit/scanning tool practice.

- **Repo**: https://github.com/nccgroup/sadcloud
- **Format**: Terraform. Deploys deliberately misconfigured resources.
- **Use case**: Test Prowler, ScoutSuite, custom audit scripts.

### TerraGoat (Checkov / Bridgecrew)

IaC misconfigurations. Multi-cloud.

- **Repo**: https://github.com/bridgecrewio/terragoat
- **Use case**: Audit tool development, IaC scanning practice.

### Kubernetes Goat

K8s security training.

- **Repo**: https://github.com/madhuakula/kubernetes-goat
- **Use case**: GKE/EKS/AKS offensive practice in a controlled environment.

## Provider-issued free training

### AWS Skill Builder

- **URL**: https://skillbuilder.aws
- **Worth your time**: AWS Security Learning Plan. Free tier covers fundamentals. Defender-side perspective is the angle.
- **Skip**: The exam prep modules unless you're sitting SCS-C02.

### Microsoft Learn

- **URL**: https://learn.microsoft.com/training/
- **Worth your time**: SC-200 and SC-300 learning paths are free and comprehensive. Free Defender for Cloud sandbox labs.
- **Bonus**: Microsoft Applied Skills credentials are free assessments worth doing.

### Google Cloud Skills Boost

- **URL**: https://www.cloudskillsboost.google
- **Worth your time**: Security Engineer learning path. Free tier limited but Qwiklabs are credit-based.
- **Bonus**: Periodic free credit promotions, follow @googlecloud for announcements.

## Reading-first resources

### hackingthe.cloud

The community wiki for cloud offensive techniques. Maintained by Nick Frichette plus contributors.

- **URL**: https://hackingthe.cloud
- **Strength**: Technique catalog organized by platform and phase. Every entry maps to a concrete command or tool invocation.
- **Use as**: Reference during engagements. The first place to check when you're trying to remember "how did I do that S3 thing again."

### Datadog Security Labs

Datadog's research blog. Practical, technique-heavy posts.

- **URL**: https://securitylabs.datadoghq.com
- **Notable contributors**: Christophe Tafani-Dereeper, Nick Frichette.
- **Content**: New attack techniques, detection engineering, Stratus Red Team scenarios.

### SpecterOps Posts

Andy Robbins and the BloodHound team. Heavy on Entra ID and hybrid identity attack paths.

- **URL**: https://posts.specterops.io
- **Notable**: Attack path research, AzureHound usage, identity-first offensive content.

### NetSPI Blog

NetSPI's offensive research. Karl Fosaaen's Azure work is the standout.

- **URL**: https://www.netspi.com/blog/
- **Notable**: MicroBurst documentation, Azure attack research.

### TrustedSec

Beau Bullock and team. GraphRunner, MFASweep originated here.

- **URL**: https://trustedsec.com/blog
- **Notable**: M365 attack tooling, OAuth phishing research.

## Capture the Flag and competitions

### fwd:cloudsec CTF

Conference CTF, cloud-focused. Past challenges archived.

- **URL**: https://fwdcloudsec.org
- **Format**: Runs alongside the conference. Past challenges sometimes published.

### AWS GameDay

AWS-run. Free if you can attend in-person events. Defender-side but exposes you to realistic AWS environments.

- **URL**: https://aws.amazon.com/gameday/

### flAWS and flAWS2

Scott Piper's AWS challenges. Free, browser-based, no AWS account needed.

- **URLs**: http://flaws.cloud and http://flaws2.cloud
- **Use case**: Quick warm-up before a real engagement. flAWS2 has both attacker and defender tracks.

### CloudWars

Bishop Fox-run.

- **URL**: Periodic, watch their socials.

## Conference talks worth watching

A non-exhaustive starter list. Search YouTube for the talk title.

- **fwd:cloudsec** all editions, the archive at https://www.youtube.com/@fwdcloudsec
- **DEF CON Cloud Village** all editions
- **Black Hat USA / EU** cloud track talks
- **Dirk-jan Mollema, "ROADtools and Tokens"** plus any of his recent talks
- **Fabian Bader, Conditional Access bypass talks** with Mollema
- **Nick Frichette, AWS-focused talks**
- **Christophe Tafani-Dereeper, "Stratus Red Team"**
- **Andy Robbins, "BloodHound and Azure attack paths"**
- **Karl Fosaaen, Azure offensive talks**
- **Beau Bullock, "Graph Runner"** and any M365 talks
- **Scott Piper, "Cloud security maturity model"** and historical AWS talks
- **Gafnit Amiga, Wiz team research talks**

## Books

Few worth buying for cloud specifically. Most current knowledge is blogs and labs.

- **"Hands-On AWS Penetration Testing with Kali Linux"** (Karl Gilbert, Benjamin Caudill) - Dated but still useful for foundational AWS concepts. The Pacu-era reference.
- **"The Pentester Blueprint"** (Phillip Wylie) - General offensive career book, not cloud-specific.

Skip generic "cloud security" books. They go stale within a year.

## Suggested learning path

A reasonable 6-12 month track for a working pentester adding cloud:

1. **Month 1-2**: CCSK self-study + flAWS + flAWS2 to get terminology and core AWS concepts.
2. **Month 2-3**: CloudGoat all scenarios. Read hackingthe.cloud cover to cover for your primary platform.
3. **Month 3-4**: Pwned Labs ACRTP or MCRTP depending on primary platform. Do the labs before reading the writeups.
4. **Month 4-6**: SCS-C02 or SC-200/SC-300 for the defender perspective. Read Datadog Security Labs and NetSPI blog archives in parallel.
5. **Month 6-9**: CARTP (if Azure-focused) plus your second platform's Pwned Labs cert.
6. **Month 9-12**: Real engagements + community contribution (blog post, tool, talk). The compounding starts here.

## DACH-specific resources

- **BSI publications**: https://www.bsi.bund.de free C5, IT-Grundschutz, and cloud computing guidance in German. Required reading for KRITIS work.
- **TROOPERS Heidelberg**: https://troopers.de annual conference, strong cloud content, German venue.
- **OWASP Germany chapters**: Local meetups in Frankfurt, München, Berlin, Hamburg.
- **Heise iX magazine**: German trade publication, periodic deep-dives on cloud security topics.

## See also

- [06-certifications](../06-certifications/README.md) for which cert each platform's labs map to.
- [08-community](../08-community/README.md) for who's behind these resources.
