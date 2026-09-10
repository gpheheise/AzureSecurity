# AzureSecurity

Practitioner resources for offensive security in the cloud, with Entra ID and
hybrid identity as the through-line: a field-experience attack handbook and an
agent-ready assessment toolkit. Built for people who run engagements, not for
people who read about them.

> **Authorisation first.** Everything here is for systems you own or are
> explicitly authorised to test. See [Authorisation and legal](#authorisation-and-legal).

---

## What's inside

Two independent, self-contained resources:

### 1. The Modern Entra ID & Hybrid Attack Handbook

[`Entra-Hybrid-Handbook v1.0.pdf`](./Entra-Hybrid-Handbook%20v1.0.pdf) — a
131-page practitioner reference for Entra ID and hybrid Active Directory attack
tradecraft, distilled from real engagement experience and structured into a
field manual.

It covers the modern identity kill chain end to end: tenant recon and user
enumeration, initial access (password spraying, MFA-bypass identification,
device-code phishing, token theft), privilege escalation and Conditional Access
bypass, hybrid identity abuse in both directions (on-prem → cloud via PHS/PTA,
cloud → on-prem via Seamless SSO / `AZUREADSSOACC$`), lateral movement,
persistence and defence evasion. Each technique pairs the offensive procedure
with the defensive view — OPSEC considerations and concrete KQL telemetry — plus
attack-chain walkthroughs, an ATT&CK matrix, and operator/defender reference
appendices.

If you assess Microsoft identity for a living, this is the desk copy.

### 2. cloud-offensive-security (Hermes skill)

[`Hermes Skill for cloud-offensive-security/`](./Hermes%20Skill%20for%20cloud-offensive-security/) —
a practitioner knowledge base and agent-ready toolkit for cloud penetration
testing, red teaming, and security audits across **AWS, Azure/Entra, and GCP**.
Loadable as a [Hermes](./Hermes%20Skill%20for%20cloud-offensive-security/SKILL.md)
skill, and equally usable as a plain reference repo.

What it gives you:

- **Kill-chain cookbooks** per platform — recon → initial access → enumeration →
  privilege escalation → lateral movement → persistence → exfiltration, with
  paste-ready commands and consistent variable names.
- **CIS-aligned audit checklists** per platform, each check tied to the benchmark
  control and to a finding ID.
- **A finding catalog** (`F-<PLATFORM>-<DOMAIN>-<NNN>`) that every cookbook and
  checklist reference resolves to.
- **Regulatory context** — DORA / TIBER-EU TLPT, NIS2 / KRITIS, US and global
  frameworks, and a sector matrix — plus methodology, tooling, certs, labs, and
  community.
- **A deliverable** — `scripts/report.py` turns an engagement JSON into a
  self-contained **HTML and PDF** report (executive summary, engagement context,
  attack narrative, findings, detection assessment, recommendations,
  appendices), 5-tier severity, vendor-neutral styling.
- **A safety model built in** — two modes (`CLOUD_AUDIT` passive, `CLOUD_REDTEAM`
  full kill chain), a human-in-the-loop approval gate (`ALLOW / ASK_HUMAN /
  DENY`) that stops for explicit human approval on anything intrusive or
  destructive, and an operator acknowledgement gate. See
  [`SKILL.md`](./Hermes%20Skill%20for%20cloud-offensive-security/SKILL.md) and
  [`NOTICE.md`](./Hermes%20Skill%20for%20cloud-offensive-security/NOTICE.md).

---

## Quick start

**Read the handbook.** Download
[`Entra-Hybrid-Handbook v1.0.pdf`](./Entra-Hybrid-Handbook%20v1.0.pdf) — it's a
standalone document, no setup.

**Use the skill as a reference.** Browse the platform folders under
[`Hermes Skill for cloud-offensive-security/`](./Hermes%20Skill%20for%20cloud-offensive-security/):
start in `00-methodology/` for scoping, then the platform cookbook
(`02-aws/`, `03-azure/`, `04-gcp/`), and map results to that platform's
`findings-mapping.md`.

**Install it as a Hermes skill and generate a report:**

```bash
cd "Hermes Skill for cloud-offensive-security"
bash install.sh                 # dry run — shows what would be installed
bash install.sh --apply         # install into ~/.hermes/skills
bash scripts/acknowledge.sh     # human, interactive: accept the operator terms
python3 scripts/self_test.py    # verify (frontmatter, cross-refs, gate, report)

# produce the engagement report (HTML + PDF) from a findings file:
python3 scripts/report.py --input samples/engagement.sample.json --outdir out
```

PDF rendering uses WeasyPrint if present, otherwise wkhtmltopdf or headless
Chromium; on Kali: `sudo apt install weasyprint` (or `wkhtmltopdf`). If none is
installed, the generated HTML is A4 print-ready.

---

## Authorisation and legal

These are offensive-security resources. The techniques and tooling here are for
**authorised testing only** — systems you own or have explicit written
permission to assess. Before running anything against a live environment you
need a signed engagement letter or scope agreement, the cloud provider's testing
policy satisfied, and the target accounts / subscriptions / projects explicitly
in scope.

The material is provided **as is, without warranty of any kind**. The author
accepts no responsibility or liability for anything that results from its use.
When an AI agent drives the toolkit, the operator remains responsible for every
action it takes and must review operations before approving them — AI agents can
make mistakes. Full terms for the skill are in its
[`NOTICE.md`](./Hermes%20Skill%20for%20cloud-offensive-security/NOTICE.md).

Authorisation is on you.

---

## Licence

Components carry their own licences:

- **cloud-offensive-security skill** — CC BY-SA 4.0
  (see the skill folder's `LICENSE`). Share and adapt with attribution under the
  same licence.
- **The handbook** — © the author; free to read and share, all rights otherwise
  reserved.
- Repository scaffolding is under the root [`LICENSE`](./LICENSE) (Apache-2.0).

Third-party tools and external resources referenced here remain under their own
licences.

---

## Author

Georg Philipp Erasmus Heise — [@gpheheise](https://github.com/gpheheise).
Offensive security, cloud and identity attack tradecraft, and security research.

Contributions and corrections welcome via issues and pull requests.
