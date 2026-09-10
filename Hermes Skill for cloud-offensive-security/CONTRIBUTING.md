# Contributing

Pull requests are welcome. This repo only stays useful if it stays current, and cloud changes fast.

## What's worth contributing

- **New techniques** that have a working command or tool invocation behind them. No theory-only entries.
- **Finding catalog additions**: a new finding category with title, severity guidance, description, and test method.
- **Tool updates**: a tool that earns its place, with install command and a one-line reason it beats the alternatives.
- **Regulatory clarifications**: corrections or updates to the standards and regulations section, with a citation to the article, clause, or official source.
- **Fixes**: dead links, outdated version numbers, deprecated flags, renamed tools.

## What's not a fit

- Marketing copy or vendor pitches.
- Techniques with no reproducible command or tool.
- Anything that facilitates testing systems you do not own or are not authorized to test.
- Copy lifted verbatim from another source. Paraphrase and cite.

## Style

The house style is deliberate. Match it.

- **Commands first, prose second.** Show the command, then explain it briefly.
- **Paste-ready commands.** Use consistent variable names: `$TOKEN`, `$ACCESS_KEY`, `$SA_KEY`, `$TENANT_ID`, `$PROJECT_ID`, `$SUBSCRIPTION_ID`.
- **No filler.** Cut "in today's fast-paced cloud landscape" and similar. Get to the point.
- **Tables for structured data.** Findings, checks, comparisons go in tables.
- **Kill-chain order in cookbooks.** Recon, Initial Access, Enumeration, Privilege Escalation, Lateral Movement, Persistence, Data Exfiltration.

## Finding IDs

New findings follow `F-<PLATFORM>-<DOMAIN>-<NNN>`:

- `PLATFORM`: `AWS`, `AZ`, `GCP`, or `MC` (multi-cloud).
- `DOMAIN`: the affected service area (`IAM`, `NET`, `LOG`, `STO`, `KV`, `EC2`, etc.).
- `NNN`: zero-padded sequential number within that platform and domain.

Check the relevant `findings-mapping.md` for the next free number before assigning.

## Submitting

1. Fork and branch (`feature/your-change` or `fix/your-change`).
2. Keep each PR focused on one logical change.
3. Update the relevant section README navigation if you add a file.
4. If you add a diagram, use Mermaid (renders natively on GitHub) over an image where possible.
5. Open the PR with a short description of what changed and why.

## A note on accuracy

If you cite a CVE, a CVSS score, a regulation article, or a price, link the source. Stale or wrong facts in a security reference are worse than no facts. When something has a version-specific detail, note the version and date.
