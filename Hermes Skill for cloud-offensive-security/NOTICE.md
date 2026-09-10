# NOTICE — Disclaimer, liability and operator responsibility

**Read this before you run anything from this skill.**

## No warranty, no responsibility

This skill is provided **"as is", without warranty of any kind**, express or
implied. The author (Georg Philipp Erasmus Heise) accepts **no responsibility
and no liability** for anything that happens as a result of using this skill,
its scripts, its recipes, or any command, technique or output it produces —
including but not limited to service disruption, data loss, account lockout,
financial cost, regulatory exposure, or any direct, indirect, incidental or
consequential damage.

## You are responsible for what the skill does

When you run this skill you are acting as the **operator**. Everything the skill
touches, it touches **on your authority and under your responsibility**. You —
not the author, not the AI — are responsible for:

- Having **written authorization** for every target you assess (engagement
  letter / scope agreement / the cloud provider's testing policy satisfied).
- Confirming that each account, subscription or project is **explicitly in
  scope** before any command runs against it.
- **Reviewing every operation before it executes**, especially anything that
  writes, escalates, moves laterally, persists, exfiltrates, or removes a
  control.
- The **consequences** of any action taken, whether you ran it directly or an
  agent ran it on your behalf.

## An AI can make mistakes

This skill is designed to be driven by an AI agent (Hermes). **AI agents can and
do make mistakes** — they can misjudge scope, misclassify an operation's blast
radius, chain steps in an unintended order, or act on target-controlled content.
**Do not treat the agent's judgement as a substitute for your own.** Verify
before you approve. When in doubt, stop.

## Acknowledgement is required

Before any active or intrusive operation, the operator must record an
acknowledgement (`scripts/acknowledge.sh`) confirming that they have read this
notice, accept responsibility for the skill's actions, and understand that the
AI driving it can make mistakes. The approval gate refuses to authorise
non-passive operations until this acknowledgement exists.

## Authorized use only

The techniques here are for **authorized security testing only**. Using them
against systems you do not own or are not explicitly authorized to test is
likely illegal. That is on you.
