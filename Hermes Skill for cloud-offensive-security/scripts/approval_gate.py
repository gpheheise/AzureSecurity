#!/usr/bin/env python3
"""Approval gate for cloud-offensive-security.

Decides whether an operation may run, given the engagement mode, the operation's
tier, the operator acknowledgement, and the human-written authorization record.

Returns one of:
  ALLOW      -> the agent may proceed.
  ASK_HUMAN  -> the agent MUST stop, present the exact operation to the human
                operator, and wait for explicit human approval in the
                conversation before executing. The agent may NOT approve on the
                human's behalf.
  DENY       -> the operation is not permitted in the current state.

Design note (why this is not self-satisfiable by an agent):
  ASK_HUMAN is a decision, not a flag the agent can flip. The agent cannot turn
  an ASK_HUMAN into an ALLOW by re-running the gate — it can only proceed after a
  human says so out-of-band. The authorization record and the acknowledgement are
  human-authored artifacts (see acknowledge.sh and NOTICE.md); SKILL.md instructs
  the agent that it must not fabricate them. Unknown operations fail toward the
  strict side (ASK_HUMAN / DENY), never toward ALLOW.

Usage:
  approval_gate.py --mode CLOUD_REDTEAM --tier intrusive [--destructive]
  approval_gate.py --mode CLOUD_AUDIT --op enum_permissions
  approval_gate.py --mode CLOUD_REDTEAM --command "aws iam create-access-key ..."
"""
import argparse
import json
import sys

import common as C

# Coarse op catalog: name -> (tier, destructive). Extend as needed.
OP_CATALOG = {
    # passive
    "recon": ("passive", False),
    "tenant_recon": ("passive", False),
    "enum_permissions": ("passive", False),
    "whoami": ("passive", False),
    "audit_readonly": ("passive", False),
    "bucket_enum": ("passive", False),
    # active
    "credential_validation": ("active", False),
    "password_spray": ("intrusive", False),   # lockout risk -> intrusive, not active
    "role_assume": ("active", False),
    "token_request": ("active", False),
    # intrusive
    "privesc_execute": ("intrusive", False),
    "create_access_key": ("intrusive", False),
    "create_role_trust": ("intrusive", False),
    "lateral_move": ("intrusive", False),
    "device_code_phish": ("intrusive", False),
    "imds_cred_theft": ("intrusive", False),
    "lambda_backdoor": ("intrusive", False),
    "snapshot_share": ("intrusive", False),
    "persistence": ("intrusive", False),
    "data_exfil": ("intrusive", False),
    # intrusive + destructive
    "disable_logging": ("intrusive", True),
    "tamper_cloudtrail": ("intrusive", True),
    "delete_resource": ("intrusive", True),
    "disable_guardduty": ("intrusive", True),
}

# Heuristics for freeform --command classification. Conservative: match = risky.
_DESTRUCTIVE_HINTS = ("delete", "stop-logging", "delete-trail", "put-event-selectors",
                      "disable", "terminate", "rm ", "destroy", "detector --status")
_INTRUSIVE_HINTS = ("create-", "put-", "update-assume-role", "attach-", "invoke",
                    "add-", "set-default-policy-version", "spray", "assume-role-with",
                    "generate-sas", "keys list", "publishing-credentials")
_PASSIVE_HINTS = ("list", "describe", "get-", "list-", "who", "caller-identity",
                  "getuserrealm", "openid-configuration")


def classify_command(cmd: str):
    c = cmd.lower()
    for h in _DESTRUCTIVE_HINTS:
        if h in c:
            return "intrusive", True
    for h in _INTRUSIVE_HINTS:
        if h in c:
            return "intrusive", False
    for h in _PASSIVE_HINTS:
        if h in c:
            return "passive", False
    # Unknown -> fail safe.
    return "intrusive", False


def decide(mode, tier, destructive):
    reasons = []
    # 0. Acknowledgement is a precondition for anything non-passive.
    if tier != "passive" and not C.ack_present():
        return "DENY", ["operator acknowledgement missing — run scripts/acknowledge.sh first"]

    if mode == C.MODE_AUDIT:
        if tier == "passive":
            return "ALLOW", ["passive check in CLOUD_AUDIT mode"]
        return "DENY", ["CLOUD_AUDIT is passive-only; switch to CLOUD_REDTEAM and record authorization"]

    if mode == C.MODE_REDTEAM:
        if tier == "passive":
            return "ALLOW", ["passive check in CLOUD_REDTEAM mode"]
        ok, why = C.valid_authorization(allow_destructive=destructive)
        if not ok:
            return "DENY", [why]
        reasons.append(why)
        if tier == "active":
            return "ALLOW", reasons + ["active, non-destructive, under valid authorization"]
        # intrusive (and destructive) always require a human go per operation.
        if destructive:
            reasons.append("DESTRUCTIVE: removes/alters a control or data — human approval mandatory")
        else:
            reasons.append("intrusive: writes/escalates/moves/persists/exfiltrates — human approval mandatory")
        return "ASK_HUMAN", reasons

    return "DENY", ["unknown mode %r (use CLOUD_AUDIT or CLOUD_REDTEAM)" % mode]


def main():
    ap = argparse.ArgumentParser(description="cloud-offensive-security approval gate")
    ap.add_argument("--mode", required=True, choices=list(C.MODES))
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--tier", choices=list(C.TIERS))
    g.add_argument("--op", help="named operation from the built-in catalog")
    g.add_argument("--command", help="freeform command string (heuristic, fails safe)")
    ap.add_argument("--destructive", action="store_true",
                    help="force-mark the operation destructive (removes/alters a control or data)")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args()

    destructive = args.destructive
    if args.tier:
        tier = args.tier
    elif args.op:
        if args.op not in OP_CATALOG:
            tier, d2 = "intrusive", False  # unknown named op -> fail safe
            note = "unknown op %r — treated as intrusive" % args.op
        else:
            tier, d2 = OP_CATALOG[args.op]
            note = "op %r -> tier %s" % (args.op, tier)
        destructive = destructive or d2
    else:
        tier, d2 = classify_command(args.command)
        destructive = destructive or d2
        note = "command classified as tier %s%s" % (tier, " (destructive)" if destructive else "")

    decision, reasons = decide(args.mode, tier, destructive)
    if args.op or args.command:
        reasons = [note] + reasons

    out = {"decision": decision, "mode": args.mode, "tier": tier,
           "destructive": destructive, "reasons": reasons}
    if args.json:
        print(json.dumps(out))
    else:
        print("%s  (mode=%s tier=%s%s)" % (decision, args.mode, tier,
              " destructive" if destructive else ""))
        for r in reasons:
            print("  - " + r)
    # exit codes: 0 ALLOW, 10 ASK_HUMAN, 20 DENY  (lets shell callers branch)
    sys.exit({"ALLOW": 0, "ASK_HUMAN": 10, "DENY": 20}.get(decision, 20))


if __name__ == "__main__":
    main()
