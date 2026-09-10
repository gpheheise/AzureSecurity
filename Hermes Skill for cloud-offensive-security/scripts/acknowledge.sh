#!/usr/bin/env bash
# Interactive operator acknowledgement for cloud-offensive-security.
# A human must run this in a terminal. It prints the disclaimer and records that
# the operator accepts responsibility and understands the AI can make mistakes.
# The approval gate refuses active/intrusive operations until this record exists.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
NOTICE="$ROOT/NOTICE.md"

if [ ! -t 0 ]; then
  echo "ERROR: acknowledge.sh must be run interactively by a human (no TTY detected)." >&2
  echo "The agent must NOT run this non-interactively or fabricate the acknowledgement." >&2
  exit 1
fi

echo "============================================================"
echo " cloud-offensive-security — operator acknowledgement"
echo "============================================================"
if [ -f "$NOTICE" ]; then
  echo
  sed -n '1,80p' "$NOTICE"
  echo
fi
echo "------------------------------------------------------------"
echo "By acknowledging you confirm that:"
echo "  1. You have read NOTICE.md and accept it."
echo "  2. You are the responsible operator for every action this"
echo "     skill takes, whether you or an AI agent execute it."
echo "  3. You understand that AI agents (such as Hermes) can make"
echo "     mistakes, and that you will review operations before"
echo "     approving them."
echo "  4. You will only test systems you own or are explicitly"
echo "     authorized to test."
echo "------------------------------------------------------------"
echo

read -r -p "Operator name (for the audit record): " OPERATOR
[ -n "$OPERATOR" ] || { echo "No operator name given. Aborting."; exit 1; }

echo
echo "Type exactly:  I ACCEPT RESPONSIBILITY"
read -r -p "> " PHRASE
if [ "$PHRASE" != "I ACCEPT RESPONSIBILITY" ]; then
  echo "Phrase did not match. Acknowledgement NOT recorded."
  exit 1
fi

# Record via python using common.py for path resolution.
ACK_SCRIPT_DIR="$HERE" python3 - "$OPERATOR" << 'PYEOF'
import os, sys, json
sys.path.insert(0, os.environ["ACK_SCRIPT_DIR"])
import common as C
rec = {
    "acknowledged": True,
    "operator": sys.argv[1],
    "accepted_notice": True,
    "understands_ai_can_err": True,
    "recorded_at": C.now_iso(),
}
p = C.ack_path()
p.write_text(json.dumps(rec, indent=2), encoding="utf-8")
print("\nAcknowledgement recorded: %s" % p)
print("Operator: %s" % rec["operator"])
PYEOF

echo
echo "You may now use CLOUD_AUDIT (passive) freely. For CLOUD_REDTEAM active/"
echo "intrusive operations you still need a human-written authorization record"
echo "(see SKILL.md > Authorization record)."
