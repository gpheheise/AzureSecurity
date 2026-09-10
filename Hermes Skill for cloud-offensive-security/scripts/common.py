"""Shared helpers for cloud-offensive-security. Pure stdlib (Kali PEP 668 safe)."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

# --- operation tiers, aligned with the cloud-offensive recipe engine ---
TIERS = ("passive", "active", "intrusive")

# Modes mirror the cloud-offensive execution skill.
MODE_AUDIT = "CLOUD_AUDIT"      # passive-only; no auth record needed
MODE_REDTEAM = "CLOUD_REDTEAM"  # full kill chain; active/intrusive gated
MODES = (MODE_AUDIT, MODE_REDTEAM)


def state_dir() -> Path:
    """Where acknowledgement / authorization state lives. Never inside the skill."""
    base = os.environ.get("HERMES_STATE")
    if base:
        d = Path(base) / "cloud-offensive-security"
    else:
        d = Path.home() / ".hermes" / "state" / "cloud-offensive-security"
    d.mkdir(parents=True, exist_ok=True)
    return d


def ack_path() -> Path:
    return state_dir() / "ACK.json"


def auth_path() -> Path:
    """Human-authored authorization record. Env override for per-engagement files."""
    override = os.environ.get("CLOUD_OFFSEC_AUTH")
    if override:
        return Path(override)
    return state_dir() / "authorization.json"


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_json(p: Path):
    try:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return None


def ack_present() -> bool:
    d = load_json(ack_path())
    return bool(d and d.get("acknowledged") is True and d.get("operator"))


def valid_authorization(allow_destructive: bool = False):
    """Return (ok, reason). Checks the human-written authorization record.

    The record is expected to be authored by a human operator, not the agent.
    Required keys: operator, reason, expires (ISO date/datetime).
    Optional: allow_destructive (bool), scope (list).
    """
    d = load_json(auth_path())
    if not d:
        return False, "no authorization record found (%s)" % auth_path()
    for k in ("operator", "reason", "expires"):
        if not d.get(k):
            return False, "authorization record missing '%s'" % k
    try:
        exp = d["expires"]
        exp_dt = datetime.fromisoformat(exp if "T" in exp else exp + "T23:59:59+00:00")
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return False, "authorization 'expires' is not ISO 8601"
    if exp_dt < datetime.now(timezone.utc):
        return False, "authorization expired on %s" % d["expires"]
    if allow_destructive and not d.get("allow_destructive"):
        return False, "authorization does not set allow_destructive=true"
    return True, "authorized by %s until %s" % (d["operator"], d["expires"])
