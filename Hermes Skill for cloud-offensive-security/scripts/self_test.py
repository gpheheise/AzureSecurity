#!/usr/bin/env python3
"""Self-test for cloud-offensive-security. Pure stdlib. Run from anywhere."""
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))


# --- Group 1: frontmatter hardline ---
skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
fm = skill.split("---", 2)[1]
fields = {}
for line in fm.splitlines():
    m = re.match(r"^(\w[\w-]*):\s*(.*)$", line)
    if m:
        fields[m.group(1)] = m.group(2).strip()
check("frontmatter has name", bool(fields.get("name")))
desc = fields.get("description", "")
check("description present", bool(desc))
check("description <= 60 chars", len(desc) <= 60, "len=%d" % len(desc))
check("description ends with period", desc.endswith("."))
check("description is one sentence", desc.count(".") == 1)
for req in ("version", "license", "author", "platforms"):
    check("frontmatter has %s" % req, req in fields)

# --- Group 2: related_skills resolve to known siblings ---
KNOWN = {"cloud-offensive", "offensive-master", "pentest-reporting",
         "pentest-status", "exploit-research", "llm-chatbot-pentest"}
rel = re.search(r"related_skills:\s*\[([^\]]*)\]", fm)
if rel:
    names = [x.strip() for x in rel.group(1).split(",") if x.strip()]
    unknown = [n for n in names if n not in KNOWN]
    check("related_skills all resolve", not unknown, "unknown=%s" % unknown)
else:
    check("related_skills present", False)

# --- Group 3: finding-ID cross-references resolve ---
FID = re.compile(r"F-(?:AWS|AZ|GCP|MC)-[A-Z0-9]+-[0-9]{3}")


def fids(p):
    return set(FID.findall((ROOT / p).read_text(encoding="utf-8")))


catalog = set()
for cat in ("02-aws/findings-mapping.md", "03-azure/findings-mapping.md",
            "04-gcp/findings-mapping.md"):
    catalog |= fids(cat)
for n in range(10, 24):  # AWS LOG CIS-alarm range entry F-AWS-LOG-010..023
    catalog.add("F-AWS-LOG-%03d" % n)
dangling = {}
for ref in ("02-aws/cookbook.md", "02-aws/audit-checklist.md",
            "03-azure/cookbook.md", "03-azure/audit-checklist.md",
            "04-gcp/cookbook.md", "04-gcp/audit-checklist.md"):
    miss = fids(ref) - catalog
    if miss:
        dangling[ref] = sorted(miss)
check("all finding-ID references resolve", not dangling, str(dangling))

# --- Group 4: referenced dirs exist ---
for d in ("00-methodology", "01-standards-and-regulations", "02-aws",
          "03-azure", "04-gcp", "05-tooling", "NOTICE.md"):
    check("reference exists: %s" % d, (ROOT / d).exists())

# --- Group 5: approval gate decision logic ---
def gate(args, env=None):
    e = dict(os.environ)
    if env:
        e.update(env)
    p = subprocess.run([sys.executable, str(SCRIPTS / "approval_gate.py"), "--json"] + args,
                       capture_output=True, text=True, env=e)
    return p.returncode, p.stdout.strip()


with tempfile.TemporaryDirectory() as tmp:
    st = Path(tmp) / "state"
    env_noack = {"HERMES_STATE": str(st)}
    # no ack yet: intrusive must DENY
    rc, out = gate(["--mode", "CLOUD_REDTEAM", "--tier", "intrusive"], env_noack)
    check("no-ack intrusive -> DENY", "DENY" in out and rc == 20, out)
    # passive audit allowed even without ack
    rc, out = gate(["--mode", "CLOUD_AUDIT", "--tier", "passive"], env_noack)
    check("audit passive -> ALLOW", "ALLOW" in out and rc == 0, out)
    # write ack
    ackdir = st / "cloud-offensive-security"
    ackdir.mkdir(parents=True, exist_ok=True)
    (ackdir / "ACK.json").write_text('{"acknowledged": true, "operator": "tester"}')
    # audit + active -> DENY (passive-only)
    rc, out = gate(["--mode", "CLOUD_AUDIT", "--tier", "active"], env_noack)
    check("audit active -> DENY", "DENY" in out and rc == 20, out)
    # redteam active without auth -> DENY
    rc, out = gate(["--mode", "CLOUD_REDTEAM", "--tier", "active"], env_noack)
    check("redteam active no-auth -> DENY", "DENY" in out and rc == 20, out)
    # add valid authorization
    (ackdir / "authorization.json").write_text(
        '{"operator":"tester","reason":"self-test","expires":"2099-01-01"}')
    rc, out = gate(["--mode", "CLOUD_REDTEAM", "--tier", "active"], env_noack)
    check("redteam active w/auth -> ALLOW", "ALLOW" in out and rc == 0, out)
    rc, out = gate(["--mode", "CLOUD_REDTEAM", "--tier", "intrusive"], env_noack)
    check("redteam intrusive w/auth -> ASK_HUMAN", "ASK_HUMAN" in out and rc == 10, out)
    # destructive without allow_destructive -> DENY
    rc, out = gate(["--mode", "CLOUD_REDTEAM", "--tier", "intrusive", "--destructive"], env_noack)
    check("destructive w/o allow_destructive -> DENY", "DENY" in out and rc == 20, out)
    # unknown named op fails safe to intrusive -> ASK_HUMAN
    rc, out = gate(["--mode", "CLOUD_REDTEAM", "--op", "totally_unknown_op"], env_noack)
    check("unknown op fails safe -> ASK_HUMAN", "ASK_HUMAN" in out and rc == 10, out)
    # freeform destructive command -> classified destructive -> DENY (no allow_destructive)
    rc, out = gate(["--mode", "CLOUD_REDTEAM", "--command", "aws cloudtrail delete-trail --name x"], env_noack)
    check("freeform delete-trail -> DENY", "DENY" in out and rc == 20, out)

# --- Group 6: report generator produces vendor-neutral HTML with expected sections ---
with tempfile.TemporaryDirectory() as tmp:
    sample = ROOT / "samples" / "engagement.sample.json"
    check("sample engagement JSON exists", sample.exists())
    if sample.exists():
        p = subprocess.run([sys.executable, str(SCRIPTS / "report.py"),
                            "--input", str(sample), "--outdir", tmp, "--html"],
                           capture_output=True, text=True)
        htmls = list(Path(tmp).glob("*.html"))
        check("report --html produces a file", len(htmls) == 1 and p.returncode == 0, p.stderr.strip())
        if htmls:
            body = htmls[0].read_text(encoding="utf-8")
            check("report has no LHIND/Lufthansa branding",
                  not re.search(r"lhind|lufthansa", body, re.I))
            for sec in ("Executive summary", "Engagement context", "Findings", "Recommendations"):
                check("report section present: %s" % sec, sec in body)
            check("report references a catalog finding ID", "F-AWS-S3-001" in body)


# --- report ---
passed = sum(1 for _, ok, _ in results if ok)
for name, ok, detail in results:
    print(("PASS" if ok else "FAIL") + "  " + name + (("  :: " + detail) if (detail and not ok) else ""))
print("\n%d/%d checks passed" % (passed, len(results)))
sys.exit(0 if passed == len(results) else 1)
