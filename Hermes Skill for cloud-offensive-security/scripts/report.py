#!/usr/bin/env python3
"""Engagement report generator for cloud-offensive-security.

Input : an engagement JSON (see samples/engagement.sample.json).
Output: a self-contained HTML report and a PDF, following the 7-part structure
        defined in 00-methodology (exec summary, context, attack narrative,
        findings, detection assessment, recommendations, appendices).

Vendor-neutral by design: no employer branding, system fonts only, a single
configurable accent colour. Pure stdlib for HTML; PDF via whichever engine is
present (weasyprint > wkhtmltopdf > chromium), falling back to print-ready HTML.

Usage:
  report.py --input engagement.json --outdir out            # HTML + PDF (default)
  report.py --input engagement.json --outdir out --html      # HTML only
  report.py --input engagement.json --outdir out --pdf       # PDF only
  report.py --input engagement.json --outdir out --engine wkhtmltopdf
"""
import argparse
import html
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEV_COLOR = {"Critical": "#b3261e", "High": "#c2410c", "Medium": "#b45309",
             "Low": "#3f6212", "Info": "#475569"}
ACCENT = "#0f766e"  # neutral teal; override with --accent

FID_RE = re.compile(r"^F-(?:AWS|AZ|GCP|MC)-[A-Z0-9]+-[0-9]{3}$")


def esc(s):
    return html.escape("" if s is None else str(s))


def para(s):
    """Escape and turn blank-line-separated text into <p>, single newlines to <br>."""
    s = "" if s is None else str(s)
    blocks = re.split(r"\n\s*\n", s.strip())
    return "".join("<p>%s</p>" % esc(b).replace("\n", "<br>") for b in blocks if b.strip())


def catalog_ids():
    ids = set()
    for cat in ("02-aws/findings-mapping.md", "03-azure/findings-mapping.md",
                "04-gcp/findings-mapping.md"):
        p = ROOT / cat
        if p.exists():
            ids |= set(re.findall(r"F-(?:AWS|AZ|GCP|MC)-[A-Z0-9]+-[0-9]{3}",
                                  p.read_text(encoding="utf-8")))
    for n in range(10, 24):
        ids.add("F-AWS-LOG-%03d" % n)
    return ids


def load_authorization():
    """Read the human-authored authorization record if reachable (for the scope note)."""
    for env in ("CLOUD_OFFSEC_AUTH",):
        p = os.environ.get(env)
        if p and Path(p).exists():
            try:
                return json.loads(Path(p).read_text(encoding="utf-8"))
            except ValueError:
                return None
    default = (Path(os.environ.get("HERMES_STATE", Path.home() / ".hermes" / "state"))
               / "cloud-offensive-security" / "authorization.json")
    if default.exists():
        try:
            return json.loads(default.read_text(encoding="utf-8"))
        except ValueError:
            return None
    return None


CSS = """
:root {{ --accent: {accent}; --ink:#1f2933; --muted:#5b6b7b; --line:#dfe3e8;
        --bg:#ffffff; --panel:#f6f8fa; }}
* {{ box-sizing:border-box; }}
html {{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
body {{ font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
        color:var(--ink); background:var(--bg); margin:0; font-size:11pt; line-height:1.5; }}
h1,h2,h3 {{ line-height:1.25; }}
h2 {{ font-size:16pt; border-bottom:2px solid var(--accent); padding-bottom:4px; margin-top:1.6em; }}
h3 {{ font-size:12.5pt; margin:1.2em 0 .3em; }}
a {{ color:var(--accent); }}
code,pre {{ font-family:ui-monospace,Menlo,Consolas,monospace; font-size:9.5pt; }}
pre {{ background:var(--panel); border:1px solid var(--line); border-radius:4px;
       padding:8px 10px; overflow-x:auto; white-space:pre-wrap; }}
.wrap {{ max-width:820px; margin:0 auto; padding:0 24px 40px; }}
.cover {{ min-height:88vh; display:flex; flex-direction:column; justify-content:center; }}
.cover .kicker {{ color:var(--accent); font-weight:700; letter-spacing:.14em; text-transform:uppercase; font-size:10pt; }}
.cover h1 {{ font-size:30pt; margin:.2em 0 .1em; }}
.cover .sub {{ color:var(--muted); font-size:13pt; }}
.meta {{ margin-top:2.2em; border-top:1px solid var(--line); padding-top:1em; }}
.meta table {{ border-collapse:collapse; width:100%; }}
.meta td {{ padding:4px 8px 4px 0; vertical-align:top; font-size:10.5pt; }}
.meta td.k {{ color:var(--muted); width:150px; white-space:nowrap; }}
table.grid {{ border-collapse:collapse; width:100%; margin:.6em 0; }}
table.grid th, table.grid td {{ border:1px solid var(--line); padding:6px 8px; text-align:left; font-size:10pt; vertical-align:top; }}
table.grid th {{ background:var(--panel); }}
.sev {{ display:inline-block; color:#fff; padding:1px 8px; border-radius:10px; font-size:9pt; font-weight:700; }}
.finding {{ border:1px solid var(--line); border-left:5px solid var(--muted); border-radius:6px;
            padding:12px 14px; margin:14px 0; page-break-inside:avoid; break-inside:avoid; }}
.finding h3 {{ margin-top:0; }}
.finding .fid {{ color:var(--muted); font-size:9.5pt; font-weight:400; }}
.finding dl {{ display:grid; grid-template-columns:130px 1fr; gap:2px 12px; margin:.4em 0 0; }}
.finding dt {{ color:var(--muted); font-size:9.5pt; }}
.bar {{ display:flex; height:16px; border-radius:8px; overflow:hidden; border:1px solid var(--line); }}
.bar span {{ display:block; }}
.legend {{ font-size:9.5pt; color:var(--muted); margin-top:6px; }}
.footer-note {{ margin-top:2.4em; padding-top:.8em; border-top:1px solid var(--line);
                color:var(--muted); font-size:9pt; }}
@page {{ size:A4; margin:18mm 16mm 20mm; }}
.pagebreak {{ page-break-before:always; }}
"""


def sev_badge(sev):
    c = SEV_COLOR.get(sev, "#475569")
    return '<span class="sev" style="background:%s">%s</span>' % (c, esc(sev))


def severity_bar(counts):
    total = sum(counts.values()) or 1
    cells = ""
    for s in SEV_ORDER:
        n = counts.get(s, 0)
        if n:
            cells += '<span style="width:%.2f%%;background:%s" title="%s: %d"></span>' % (
                100.0 * n / total, SEV_COLOR[s], s, n)
    legend = " · ".join("%s %d" % (s, counts.get(s, 0)) for s in SEV_ORDER if counts.get(s, 0))
    return '<div class="bar">%s</div><div class="legend">%s</div>' % (cells, esc(legend))


def build_html(data, accent):
    eng = data.get("engagement", {})
    findings = list(data.get("findings", []))
    known = catalog_ids()

    # sort findings by severity then id
    sev_idx = {s: i for i, s in enumerate(SEV_ORDER)}
    findings.sort(key=lambda f: (sev_idx.get(f.get("severity", "Info"), 99), f.get("id", "")))
    counts = {}
    for f in findings:
        counts[f.get("severity", "Info")] = counts.get(f.get("severity", "Info"), 0) + 1

    mode = eng.get("mode", "CLOUD_AUDIT")
    is_redteam = mode == "CLOUD_REDTEAM"
    gen_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    P = []
    P.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    P.append("<meta name='viewport' content='width=device-width,initial-scale=1'>")
    P.append("<title>%s</title>" % esc(eng.get("title", "Cloud Security Assessment")))
    P.append("<style>%s</style></head><body>" % (CSS.format(accent=accent)))
    P.append("<div class='wrap'>")

    # --- cover ---
    P.append("<section class='cover'>")
    P.append("<div class='kicker'>Cloud Security Assessment</div>")
    P.append("<h1>%s</h1>" % esc(eng.get("title", "Cloud Security Assessment")))
    if eng.get("client"):
        P.append("<div class='sub'>Prepared for %s</div>" % esc(eng["client"]))
    P.append("<div class='meta'><table>")
    rows = [
        ("Assessor", eng.get("assessor")),
        ("Engagement mode", {"CLOUD_AUDIT": "Configuration audit (passive)",
                             "CLOUD_REDTEAM": "Red team / full kill chain"}.get(mode, mode)),
        ("Platforms", ", ".join(eng.get("platforms", [])) or None),
        ("Assessment period", _period(eng.get("period"))),
        ("Severity model", eng.get("severity_model", "5-tier (Info / Low / Medium / High / Critical)")),
        ("Report date", gen_at[:10]),
    ]
    for k, v in rows:
        if v:
            P.append("<tr><td class='k'>%s</td><td>%s</td></tr>" % (esc(k), esc(v)))
    P.append("</table></div></section>")

    # --- 1. executive summary ---
    P.append("<div class='pagebreak'></div>")
    P.append("<h2>1. Executive summary</h2>")
    if data.get("executive_summary"):
        P.append(para(data["executive_summary"]))
    else:
        P.append("<p>This assessment identified %d finding(s) across %s. "
                 "The severity distribution is shown below; the highest-rated issues "
                 "are summarised in the finding overview.</p>"
                 % (len(findings), ", ".join(eng.get("platforms", [])) or "the in-scope environment"))
    P.append(severity_bar(counts))
    # top findings table
    P.append("<h3>Finding overview</h3><table class='grid'><tr><th>ID</th><th>Finding</th><th>Severity</th><th>Asset</th></tr>")
    for f in findings:
        P.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            esc(f.get("id", "")), esc(f.get("title", "")), sev_badge(f.get("severity", "Info")),
            esc(f.get("asset", ""))))
    if not findings:
        P.append("<tr><td colspan='4'>No findings recorded.</td></tr>")
    P.append("</table>")

    # --- 2. engagement context ---
    P.append("<h2>2. Engagement context</h2>")
    auth = load_authorization()
    scope = eng.get("scope") or (auth.get("scope") if auth else None)
    P.append("<h3>Scope and authorization</h3>")
    if scope:
        P.append("<p>The following targets were explicitly in scope:</p><ul>%s</ul>"
                 % "".join("<li><code>%s</code></li>" % esc(x) for x in scope))
    if auth and auth.get("reason"):
        P.append("<p>Testing was authorized: %s (operator: %s; valid until %s).</p>"
                 % (esc(auth.get("reason")), esc(auth.get("operator", "—")), esc(auth.get("expires", "—"))))
    else:
        P.append("<p>Testing was conducted under a written authorization held by the assessing party.</p>")
    if eng.get("roe"):
        P.append("<h3>Rules of engagement</h3>%s" % para(eng["roe"]))
    P.append("<h3>Methodology</h3><p>The assessment followed a cloud kill-chain methodology "
             "(recon, initial access, enumeration, privilege escalation, lateral movement, "
             "persistence, exfiltration), with control checks aligned to the CIS Foundations "
             "Benchmarks and techniques mapped to the MITRE ATT&amp;CK Cloud matrix.</p>")

    n = 3
    # --- 3. attack narrative (red team only) ---
    if is_redteam and data.get("attack_narrative"):
        P.append("<h2>%d. Attack narrative</h2>" % n); n += 1
        P.append("<table class='grid'><tr><th>Time</th><th>Step</th><th>Detected</th></tr>")
        for step in data["attack_narrative"]:
            det = step.get("detected")
            det_s = "Yes" if det is True else ("No" if det is False else "—")
            P.append("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                esc(step.get("time", "")), esc(step.get("step", "")), det_s))
        P.append("</table>")

    # --- findings (detailed) ---
    P.append("<h2>%d. Findings</h2>" % n); n += 1
    for f in findings:
        fid = f.get("id", "")
        border = SEV_COLOR.get(f.get("severity", "Info"), "#475569")
        unknown = fid and FID_RE.match(fid) and fid not in known
        P.append("<div class='finding' style='border-left-color:%s'>" % border)
        P.append("<h3>%s <span class='fid'>%s%s</span></h3>" % (
            esc(f.get("title", "Untitled finding")), esc(fid),
            " · not in catalog" if unknown else ""))
        P.append("<p>%s &nbsp; <code>%s</code></p>" % (sev_badge(f.get("severity", "Info")), esc(f.get("asset", ""))))
        if f.get("description"):
            P.append(para(f["description"]))
        if f.get("attack_path"):
            P.append("<dl><dt>Attack path</dt><dd>%s</dd></dl>" % esc(f["attack_path"]))
        if f.get("evidence"):
            P.append("<dt style='color:var(--muted);font-size:9.5pt'>Evidence</dt><pre>%s</pre>" % esc(f["evidence"]))
        if f.get("impact"):
            P.append("<dl><dt>Business impact</dt><dd>%s</dd></dl>" % esc(f["impact"]))
        if f.get("remediation"):
            P.append("<dl><dt>Remediation</dt><dd>%s</dd></dl>" % esc(f["remediation"]))
        refs = f.get("references") or []
        if refs:
            P.append("<dl><dt>References</dt><dd>%s</dd></dl>" % esc(" · ".join(refs)))
        P.append("</div>")

    # --- detection assessment (red team only) ---
    if is_redteam and data.get("detection_assessment"):
        P.append("<h2>%d. Detection assessment</h2>" % n); n += 1
        P.append(para(data["detection_assessment"]))

    # --- recommendations ---
    rec = data.get("recommendations") or {}
    if rec:
        P.append("<h2>%d. Recommendations</h2>" % n); n += 1
        for key, label in (("quick_wins", "Quick wins"), ("structural", "Structural"),
                           ("strategic", "Strategic")):
            items = rec.get(key) or []
            if items:
                P.append("<h3>%s</h3><ul>%s</ul>" % (label, "".join("<li>%s</li>" % esc(i) for i in items)))

    # --- appendices ---
    apps = data.get("appendices") or []
    if apps:
        P.append("<h2>%d. Appendices</h2>" % n)
        for a in apps:
            P.append("<h3>%s</h3>" % esc(a.get("title", "Appendix")))
            body = a.get("body", "")
            P.append("<pre>%s</pre>" % esc(body) if a.get("verbatim") else para(body))

    P.append("<div class='footer-note'>%s report generated %s. "
             "Report drafted with AI assistance; all findings were reviewed and validated by the assessor "
             "before issue. This document is confidential and intended only for the named recipient.</div>"
             % (esc(eng.get("title", "Cloud Security Assessment")), esc(gen_at[:10])))
    P.append("</div></body></html>")
    return "".join(P)


def _period(p):
    if not p:
        return None
    if isinstance(p, str):
        return p
    s, e = p.get("start"), p.get("end")
    return " – ".join(x for x in (s, e) if x) or None


def render_pdf(html_path, pdf_path, engine):
    engines = [engine] if engine != "auto" else ["weasyprint", "wkhtmltopdf", "chromium"]
    for e in engines:
        try:
            if e == "weasyprint":
                import weasyprint  # noqa
                weasyprint.HTML(filename=str(html_path)).write_pdf(str(pdf_path))
                return "weasyprint"
            if e == "wkhtmltopdf" and shutil.which("wkhtmltopdf"):
                subprocess.run(["wkhtmltopdf", "--quiet", "--enable-local-file-access",
                                str(html_path), str(pdf_path)], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return "wkhtmltopdf"
            if e == "chromium":
                for b in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
                    if shutil.which(b):
                        subprocess.run([b, "--headless", "--no-sandbox",
                                        "--print-to-pdf=" + str(pdf_path), str(html_path)],
                                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        return b
        except Exception:
            continue
    return None


def main():
    ap = argparse.ArgumentParser(description="cloud-offensive-security report generator")
    ap.add_argument("--input", required=True, help="engagement JSON")
    ap.add_argument("--outdir", default="report-out")
    ap.add_argument("--html", action="store_true", help="produce HTML only")
    ap.add_argument("--pdf", action="store_true", help="produce PDF only")
    ap.add_argument("--engine", default="auto",
                    choices=["auto", "weasyprint", "wkhtmltopdf", "chromium"])
    ap.add_argument("--accent", default=ACCENT, help="accent colour (hex)")
    args = ap.parse_args()

    want_html = args.html or not args.pdf
    want_pdf = args.pdf or not args.html

    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    outdir = Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)
    base = re.sub(r"[^A-Za-z0-9._-]+", "-",
                  data.get("engagement", {}).get("title", "cloud-assessment")).strip("-") or "report"

    html_str = build_html(data, args.accent)
    html_path = outdir / (base + ".html")
    html_path.write_text(html_str, encoding="utf-8")
    produced = [str(html_path)] if want_html else []
    if not want_html:  # PDF-only: still need the html on disk to render from
        pass

    pdf_used = None
    if want_pdf:
        pdf_path = outdir / (base + ".pdf")
        pdf_used = render_pdf(html_path, pdf_path, args.engine)
        if pdf_used:
            produced.append(str(pdf_path))
        else:
            print("WARN: no PDF engine available. Install one on the operator box:",
                  file=sys.stderr)
            print("      Kali: sudo apt install weasyprint  (or)  sudo apt install wkhtmltopdf",
                  file=sys.stderr)
            print("      The HTML at %s is print-ready (A4) — open it and Print > Save as PDF."
                  % html_path, file=sys.stderr)
        if not want_html:
            # PDF-only requested: remove the intermediate HTML
            try:
                html_path.unlink()
                produced = [p for p in produced if not p.endswith(".html")]
            except OSError:
                pass

    for p in produced:
        print(p)
    if pdf_used:
        print("PDF engine: %s" % pdf_used, file=sys.stderr)


if __name__ == "__main__":
    main()
