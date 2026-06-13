"""
utils/reporter.py — JSON + HTML report generators

The HTML output is a formal **penetration-test report**: cover, executive
summary, scope & methodology, a findings-summary table, detailed per-finding
write-ups (each naming the exact SQLi type), recommendations, and an appendix.
"""
import json
import os
from typing import List, Dict

from agent.vulnerability_model import (
    ScanReport, Finding, RiskLevel, sqli_type_label, cvss_vector, OWASP_CATEGORY,
    category_coverage,
)

RISK_COLORS = {
    "CRITICAL": "#c0392b", "HIGH": "#e67e22", "MEDIUM": "#d4ac0d",
    "LOW": "#27ae60", "INFO": "#2980b9",
}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

TYPE_DESCRIPTION = {
    "IN_BAND_UNION": "User input is concatenated into the SQL statement, allowing a UNION SELECT to append attacker-chosen columns and read arbitrary data in the response.",
    "BOOLEAN_BLIND": "The query's logic can be altered with a boolean condition; the application returns no data directly, but TRUE and FALSE conditions yield observably different responses, enabling bit-by-bit data inference.",
    "TIME_BASED": "The query can be made to pause via a time function; a conditional delay lets an attacker infer data from response timing even when nothing is returned.",
    "ERROR_BASED": "Malformed input causes the database to raise an error that is reflected to the client, leaking database structure/version and confirming injection.",
    "STACKED": "The endpoint executes multiple statements, so an attacker can append an entirely new statement (e.g. INSERT/UPDATE/DROP) after the original query.",
    "COMMENT_STRIP": "A SQL comment truncates the rest of the WHERE clause (e.g. the password check), allowing authentication bypass.",
    "HEADER_INJECT": "An HTTP header value is interpolated into SQL; header inputs are rarely validated, making this a common filter/WAF bypass.",
    "ORDERBY": "The ORDER BY column is user-controlled and cannot be parameterised, enabling conditional extraction and timing attacks.",
    "SECOND_ORDER": "A stored value is later used unsafely in a different query, so the injection executes away from the input point and evades input-time filtering.",
    "TAUTOLOGY": "An always-true condition subverts the query's logic and returns unauthorised rows.",
}
TYPE_IMPACT = {
    "IN_BAND_UNION": "Direct extraction of arbitrary tables/columns (credentials, PII).",
    "BOOLEAN_BLIND": "Full database contents extractable bit-by-bit via inference.",
    "TIME_BASED": "Blind data extraction via a timing side-channel; also a DoS vector.",
    "ERROR_BASED": "Database metadata and data disclosed through verbose errors.",
    "STACKED": "Arbitrary data modification, account creation, or table destruction — potential full database compromise.",
    "COMMENT_STRIP": "Authentication bypass — log in as any user, including admin.",
    "HEADER_INJECT": "Injection through headers, frequently bypassing input filters/WAFs.",
    "ORDERBY": "Conditional data extraction and timing attacks via the sort clause.",
    "SECOND_ORDER": "Delayed execution in a trusted context, bypassing input validation.",
    "TAUTOLOGY": "Unauthorised data disclosure by subverting query logic.",
}


# ─────────────────────────────────────────────────────────────────────────────
# JSON
# ─────────────────────────────────────────────────────────────────────────────
def generate_json_report(scan: ScanReport, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    coverage = category_coverage(scan)
    out = {
        "meta": {
            "tool": "SQLSlayer v1.0", "target": scan.target_url,
            "scan_start": scan.scan_start, "scan_end": scan.scan_end,
            "llm_provider": scan.llm_provider,
        },
        "summary": {
            "total_payloads": scan.total_payloads_fired,
            "total_vulnerabilities": scan.total_vulnerabilities,
            "critical": scan.critical_count,
            "overall_risk": scan.overall_risk.value,
            "categories_tested": sum(1 for c in coverage if c["tested"]),
            "categories_vulnerable": sum(1 for c in coverage if c["vulnerable"]),
        },
        "category_coverage": coverage,
        "endpoints": [
            {
                "endpoint": r.endpoint, "method": r.method,
                "max_risk": r.max_risk.value, "max_cvss": r.max_cvss,
                "total_probes": r.total_probes, "vulnerable": r.vulnerable_count,
                "findings": [f.to_dict() for f in r.findings if f.is_vulnerable],
            }
            for r in scan.endpoint_reports
        ],
    }
    path = os.path.join(output_dir, "sqli_report.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)
    return path


# ─────────────────────────────────────────────────────────────────────────────
# HTML — penetration-test report
# ─────────────────────────────────────────────────────────────────────────────
def _representative(scan: ScanReport) -> List[Finding]:
    best: Dict[tuple, Finding] = {}
    for er in scan.endpoint_reports:
        for f in er.findings:
            if not f.is_vulnerable:
                continue
            key = (f.endpoint, f.method, f.parameter, f.display_category)
            cur = best.get(key)
            if cur is None or (f.cvss_score, f.confidence) > (cur.cvss_score, cur.confidence):
                best[key] = f
    out = list(best.values())
    out.sort(key=lambda f: (SEV_ORDER.get(f.risk_level.value, 9), -f.cvss_score))
    return out


def generate_html_report(scan: ScanReport, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    findings = _representative(scan)
    coverage = category_coverage(scan)

    # ── category-coverage matrix rows ─────────────────────────────────────────
    cov_rows = ""
    for cov in coverage:
        if cov["vulnerable"]:
            cc = RISK_COLORS.get(cov["severity"], "#555")
            status = f'<span class="badge" style="background:{cc}">VULNERABLE</span>'
            sev = f'<span class="badge" style="background:{cc}">{cov["severity"]}</span>'
            cvss = cov["max_cvss"]
            where = ", ".join(f"<code>{_escape(e)}</code>" for e in cov["endpoints"]) or "—"
        elif cov["tested"]:
            status = '<span class="badge" style="background:#27ae60">not found</span>'
            sev = "—"; cvss = "—"; where = "—"
        else:
            status = '<span class="badge" style="background:#95a5a6">not tested</span>'
            sev = "—"; cvss = "—"; where = "—"
        cov_rows += f"""<tr>
            <td>{_escape(cov['sqli_type'])}</td>
            <td>{status}</td>
            <td>{cov['probes']}</td>
            <td>{sev}</td>
            <td>{cvss}</td>
            <td>{where}</td></tr>"""

    # severity tallies
    sev_counts = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    for f in findings:
        sev_counts[f.risk_level.value] = sev_counts.get(f.risk_level.value, 0) + 1

    overall = scan.overall_risk.value
    ocolor = RISK_COLORS.get(overall, "#555")

    # ── summary table rows ────────────────────────────────────────────────────
    summary_rows = ""
    for i, f in enumerate(findings, 1):
        c = RISK_COLORS.get(f.risk_level.value, "#555")
        summary_rows += f"""<tr>
            <td>F-{i:02d}</td>
            <td><span class="badge" style="background:{c}">{f.risk_level.value}</span></td>
            <td>{_escape(sqli_type_label(f.display_category))}</td>
            <td><code>{_escape(f.method)} {_escape(f.endpoint)}</code></td>
            <td><code>{_escape(f.parameter)}</code></td>
            <td>{f.cvss_score}</td></tr>"""

    # ── detailed findings ─────────────────────────────────────────────────────
    details = ""
    for i, f in enumerate(findings, 1):
        c = RISK_COLORS.get(f.risk_level.value, "#555")
        cat = f.display_category
        rows = [
            ("Severity", f'<span class="badge" style="background:{c}">{f.risk_level.value}</span>'),
            ("SQLi type", f"<b>{_escape(sqli_type_label(cat))}</b>"),
            ("CVSS v3.1", f"{f.cvss_score} &nbsp;<span class='vec'>{cvss_vector(f.risk_level.value)}</span>"),
            ("Classification", f"CWE-89 · OWASP {OWASP_CATEGORY}"),
            ("Database", _escape(f.dbms or "unknown")),
            ("Affected", f"<code>{_escape(f.method)} {_escape(f.endpoint)}</code> — parameter <code>{_escape(f.parameter)}</code>"),
            ("Detection", f"{f.detection_method.value} (confidence {round(f.confidence*100)}%)"),
        ]
        meta_rows = "".join(f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in rows)
        confirm = f'<div class="block ok"><b>Confirmation (harmless PoC):</b> {_escape(f.confirmation)}</div>' if f.confirmation else ""
        exploit = f'<div class="block warn"><b>Exploitation (schema only):</b> {_escape(f.exploitation)}</div>' if f.exploitation else ""
        llm = f'<div class="block ai"><b>AI analysis:</b> {_escape(f.llm_analysis)}</div>' if f.llm_analysis else ""
        details += f"""
        <div class="finding" style="border-left:5px solid {c}">
          <h3>F-{i:02d} &nbsp;[{f.risk_level.value}] &nbsp;{_escape(sqli_type_label(cat))}</h3>
          <table class="meta">{meta_rows}</table>
          <p><b>Description.</b> {_escape(TYPE_DESCRIPTION.get(cat, 'User input reaches a SQL query without parameterisation.'))}</p>
          <p><b>Proof of Concept.</b></p>
          <pre>{_escape(_poc(scan, f))}</pre>
          {confirm}{exploit}
          <p><b>Evidence.</b> {_escape(f.evidence[:300])}</p>
          {llm}
          <p><b>Impact.</b> {_escape(TYPE_IMPACT.get(cat, 'Unauthorised data access or modification.'))}</p>
          <p><b>Remediation.</b> {_escape(f.remediation or 'Use parameterised queries / prepared statements.')}</p>
        </div>"""

    if not findings:
        details = '<p class="none">No SQL injection vulnerabilities were confirmed.</p>'
        summary_rows = '<tr><td colspan="6" class="none">No findings.</td></tr>'

    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>SQL Injection — Penetration Test Report</title>
<style>
  * {{ box-sizing:border-box; }}
  body {{ font-family:'Segoe UI',Calibri,Arial,sans-serif; color:#222; background:#f4f5f7; margin:0; line-height:1.5; }}
  .page {{ max-width:980px; margin:0 auto; background:#fff; box-shadow:0 0 12px rgba(0,0,0,.08); }}
  .cover {{ background:linear-gradient(135deg,#1f4e79,#2e74b5); color:#fff; padding:48px 56px; }}
  .cover .conf {{ float:right; border:1px solid #fff; padding:3px 10px; border-radius:3px; font-size:.7rem; letter-spacing:1px; }}
  .cover h1 {{ font-size:2rem; margin:0 0 6px; }}
  .cover .sub {{ opacity:.9; font-size:.95rem; }}
  .cover table {{ margin-top:22px; color:#eaf2fb; font-size:.85rem; }}
  .cover td {{ padding:2px 18px 2px 0; }}
  section {{ padding:24px 56px; border-bottom:1px solid #eee; }}
  h2 {{ color:#1f4e79; font-size:1.25rem; border-bottom:2px solid #1f4e79; padding-bottom:5px; margin:0 0 14px; }}
  h3 {{ color:#1f4e79; font-size:1.05rem; margin:0 0 10px; }}
  .cards {{ display:flex; gap:14px; flex-wrap:wrap; }}
  .card {{ flex:1; min-width:130px; background:#f7f9fc; border:1px solid #e3e8ef; border-radius:7px; padding:14px; text-align:center; }}
  .card .n {{ font-size:1.7rem; font-weight:700; }}
  .card .l {{ font-size:.72rem; color:#667; text-transform:uppercase; margin-top:3px; }}
  table.grid {{ width:100%; border-collapse:collapse; font-size:.85rem; margin-top:8px; }}
  table.grid th {{ background:#1f4e79; color:#fff; text-align:left; padding:8px 10px; }}
  table.grid td {{ padding:7px 10px; border-bottom:1px solid #eee; vertical-align:top; }}
  table.grid tr:nth-child(even) td {{ background:#fafbfc; }}
  .badge {{ display:inline-block; padding:2px 9px; border-radius:3px; color:#fff; font-size:.72rem; font-weight:700; }}
  .finding {{ background:#fff; border:1px solid #e3e8ef; border-radius:7px; padding:18px 22px; margin-bottom:20px; }}
  table.meta {{ border-collapse:collapse; margin:6px 0 12px; font-size:.85rem; }}
  table.meta th {{ text-align:left; color:#667; font-weight:600; padding:3px 16px 3px 0; vertical-align:top; white-space:nowrap; }}
  table.meta td {{ padding:3px 0; }}
  code {{ background:#eef1f5; padding:1px 5px; border-radius:3px; font-family:Consolas,monospace; font-size:.82rem; color:#a31445; }}
  pre {{ background:#1e1e1e; color:#e6e6e6; padding:12px 14px; border-radius:6px; overflow-x:auto; font-family:Consolas,monospace; font-size:.8rem; }}
  .vec {{ font-family:Consolas,monospace; font-size:.72rem; color:#667; }}
  .block {{ padding:8px 12px; border-radius:5px; font-size:.84rem; margin:8px 0; }}
  .block.ok {{ background:#eafaf1; border:1px solid #cdeedd; }}
  .block.warn {{ background:#fdf3e7; border:1px solid #f6dcb8; }}
  .block.ai {{ background:#eef4fb; border:1px solid #d5e4f5; font-style:italic; }}
  ol {{ margin:0; padding-left:20px; }} li {{ margin:4px 0; }}
  .none {{ color:#27ae60; text-align:center; padding:14px; }}
  footer {{ padding:18px 56px; color:#889; font-size:.75rem; }}
</style></head><body><div class="page">

<div class="cover">
  <span class="conf">CONFIDENTIAL</span>
  <h1>SQL Injection — Penetration Test Report</h1>
  <div class="sub">Automated assessment performed by SQLSlayer</div>
  <table>
    <tr><td>Target</td><td><b>{_escape(scan.target_url)}</b></td></tr>
    <tr><td>Assessment window</td><td>{scan.scan_start[:19].replace('T',' ')} — {scan.scan_end[:19].replace('T',' ')} UTC</td></tr>
    <tr><td>Overall risk</td><td><b>{overall}</b></td></tr>
    <tr><td>Analysis engine</td><td>{_escape(scan.llm_provider)}</td></tr>
  </table>
</div>

<section>
  <h2>1. Executive Summary</h2>
  <p>SQLSlayer assessed <b>{len(scan.endpoint_reports)}</b> endpoint(s) using
  <b>{scan.total_payloads_fired}</b> probes and confirmed <b>{scan.total_vulnerabilities}</b>
  SQL injection finding(s) ({len(findings)} unique), of which <b>{scan.critical_count}</b>
  are CRITICAL. The overall risk to the target is
  <b style="color:{ocolor}">{overall}</b>. SQL injection allows an attacker to read or
  modify database contents and, in the worst case, fully compromise the data store.</p>
  <div class="cards">
    <div class="card"><div class="n" style="color:{ocolor}">{overall}</div><div class="l">Overall risk</div></div>
    <div class="card"><div class="n" style="color:#c0392b">{scan.total_vulnerabilities}</div><div class="l">Findings</div></div>
    <div class="card"><div class="n" style="color:#c0392b">{scan.critical_count}</div><div class="l">Critical</div></div>
    <div class="card"><div class="n" style="color:#1f4e79">{len(scan.endpoint_reports)}</div><div class="l">Endpoints</div></div>
    <div class="card"><div class="n" style="color:#1f4e79">{scan.total_payloads_fired}</div><div class="l">Probes</div></div>
  </div>
</section>

<section>
  <h2>2. Scope &amp; Methodology</h2>
  <p><b>Scope.</b> {_escape(scan.target_url)} — {len(scan.endpoint_reports)} endpoint(s) / parameter(s).</p>
  <p><b>Methodology.</b> Each parameter was baselined and probed with a SQL injection
  payload library across all major classes. Findings were determined by fusing static
  signals (database errors, reflected SQL/UNION data, response differentials, row counts),
  a boolean true/false oracle with similarity-ratio comparison, a jitter-aware time-based
  oracle, and DBMS fingerprinting — then validated by an AI reasoning pass. Confirmed
  injections were proven harmlessly (a controlled marker + the database version). Testing
  ran in read-only safe mode unless destructive testing was explicitly authorised.</p>
  <p><b>Standards.</b> CWE-89 · OWASP {OWASP_CATEGORY}.</p>
</section>

<section>
  <h2>3. SQLi Category Coverage</h2>
  <p>Every SQL injection class was probed. The matrix below shows, per class,
  whether it was tested, whether it was confirmed vulnerable, and on which
  endpoint(s) — so coverage and where each category was found are explicit.
  <i>Not tested</i> typically means that class's payloads were withheld (e.g.
  destructive stacked queries are skipped in read-only safe mode).</p>
  <table class="grid">
    <tr><th>SQLi category</th><th>Status</th><th>Probes</th><th>Severity</th><th>Max CVSS</th><th>Endpoint(s) affected</th></tr>
    {cov_rows}
  </table>
</section>

<section>
  <h2>4. Summary of Findings</h2>
  <table class="grid">
    <tr><th>ID</th><th>Severity</th><th>SQLi type</th><th>Endpoint</th><th>Parameter</th><th>CVSS</th></tr>
    {summary_rows}
  </table>
</section>

<section>
  <h2>5. Detailed Findings</h2>
  {details}
</section>

<section>
  <h2>6. Recommendations</h2>
  <ol>
    <li>Replace all string-concatenated SQL with <b>parameterised queries / prepared statements</b>.</li>
    <li>For non-parameterisable clauses (e.g. <code>ORDER BY</code>), <b>allow-list</b> valid column names.</li>
    <li>Run the application under a <b>least-privilege</b> database account.</li>
    <li><b>Suppress</b> detailed database errors in API responses.</li>
    <li>Add a <b>WAF</b> and server-side input validation as defence-in-depth.</li>
    <li>Re-test after remediation to confirm closure.</li>
  </ol>
</section>

<footer>
  SQLSlayer v1.0 — automated SQL injection assessment. For authorised security testing
  only; automated findings should be manually validated before remediation sign-off.
</footer>
</div></body></html>"""

    path = os.path.join(output_dir, "sqli_report.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return path


def _poc(scan: ScanReport, f: Finding) -> str:
    base = f.endpoint if f.endpoint.startswith("http") else scan.target_url.rstrip("/") + f.endpoint
    if f.method in ("POST", "PUT", "PATCH"):
        body = json.dumps({f.parameter: f.payload})
        return f"curl -X {f.method} \"{base}\" -H 'Content-Type: application/json' -d '{body}'"
    sep = "&" if "?" in base else "?"
    verb = "" if f.method == "GET" else f"-X {f.method} "
    return f'curl {verb}"{base}{sep}{f.parameter}={f.payload}"'


def _escape(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _method_color(method: str) -> str:
    return {"GET": "#27ae60", "POST": "#2980b9",
            "PUT": "#e67e22", "DELETE": "#c0392b"}.get(method.upper(), "#666")
