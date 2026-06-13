"""
utils/bughunter_report.py — AI-written, bug-bounty-style Markdown report

Produces a professional vulnerability report in the voice of an experienced
bug-bounty hunter / penetration tester. When an LLM (Groq/Anthropic) key is
available it composes the narrative (executive summary, per-finding writeups,
impact, remediation). Without a key it falls back to a structured template so
a report is always produced.

Report sections per finding: Title · Severity/CVSS/CWE · Affected endpoint ·
Description · Steps to Reproduce (curl PoC) · Impact · Remediation · References.
"""
import os
import json
from typing import List, Dict, Any

from config import CONFIG
from agent.vulnerability_model import (
    ScanReport, Finding, sqli_type_label, cvss_vector, OWASP_CATEGORY,
    category_coverage,
)
from agent.sqli_agent import LLMClient
from utils.logger import logger


SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _coverage_rows_md(scan: ScanReport) -> List[str]:
    """Markdown table rows for the per-category coverage matrix."""
    rows = ["| SQLi Category | Status | Probes | Severity | Max CVSS | Endpoint(s) affected |",
            "| --- | --- | --- | --- | --- | --- |"]
    for c in category_coverage(scan):
        if c["vulnerable"]:
            status, sev = "**VULNERABLE**", c["severity"]
            cvss = c["max_cvss"]
            where = ", ".join(f"`{e}`" for e in c["endpoints"]) or "—"
        elif c["tested"]:
            status, sev, cvss, where = "not found", "—", "—", "—"
        else:
            status, sev, cvss, where = "not tested", "—", "—", "—"
        rows.append(f"| {c['sqli_type']} | {status} | {c['probes']} | {sev} | {cvss} | {where} |")
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# COLLECT & DEDUPE CONFIRMED FINDINGS
# ─────────────────────────────────────────────────────────────────────────────
def _representative_findings(scan: ScanReport) -> List[Finding]:
    """One best finding per (endpoint, method, parameter, category)."""
    best: Dict[tuple, Finding] = {}
    for er in scan.endpoint_reports:
        for f in er.findings:
            if not f.is_vulnerable:
                continue
            key = (f.endpoint, f.method, f.parameter, f.display_category)
            cur = best.get(key)
            if cur is None or (f.cvss_score, f.confidence) > (cur.cvss_score, cur.confidence):
                best[key] = f
    findings = list(best.values())
    findings.sort(key=lambda f: (SEV_ORDER.get(f.risk_level.value, 9), -f.cvss_score))
    return findings


def _poc_curl(scan: ScanReport, f: Finding) -> str:
    """Build a copy-pasteable curl PoC for a finding."""
    base = f.endpoint if f.endpoint.startswith("http") else scan.target_url.rstrip("/") + f.endpoint
    if f.method == "GET":
        sep = "&" if "?" in base else "?"
        return f'curl "{base}{sep}{f.parameter}={f.payload}"'
    if f.method in ("POST", "PUT", "PATCH"):
        body = json.dumps({f.parameter: f.payload})
        return (f"curl -X {f.method} \"{base}\" "
                f"-H 'Content-Type: application/json' -d '{body}'")
    if f.method == "DELETE":
        sep = "&" if "?" in base else "?"
        return f'curl -X DELETE "{base}{sep}{f.parameter}={f.payload}"'
    return f'# {f.method} {base}  param={f.parameter} payload={f.payload}'


def _findings_payload(scan: ScanReport, findings: List[Finding]) -> List[Dict[str, Any]]:
    return [{
        "sqli_type": sqli_type_label(f.display_category),
        "title": f"{sqli_type_label(f.display_category)} in `{f.parameter}` on {f.endpoint}",
        "severity": f.risk_level.value,
        "cvss": f.cvss_score,
        "cvss_vector": cvss_vector(f.risk_level.value),
        "cwe": ", ".join(f.cwe_refs),
        "owasp": OWASP_CATEGORY,
        "category": f.display_category,
        "dbms": f.dbms or "unknown",
        "endpoint": f.endpoint,
        "method": f.method,
        "parameter": f.parameter,
        "payload": f.payload,
        "detection_method": f.detection_method.value,
        "confidence": round(f.confidence, 2),
        "evidence": f.evidence[:300],
        "confirmation": f.confirmation or "",
        "exploitation": f.exploitation or "",
        "poc": _poc_curl(scan, f),
        "llm_note": f.llm_analysis or "",
        "remediation": f.remediation,
    } for f in findings]


# ─────────────────────────────────────────────────────────────────────────────
# LLM-WRITTEN REPORT
# ─────────────────────────────────────────────────────────────────────────────
def _llm_report(scan: ScanReport, items: List[Dict[str, Any]], llm: LLMClient) -> str:
    coverage = category_coverage(scan)
    meta = {
        "target": scan.target_url,
        "scan_start": scan.scan_start,
        "scan_end": scan.scan_end,
        "endpoints_tested": len(scan.endpoint_reports),
        "total_probes": scan.total_payloads_fired,
        "total_vulnerabilities": scan.total_vulnerabilities,
        "critical": scan.critical_count,
        "overall_risk": scan.overall_risk.value,
        "llm_provider": scan.llm_provider,
    }
    prompt = f"""You are a senior penetration tester writing a formal SQL Injection
penetration-test report for a client. Write clean GitHub-flavoured Markdown in a
precise, professional consulting voice.

SCAN METADATA (JSON):
{json.dumps(meta, indent=2)}

CONFIRMED FINDINGS (JSON array — use these facts ONLY; do NOT invent endpoints,
payloads, or types. Each item has an authoritative `sqli_type`):
{json.dumps(items, indent=2)}

SQLi CATEGORY COVERAGE (JSON array — one row per SQLi class with tested/confirmed
status and the endpoints affected; render this VERBATIM as the coverage table):
{json.dumps(coverage, indent=2)}

Produce a report with EXACTLY this structure and headings:

# SQL Injection — Penetration Test Report

**Target:** <target>  |  **Date:** <scan_end date>  |  **Assessed by:** SQLSlayer (automated agent)  |  **Classification:** CONFIDENTIAL

## 1. Executive Summary
3-6 sentences for management: overall risk, counts by severity, and worst-case business impact in plain language.

## 2. Scope & Methodology
2-3 sentences: what was tested (target + endpoint/parameter count) and the approach (payload library across all SQLi classes; static signals + boolean/time oracles + DBMS fingerprinting; AI validation; harmless confirmation; CWE-89 / OWASP {OWASP_CATEGORY}).

## 3. SQLi Category Coverage
One sentence stating every SQLi class was probed, then a Markdown table built from the COVERAGE array with columns: SQLi Category | Status | Probes | Severity | Max CVSS | Endpoint(s) affected. For each row: Status is **VULNERABLE** when `vulnerable` is true (else "not found" if `tested` else "not tested"); list the `endpoints` verbatim. Do not omit any category.

## 4. Summary of Findings
A Markdown table with columns: ID | Severity | SQLi Type | Endpoint | Parameter | CVSS. Number findings F-01, F-02, … in descending severity.

## 5. Detailed Findings
For EACH finding a `### F-NN — [SEVERITY] <sqli_type>` section containing these labelled lines:
- **SQLi Type:** <the item's `sqli_type` verbatim>
- **Severity / CVSS:** <severity> / <cvss> `<cvss_vector>`
- **Classification:** <cwe> · OWASP {OWASP_CATEGORY}
- **Database:** <dbms>
- **Affected:** `<method> <endpoint>` — parameter `<parameter>`
- **Detection:** <detection_method> (confidence)
- **Description:** 2-4 sentences on the root cause for THIS sqli_type.
- **Proof of Concept:** a fenced ```bash``` block with the `poc` command; then the observed `evidence`.
- **Confirmation:** the `confirmation` field verbatim if present (harmless PoC — marker + DB version).
- **Exploitation:** the `exploitation` field verbatim if present (table names only).
- **Impact:** concrete consequences for THIS sqli_type.
- **Remediation:** the specific fix.

## 6. Recommendations
A prioritised checklist (parameterised queries, allow-listing ORDER BY, least-privilege DB user, error suppression, WAF, re-test).

## 7. Disclaimer
One line: authorised testing only; automated findings should be manually validated.

Output ONLY the Markdown — no preamble and no code fence around the whole document."""

    raw = llm.analyse(prompt)
    if raw:
        return raw.replace("```markdown", "").strip()
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# TEMPLATE FALLBACK (no LLM key)
# ─────────────────────────────────────────────────────────────────────────────
def _template_report(scan: ScanReport, items: List[Dict[str, Any]]) -> str:
    sev_counts: Dict[str, int] = {}
    for it in items:
        sev_counts[it["severity"]] = sev_counts.get(it["severity"], 0) + 1

    lines = [
        "# SQL Injection — Penetration Test Report",
        "",
        f"**Target:** {scan.target_url}  |  **Date:** {scan.scan_end[:10]}  "
        f"|  **Assessed by:** SQLSlayer (automated agent)  |  **Classification:** CONFIDENTIAL",
        "",
        "## 1. Executive Summary",
        "",
        f"SQLSlayer assessed {len(scan.endpoint_reports)} endpoint(s) with "
        f"{scan.total_payloads_fired} probes and confirmed "
        f"{scan.total_vulnerabilities} SQL injection finding(s) ({len(items)} unique), "
        f"of which {scan.critical_count} are CRITICAL. Overall risk is "
        f"**{scan.overall_risk.value}**. Unsanitised user input is concatenated "
        "directly into SQL statements, allowing data disclosure, authentication "
        "bypass and — where stacked queries execute — full database compromise.",
        "",
        "Severity breakdown: " + ", ".join(
            f"{sev} {sev_counts[sev]}" for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            if sev_counts.get(sev)) + ".",
        "",
        "## 2. Scope & Methodology",
        "",
        f"**Scope:** {scan.target_url} — {len(scan.endpoint_reports)} endpoint(s)/parameter(s). "
        "**Methodology:** each parameter was baselined and probed across all SQLi classes; "
        "findings were determined from database errors, reflected UNION/SQL data, response "
        "differentials, a boolean true/false oracle, and a jitter-aware time oracle, with "
        "DBMS fingerprinting and an AI validation pass, then proven with a harmless "
        f"confirmation. **Standards:** CWE-89 · OWASP {OWASP_CATEGORY}.",
        "",
        "## 3. SQLi Category Coverage",
        "",
        "Every SQL injection class was probed. This matrix shows, per class, whether "
        "it was tested, whether it was confirmed, and on which endpoint(s). "
        "_Not tested_ usually means that class's payloads were withheld (e.g. "
        "destructive stacked queries are skipped in read-only safe mode).",
        "",
        *_coverage_rows_md(scan),
        "",
        "## 4. Summary of Findings",
        "",
        "| ID | Severity | SQLi Type | Endpoint | Parameter | CVSS |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for i, it in enumerate(items, 1):
        lines.append(f"| F-{i:02d} | {it['severity']} | {it['sqli_type']} | "
                     f"`{it['method']} {it['endpoint']}` | `{it['parameter']}` | {it['cvss']} |")
    lines += ["", "## 5. Detailed Findings", ""]

    for i, it in enumerate(items, 1):
        lines += [
            f"### F-{i:02d} — [{it['severity']}] {it['sqli_type']}",
            "",
            f"- **SQLi Type:** {it['sqli_type']}",
            f"- **Severity / CVSS:** {it['severity']} / {it['cvss']} `{it['cvss_vector']}`",
            f"- **Classification:** {it['cwe']} · OWASP {it['owasp']}",
            f"- **Database:** {it['dbms']}",
            f"- **Affected:** `{it['method']} {it['endpoint']}` — parameter `{it['parameter']}`",
            f"- **Detection:** {it['detection_method']} (confidence {it['confidence']})",
            "",
            f"**Description.** {_describe(it['category'])}",
            "",
            "**Proof of Concept.**",
            "",
            "```bash",
            it["poc"],
            "```",
            (f"\nObserved evidence: `{it['evidence']}`" if it["evidence"] else ""),
            (f"\n**Confirmation (harmless PoC):** {it['confirmation']}" if it["confirmation"] else ""),
            (f"\n**Exploitation (schema only):** {it['exploitation']}" if it["exploitation"] else ""),
            (f"\n> AI analysis: {it['llm_note']}" if it["llm_note"] else ""),
            "",
            f"**Impact.** {_impact_for(it['category'])}",
            "",
            f"**Remediation.** {it['remediation']}",
            "",
            "---",
            "",
        ]

    lines += [
        "## 6. Recommendations",
        "",
        "1. Replace all string-concatenated SQL with **parameterised queries / prepared statements**.",
        "2. For non-parameterisable clauses (e.g. `ORDER BY`), **allow-list** valid column names.",
        "3. Run the application under a **least-privilege** database account.",
        "4. **Suppress** detailed database errors in API responses.",
        "5. Add a **WAF** and server-side input validation as defence-in-depth.",
        "6. **Re-test** after remediation to confirm closure.",
        "",
        "## 7. Disclaimer",
        "",
        "_For authorised security testing only. Automated findings should be manually validated before remediation sign-off._",
    ]
    return "\n".join(l for l in lines if l is not None)


def _describe(category: str) -> str:
    return {
        "IN_BAND_UNION": "User input is concatenated into the query, allowing a UNION SELECT to append attacker-chosen columns and read data in the response.",
        "BOOLEAN_BLIND": "The query logic can be altered with a boolean condition; TRUE and FALSE conditions yield different responses, enabling data inference.",
        "TIME_BASED": "A conditional time delay can be injected, letting an attacker infer data from response timing.",
        "ERROR_BASED": "Malformed input raises a database error that is reflected to the client, leaking structure/version.",
        "STACKED": "Multiple statements execute, so an attacker can append a new statement after the original query.",
        "COMMENT_STRIP": "A SQL comment truncates the password check, enabling authentication bypass.",
        "HEADER_INJECT": "An HTTP header value is interpolated into SQL; header inputs are rarely validated.",
        "ORDERBY": "The ORDER BY column is user-controlled and cannot be parameterised.",
        "SECOND_ORDER": "A stored value is later used unsafely in another query, executing away from the input point.",
        "TAUTOLOGY": "An always-true condition subverts the query and returns unauthorised rows.",
    }.get(category, "User input reaches a SQL query without parameterisation.")


def _impact_for(category: str) -> str:
    return {
        "IN_BAND_UNION": "Direct extraction of arbitrary tables/columns (credentials, PII) via UNION SELECT.",
        "BOOLEAN_BLIND": "Bit-by-bit data extraction by observing true/false response differences.",
        "TIME_BASED": "Blind data extraction via timing side-channel even when no output is returned.",
        "ERROR_BASED": "Database structure and data leaked through verbose error messages.",
        "STACKED": "Execution of arbitrary additional statements — data modification, account creation, or table drops (full DB compromise).",
        "COMMENT_STRIP": "Authentication bypass — log in as any user, including admin, without valid credentials.",
        "HEADER_INJECT": "Injection via HTTP headers, frequently bypassing input filters and WAFs.",
        "ORDERBY": "Conditional data extraction and timing attacks through the ORDER BY clause.",
        "SECOND_ORDER": "Stored payload executes later in a trusted context, evading input-time filtering.",
        "TAUTOLOGY": "Query logic subversion returning unauthorised rows.",
    }.get(category, "Unauthorised data access or modification.")


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def generate_markdown_report(scan: ScanReport, output_dir: str,
                             max_findings: int = 30) -> str:
    os.makedirs(output_dir, exist_ok=True)
    findings = _representative_findings(scan)

    truncated = False
    if len(findings) > max_findings:
        findings = findings[:max_findings]
        truncated = True

    items = _findings_payload(scan, findings)

    md = ""
    llm = LLMClient()
    if CONFIG.agent.enable_llm_analysis and llm.available() and items:
        logger.info("Composing AI bug-hunter report via LLM …")
        md = _llm_report(scan, items, llm)

    if not md:
        if llm.available() and items:
            logger.warning("LLM report empty — using template fallback")
        md = _template_report(scan, items)

    if truncated:
        md += (f"\n\n> _Note: report limited to the top {max_findings} findings; "
               f"additional lower-severity findings exist in the JSON report._\n")
    if not items:
        md += "\n_No vulnerabilities were confirmed in this scan._\n"

    path = os.path.join(output_dir, "sqli_report.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(md)
    return path
