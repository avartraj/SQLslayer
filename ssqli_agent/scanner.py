"""
scanner.py — Unified SQL Injection scan orchestrator

Drives the SQLSlayer across three input modes and produces a ScanReport plus
HTML/JSON reports:

    1. Single URL   : scan_single_url("https://site/page?id=1&q=x")
    2. URL file     : scan_url_file("urls.txt")   (one URL per line)
    3. Domain       : scan_domain("example.com")  (full recon → crawl → scan)

All three converge on a list of ParamTarget objects which are then probed
parameter-by-parameter by the agent.
"""
import datetime
from typing import List, Optional

from config import CONFIG
from agent.sqli_agent import SQLSlayer
from agent.payload_engine import Payload
from agent.vulnerability_model import (
    Finding, ScanReport, EndpointReport, RiskLevel,
)
from recon.param_target import ParamTarget
from recon.param_discovery import targets_from_urls
from recon.recon_orchestrator import recon_domain
from utils.reporter import generate_html_report, generate_json_report
from utils.bughunter_report import generate_markdown_report
from utils.logger import logger


# ─────────────────────────────────────────────────────────────────────────────
# TARGET → FINDINGS
# ─────────────────────────────────────────────────────────────────────────────
def scan_target(agent: SQLSlayer, target: ParamTarget,
                payloads: Optional[List[Payload]] = None) -> List[Finding]:
    """Scan every parameter in a single ParamTarget."""
    findings: List[Finding] = []
    for param_name in target.params:
        if target.param_type == "query":
            findings.extend(agent.scan_url(
                url        = target.url,
                param_name = param_name,
                method     = target.method,
                param_type = "query",
                base_query = target.params,
                baseline_value = target.params.get(param_name, "1"),
                payloads   = payloads,
            ))
        else:  # body / json form parameters
            extra_body = {k: v for k, v in target.params.items() if k != param_name}
            findings.extend(agent.scan_url(
                url        = target.url,
                param_name = param_name,
                method     = target.method,
                param_type = "body",
                extra_body = extra_body,
                baseline_value = target.params.get(param_name, "1"),
                payloads   = payloads,
            ))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# TARGETS → SCAN REPORT
# ─────────────────────────────────────────────────────────────────────────────
def scan_targets(targets: List[ParamTarget],
                 payloads: Optional[List[Payload]] = None,
                 target_label: str = "") -> ScanReport:
    if not targets:
        logger.error("No injectable targets to scan.")
    agent = SQLSlayer()
    scan_start = datetime.datetime.utcnow().isoformat()

    endpoint_reports: List[EndpointReport] = []
    total_probes = 0

    for i, target in enumerate(targets, 1):
        logger.section(f"[{i}/{len(targets)}] {target.method} {target.url}  "
                       f"params={list(target.params)}")
        findings = scan_target(agent, target, payloads)
        total_probes += len(findings)
        er = EndpointReport(
            endpoint     = target.url,
            method       = target.method.upper(),
            total_probes = len(findings),
            findings     = findings,
        )
        endpoint_reports.append(er)
        if er.vulnerable_count:
            logger.critical(f"  → {er.vulnerable_count} finding(s) "
                            f"[{er.max_risk.value}, CVSS {er.max_cvss}]")
        else:
            logger.success("  → no vulnerabilities detected")

    scan_end = datetime.datetime.utcnow().isoformat()
    scan = ScanReport(
        target_url           = target_label or (targets[0].url if targets else "n/a"),
        scan_start           = scan_start,
        scan_end             = scan_end,
        endpoint_reports     = endpoint_reports,
        total_payloads_fired = total_probes,
        llm_provider         = f"{CONFIG.llm.provider}/{CONFIG.llm.active_model}",
    )
    _finalise(scan)
    return scan


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC ENTRY POINTS — THREE INPUT MODES
# ─────────────────────────────────────────────────────────────────────────────
def scan_single_url(url: str, payloads: Optional[List[Payload]] = None) -> ScanReport:
    logger.banner(f"SQLSlayer SCAN — single URL")
    targets = targets_from_urls([url], source="url")
    return scan_targets(targets, payloads, target_label=url)


def scan_url_file(path: str, payloads: Optional[List[Payload]] = None) -> ScanReport:
    logger.banner(f"SQLSlayer SCAN — URL file: {path}")
    urls = _read_url_file(path)
    logger.info(f"Loaded {len(urls)} URL(s) from {path}")
    targets = targets_from_urls(urls, source="file")
    return scan_targets(targets, payloads, target_label=path)


def scan_domain(domain: str, payloads: Optional[List[Payload]] = None) -> ScanReport:
    logger.banner(f"SQLSlayer SCAN — domain: {domain}")
    targets = recon_domain(domain)
    return scan_targets(targets, payloads, target_label=domain)


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _read_url_file(path: str) -> List[str]:
    urls = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    return urls


def _finalise(scan: ScanReport) -> None:
    logger.banner("SCAN SUMMARY")
    logger.info(f"Target              : {scan.target_url}")
    logger.info(f"Endpoints tested    : {len(scan.endpoint_reports)}")
    logger.info(f"Total probes fired  : {scan.total_payloads_fired}")
    logger.info(f"Vulnerabilities     : {scan.total_vulnerabilities}")
    logger.info(f"Critical findings   : {scan.critical_count}")
    logger.info(f"Overall risk        : {scan.overall_risk.value}")

    if CONFIG.agent.save_report and scan.endpoint_reports:
        report_dir = CONFIG.agent.report_dir
        json_path = generate_json_report(scan, report_dir)
        html_path = generate_html_report(scan, report_dir)
        md_path   = generate_markdown_report(scan, report_dir)
        logger.success(f"JSON report     -> {json_path}")
        logger.success(f"HTML report     -> {html_path}")
        logger.success(f"Markdown report -> {md_path}")
