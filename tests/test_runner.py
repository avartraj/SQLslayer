"""
tests/test_runner.py — Demo scenario suite against the vulnerable target API

Flow:
  1. Launch vulnerable_target/app.py as a SEPARATE process (true decoupling)
  2. Wait for its health check
  3. Run all 10 SQLi scenarios through the SQLSlayer agent
  4. Aggregate into a ScanReport
  5. Generate JSON + HTML + AI bug-hunter Markdown reports
  6. Print a console summary, then tear the target down

Run:  python tests/test_runner.py            (from the repo root)
"""
import _bootstrap  # noqa: F401  (adds the tool to sys.path; exposes TARGET/ROOT)
from _bootstrap import TARGET

import sys
import os
import time
import subprocess
import datetime
import urllib.request

from config import CONFIG
from agent.sqli_agent import SQLSlayer
from agent.vulnerability_model import ScanReport, EndpointReport, RiskLevel
from test_scenarios import SCENARIOS, get_payloads_for_scenario
from utils.reporter import generate_html_report, generate_json_report
from utils.bughunter_report import generate_markdown_report
from utils.logger import logger
from colorama import Fore, Style


# ─────────────────────────────────────────────────────────────────────────────
# TARGET LIFECYCLE (separate process)
# ─────────────────────────────────────────────────────────────────────────────
def start_target_api() -> subprocess.Popen:
    """Launch the vulnerable target API as its own process."""
    app_path = os.path.join(TARGET, "app.py")
    proc = subprocess.Popen(
        [sys.executable, app_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        cwd=TARGET,
    )
    logger.info(f"Vulnerable target launched (pid {proc.pid}) from {app_path}")
    return proc


def wait_for_target(max_wait: int = 20) -> bool:
    for _ in range(max_wait):
        try:
            with urllib.request.urlopen("http://127.0.0.1:5050/health", timeout=2) as r:
                if r.status == 200:
                    logger.success("Target API is up and healthy")
                    return True
        except Exception:
            time.sleep(1)
    logger.error("Target API did not start in time")
    return False


def stop_target_api(proc: subprocess.Popen) -> None:
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logger.info("Vulnerable target stopped")


# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY TABLE
# ─────────────────────────────────────────────────────────────────────────────
RISK_COLORS_TERM = {
    "CRITICAL": Fore.RED + Style.BRIGHT, "HIGH": Fore.YELLOW + Style.BRIGHT,
    "MEDIUM": Fore.YELLOW, "LOW": Fore.GREEN, "INFO": Fore.CYAN,
}


def print_summary_table(endpoint_reports):
    reset = Style.RESET_ALL
    print(Fore.CYAN + "═" * 80 + reset)
    print(Fore.WHITE + Style.BRIGHT +
          f"{'ID':<8}{'ENDPOINT':<28}{'METHOD':<8}{'RISK':<10}{'CVSS':<6}{'FINDINGS':<10}{'PROBES'}" + reset)
    print(Fore.CYAN + "─" * 80 + reset)
    for i, er in enumerate(endpoint_reports, 1):
        rc = RISK_COLORS_TERM.get(er.max_risk.value, "")
        vuln_str = f"{er.vulnerable_count}/{er.total_probes}"
        print(f"{Fore.WHITE}{i:<8}{reset}{Fore.CYAN}{er.endpoint:<28}{reset}"
              f"{Fore.WHITE}{er.method:<8}{reset}{rc}{er.max_risk.value:<10}{reset}"
              f"{Fore.WHITE}{er.max_cvss:<6}{reset}"
              f"{(Fore.RED if er.vulnerable_count else Fore.GREEN)}{vuln_str:<10}{reset}"
              f"{Fore.WHITE}{er.total_probes}{reset}")
    print(Fore.CYAN + "═" * 80 + reset)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN RUNNER
# ─────────────────────────────────────────────────────────────────────────────
def run_all_scenarios(start_server: bool = True) -> ScanReport:
    logger.banner("SQLSlayer — Demo Scenario Suite")

    proc = None
    try:
        if start_server:
            proc = start_target_api()
            if not wait_for_target():
                sys.exit(1)

        # Per-finding LLM analysis fires one call per vulnerable probe (hundreds
        # across all scenarios). For the demo we disable it for speed — the final
        # AI bug-hunter Markdown report still makes a single LLM call to write the
        # narrative. Set SQLSLAYER_LLM_FINDINGS=1 to re-enable per-finding notes.
        if os.getenv("SQLSLAYER_LLM_FINDINGS") != "1":
            CONFIG.agent.enable_llm_analysis = False

        # VulnShop is a controlled local target that re-seeds its DB on every
        # start, so the demo opts into full coverage (incl. destructive stacked
        # payloads) to exercise ALL categories. Production scans stay SAFE.
        CONFIG.agent.allow_destructive = True

        agent = SQLSlayer()
        scan_start = datetime.datetime.utcnow().isoformat()
        endpoint_reports = []
        total_payloads = 0

        for scenario in SCENARIOS:
            logger.section(f"{scenario.scenario_id} — {scenario.name}")
            logger.info(scenario.description[:120])
            payloads = get_payloads_for_scenario(scenario)
            total_payloads += len(payloads)

            findings = agent.scan_endpoint(
                endpoint       = scenario.endpoint,
                method         = scenario.method,
                param_name     = scenario.param_name,
                param_type     = scenario.param_type,
                baseline_value = scenario.baseline_value,
                extra_body     = scenario.extra_body,
                payloads       = payloads,
            )
            er = EndpointReport(
                endpoint=scenario.endpoint, method=scenario.method.upper(),
                total_probes=len(payloads), findings=findings,
            )
            endpoint_reports.append(er)
            if er.vulnerable_count:
                logger.critical(f"{scenario.scenario_id} RESULT: {er.vulnerable_count} "
                                f"vulnerabilities [{er.max_risk.value}, CVSS {er.max_cvss}]")
            else:
                logger.success(f"{scenario.scenario_id} RESULT: No vulnerabilities detected")

        scan_end = datetime.datetime.utcnow().isoformat()
        scan = ScanReport(
            target_url=CONFIG.target.base_url, scan_start=scan_start, scan_end=scan_end,
            endpoint_reports=endpoint_reports, total_payloads_fired=total_payloads,
            llm_provider=f"{CONFIG.llm.provider}/{CONFIG.llm.active_model}",
        )

        logger.banner("SCAN SUMMARY")
        print_summary_table(endpoint_reports)
        print(f"\n  Total payloads fired : {scan.total_payloads_fired}")
        print(f"  Vulnerabilities found: {scan.total_vulnerabilities}")
        print(f"  Critical findings    : {scan.critical_count}")
        print(f"  Overall risk         : {scan.overall_risk.value}\n")

        if CONFIG.agent.save_report:
            rd = CONFIG.agent.report_dir
            logger.success(f"JSON report     -> {generate_json_report(scan, rd)}")
            logger.success(f"HTML report     -> {generate_html_report(scan, rd)}")
            logger.success(f"Markdown report -> {generate_markdown_report(scan, rd)}")

        return scan
    finally:
        stop_target_api(proc)


if __name__ == "__main__":
    run_all_scenarios()
