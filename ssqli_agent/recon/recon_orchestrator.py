"""
recon/recon_orchestrator.py — Full domain recon pipeline

Pipeline (domain mode):
    domain
      → enumerate_subdomains()      (crt.sh + DNS brute-force)
      → filter_live_hosts()         (HTTP/HTTPS liveness probe)
      → crawl() each live host      (link + form extraction)
      → build_targets()             (parameter discovery)
      → deduped List[ParamTarget]
"""
from typing import List

from recon.subdomain_enum import enumerate_subdomains
from recon.liveness import filter_live_hosts
from recon.crawler import crawl, CrawlResult
from recon.param_discovery import build_targets
from recon.param_target import ParamTarget, dedupe_targets
from utils.logger import logger


def recon_domain(domain: str) -> List[ParamTarget]:
    """Run the full recon pipeline for a domain and return injectable targets."""
    logger.banner(f"RECON — {domain}")

    # 1. Subdomain enumeration
    subdomains = enumerate_subdomains(domain)
    if not subdomains:
        logger.error(f"No subdomains discovered for {domain}")
        return []

    # 2. Liveness filtering
    live_hosts = filter_live_hosts(subdomains)
    if not live_hosts:
        logger.error("No live hosts found — nothing to crawl")
        return []

    # 3. Crawl each live host & collect URLs/forms
    merged = CrawlResult()
    for host in live_hosts:
        logger.scan(f"Crawling {host.base_url} …")
        result = crawl(host.base_url)
        merged.urls |= result.urls
        merged.forms.extend(result.forms)

    # 4. Parameter discovery
    targets = build_targets(merged)

    logger.success(
        f"Recon complete: {len(live_hosts)} live host(s), "
        f"{len(merged.urls)} URL(s), {len(targets)} injectable target(s)"
    )
    return dedupe_targets(targets)
