"""
recon/liveness.py — Detect which hosts are live over HTTP/HTTPS
SQLSlayer

For each candidate host we probe https:// first, then http://, and return the
first scheme that responds. Probing is parallelised across a thread pool.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Optional

from config import CONFIG
from utils.http_client import http_request
from utils.logger import logger


@dataclass
class LiveHost:
    host:        str          # bare host, e.g. api.example.com
    base_url:    str          # responding base URL, e.g. https://api.example.com
    status_code: int
    scheme:      str


def _probe_one(host: str, timeout: int) -> Optional[LiveHost]:
    for scheme in ("https", "http"):
        base = f"{scheme}://{host}"
        resp = http_request(base, method="GET", timeout=timeout)
        # status_code 0 means the request never connected; anything else is "alive".
        if resp.status_code and resp.status_code != 0:
            return LiveHost(host=host, base_url=base,
                            status_code=resp.status_code, scheme=scheme)
    return None


def filter_live_hosts(hosts: List[str]) -> List[LiveHost]:
    """Return the subset of hosts that respond, with their working base URL."""
    live: List[LiveHost] = []
    timeout = CONFIG.recon.liveness_timeout
    workers = CONFIG.recon.liveness_workers

    logger.scan(f"Probing {len(hosts)} hosts for liveness "
                f"({workers} workers, {timeout}s timeout) …")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_probe_one, h, timeout): h for h in hosts}
        for fut in as_completed(futures):
            try:
                result = fut.result()
            except Exception:
                result = None
            if result:
                live.append(result)
                logger.info(f"  LIVE  {result.base_url} [{result.status_code}]")

    logger.success(f"{len(live)}/{len(hosts)} hosts are live")
    return live
