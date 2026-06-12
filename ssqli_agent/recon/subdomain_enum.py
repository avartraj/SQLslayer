"""
recon/subdomain_enum.py — Subdomain enumeration for domain-mode scans
SQLSlayer

Two passive/light-active strategies, dependency-free (stdlib only):
  1. Certificate Transparency logs via crt.sh (passive, no API key)
  2. DNS brute-force against a small wordlist of common subdomains

Both are best-effort: failures are swallowed so a partial result is still
returned. This is intended for AUTHORISED testing of domains you own or have
explicit permission to assess.
"""
import json
import socket
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set

from config import CONFIG
from utils.logger import logger


# Common subdomain labels for the light DNS brute-force pass.
COMMON_SUBDOMAINS = [
    "www", "api", "app", "dev", "staging", "stage", "test", "uat", "qa",
    "admin", "portal", "secure", "login", "auth", "mail", "webmail", "smtp",
    "blog", "shop", "store", "cdn", "static", "assets", "img", "images",
    "beta", "demo", "internal", "intranet", "vpn", "gateway", "gw", "proxy",
    "dashboard", "console", "account", "accounts", "user", "users", "mobile",
    "m", "ws", "service", "services", "data", "db", "sql", "search", "files",
]


def _normalise(name: str, domain: str) -> str:
    name = name.strip().lower().lstrip("*.")
    return name


def enumerate_from_crtsh(domain: str, timeout: int = 15) -> Set[str]:
    """Query crt.sh certificate transparency logs for subdomains."""
    found: Set[str] = set()
    url = f"https://crt.sh/?q={urllib.parse.quote('%.' + domain)}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SQLSlayer/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        records = json.loads(raw)
        for rec in records:
            # name_value can contain multiple newline-separated names
            for name in str(rec.get("name_value", "")).splitlines():
                name = _normalise(name, domain)
                if name.endswith(domain) and " " not in name:
                    found.add(name)
        logger.info(f"crt.sh returned {len(found)} unique names for {domain}")
    except Exception as e:
        logger.warning(f"crt.sh lookup failed for {domain}: {e}")
    return found


def _resolves(host: str) -> bool:
    try:
        socket.gethostbyname(host)
        return True
    except Exception:
        return False


def enumerate_from_dns(domain: str, workers: int = 20) -> Set[str]:
    """Brute-force common subdomain labels via DNS resolution."""
    candidates = [f"{label}.{domain}" for label in COMMON_SUBDOMAINS]
    found: Set[str] = set()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_resolves, host): host for host in candidates}
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                if fut.result():
                    found.add(host)
            except Exception:
                pass
    logger.info(f"DNS brute-force resolved {len(found)} subdomains for {domain}")
    return found


def enumerate_subdomains(domain: str) -> List[str]:
    """Enumerate subdomains using all enabled strategies.

    Always includes the apex domain and www.<domain>. Returns a sorted,
    de-duplicated list capped at CONFIG.recon.max_subdomains.
    """
    domain = domain.strip().lower()
    # Strip scheme/path if a URL was passed in by mistake.
    if "://" in domain:
        domain = urllib.parse.urlsplit(domain).netloc or domain
    domain = domain.split("/")[0]

    results: Set[str] = {domain, f"www.{domain}"}

    if CONFIG.recon.enable_subdomain_enum:
        logger.scan(f"Enumerating subdomains for {domain} via crt.sh …")
        results |= enumerate_from_crtsh(domain)

    if CONFIG.recon.enable_dns_bruteforce:
        logger.scan(f"DNS brute-forcing common subdomains for {domain} …")
        results |= enumerate_from_dns(domain, workers=CONFIG.recon.liveness_workers)

    ordered = sorted(results)
    capped = ordered[: CONFIG.recon.max_subdomains]
    if len(ordered) > len(capped):
        logger.warning(
            f"Subdomain list capped at {CONFIG.recon.max_subdomains} "
            f"(found {len(ordered)}). Raise CONFIG.recon.max_subdomains to scan more."
        )
    logger.success(f"Total candidate subdomains: {len(capped)}")
    return capped
