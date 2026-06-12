"""
recon/param_discovery.py — Turn crawled URLs & forms into injectable targets
"""
import urllib.parse
from typing import List

from recon.crawler import CrawlResult, Form
from recon.param_target import ParamTarget, dedupe_targets
from utils.logger import logger


def url_to_target(url: str, source: str = "crawl") -> ParamTarget | None:
    """Build a ParamTarget from a URL's query string, or None if it has none."""
    parsed = urllib.parse.urlsplit(url)
    query = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
    if not query:
        return None
    clean = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, "", "")
    )
    return ParamTarget(url=clean, method="GET", params=query,
                       param_type="query", source=source)


def form_to_target(form: Form) -> ParamTarget:
    """Build a ParamTarget from an HTML form."""
    method = form.method.upper()
    param_type = "body" if method in ("POST", "PUT", "PATCH") else "query"
    return ParamTarget(url=form.action, method=method, params=dict(form.fields),
                       param_type=param_type, source="form")


def build_targets(crawl: CrawlResult) -> List[ParamTarget]:
    """Collect every injectable target from a crawl result."""
    targets: List[ParamTarget] = []

    for url in crawl.urls:
        t = url_to_target(url)
        if t:
            targets.append(t)

    for form in crawl.forms:
        if form.fields:
            targets.append(form_to_target(form))

    deduped = dedupe_targets(targets)
    logger.info(f"  parameter discovery → {len(deduped)} unique injectable target(s)")
    return deduped


def targets_from_urls(urls: List[str], source: str = "input") -> List[ParamTarget]:
    """Build targets directly from a list of raw URLs (url/file modes)."""
    targets = []
    for url in urls:
        t = url_to_target(url, source=source)
        if t:
            targets.append(t)
        else:
            logger.warning(f"No parameters in URL, skipping: {url}")
    return dedupe_targets(targets)
