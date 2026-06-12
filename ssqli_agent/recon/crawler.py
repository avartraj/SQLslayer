"""
recon/crawler.py — Lightweight same-scope link & form crawler
SQLSlayer

Fetches HTML pages starting from a base URL, extracts links (href/src/action)
and HTML forms, and follows in-scope links up to a configured depth. Pure
stdlib + regex parsing — no external HTML library required.
"""
import re
import urllib.parse
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from config import CONFIG
from utils.http_client import http_request
from utils.logger import logger


# ── HTML extraction regexes ──────────────────────────────────────────────────
_LINK_RE  = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#]+)["']""", re.IGNORECASE)
# Capture the opening-tag attributes (group 1) AND the form body (group 2) so
# method/action (which live on the <form> tag) and inputs (in the body) are both
# available to the parser.
_FORM_RE  = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_ACTION_RE = re.compile(r"""\baction\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_METHOD_RE = re.compile(r"""\bmethod\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_INPUT_RE = re.compile(
    r"""<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["']([^"']+)["'][^>]*>""",
    re.IGNORECASE,
)
_VALUE_RE = re.compile(r"""\bvalue\s*=\s*["']([^"']*)["']""", re.IGNORECASE)


@dataclass
class Form:
    action: str
    method: str
    fields: Dict[str, str] = field(default_factory=dict)


@dataclass
class CrawlResult:
    urls:  Set[str] = field(default_factory=set)   # all in-scope URLs seen
    forms: List[Form] = field(default_factory=list)


def _same_scope(url: str, root_netloc: str) -> bool:
    netloc = urllib.parse.urlsplit(url).netloc.lower()
    if not netloc:
        return True  # relative URL — same scope by definition
    # Treat sub-paths of the same registrable host as in-scope.
    return netloc == root_netloc or netloc.endswith("." + root_netloc)


def _extract_forms(html: str, page_url: str) -> List[Form]:
    forms: List[Form] = []
    for attrs, body in _FORM_RE.findall(html):
        # method/action are attributes of the <form> tag (group 1); input names
        # live in the form body (group 2).
        m_action = _ACTION_RE.search(attrs)
        m_method = _METHOD_RE.search(attrs)
        action = m_action.group(1) if m_action else page_url
        method = (m_method.group(1) if m_method else "GET").upper()
        fields: Dict[str, str] = {}
        for name in _INPUT_RE.findall(body):
            fields[name] = "test"
        if fields:
            forms.append(Form(
                action=urllib.parse.urljoin(page_url, action),
                method=method,
                fields=fields,
            ))
    return forms


def _extract_links(html: str, page_url: str) -> Set[str]:
    links: Set[str] = set()
    for raw in _LINK_RE.findall(html):
        if raw.lower().startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue
        absolute = urllib.parse.urljoin(page_url, raw)
        scheme = urllib.parse.urlsplit(absolute).scheme
        if scheme in ("http", "https"):
            links.add(absolute)
    return links


def crawl(base_url: str) -> CrawlResult:
    """Breadth-first crawl from base_url, honouring CONFIG.recon limits."""
    depth_limit = CONFIG.recon.crawl_depth
    max_pages   = CONFIG.recon.crawl_max_pages
    same_only   = CONFIG.recon.same_domain_only
    timeout     = CONFIG.recon.liveness_timeout

    root_netloc = urllib.parse.urlsplit(base_url).netloc.lower()
    result = CrawlResult()
    visited: Set[str] = set()
    queue: deque[Tuple[str, int]] = deque([(base_url, 0)])

    while queue and len(visited) < max_pages:
        url, depth = queue.popleft()
        norm = url.split("#")[0]
        if norm in visited:
            continue
        visited.add(norm)

        resp = http_request(norm, method="GET", timeout=timeout)
        result.urls.add(norm)
        if resp.status_code == 0 or not resp.body:
            continue

        # Only parse HTML-ish bodies.
        body = resp.body
        forms = _extract_forms(body, norm)
        result.forms.extend(forms)

        links = _extract_links(body, norm)
        for link in links:
            if same_only and not _same_scope(link, root_netloc):
                continue
            result.urls.add(link)
            if depth < depth_limit and link.split("#")[0] not in visited:
                queue.append((link, depth + 1))

    logger.info(f"  crawled {len(visited)} page(s) on {root_netloc} → "
                f"{len(result.urls)} URLs, {len(result.forms)} form(s)")
    return result
