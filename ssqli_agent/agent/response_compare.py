"""
agent/response_compare.py — Response normalisation & similarity comparison

Adopted from the approach used by ghauri / sqlmap for accurate boolean-based
detection: before comparing two responses we

  1. strip reflections — remove the injected payload (and its URL-encoded forms)
     so the payload echoing back doesn't make pages look different, and
  2. neutralise volatile content — timestamps, long hex/CSRF tokens, nonces, etc.
     that change on every request,

then score similarity with difflib's ratio. A TRUE condition should yield a page
nearly identical to the baseline (ratio >= threshold); a FALSE condition should
diverge (ratio < threshold). This is far more reliable than raw length/status.
"""
import re
import difflib
import urllib.parse
from typing import Iterable

# Volatile substrings that legitimately differ between identical requests.
_VOLATILE = [
    re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}[.\d]*"),   # ISO timestamps
    re.compile(r"\b[0-9a-fA-F]{16,}\b"),                            # long hex / tokens
    re.compile(r"\b\d{10,}\b"),                                     # epoch-like numbers
    re.compile(r"(csrf|xsrf|nonce|token|sessionid|request_id)"
               r"['\"\s:=]+[^\"'&\s,}]+", re.IGNORECASE),
]


def _strip_reflections(text: str, reflections: Iterable[str]) -> str:
    for r in reflections:
        if not r:
            continue
        for variant in {r, urllib.parse.quote(r), urllib.parse.quote_plus(r)}:
            if variant:
                text = text.replace(variant, "")
    return text


def normalize(body: str, reflections: Iterable[str] = ()) -> str:
    """Return a stable, comparable form of a response body."""
    t = body or ""
    t = _strip_reflections(t, reflections)
    for rx in _VOLATILE:
        t = rx.sub("", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def ratio(a: str, b: str) -> float:
    """Similarity ratio in [0,1] between two (already normalised) strings."""
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def page_is_stable(body1: str, body2: str, reflections: Iterable[str] = (),
                   threshold: float = 0.98) -> bool:
    """Two responses to the SAME request should be near-identical after
    normalisation. If they are not, the page is too dynamic for ratio-based
    boolean comparison and we should fall back to a structural signal."""
    return ratio(normalize(body1, reflections), normalize(body2, reflections)) >= threshold
