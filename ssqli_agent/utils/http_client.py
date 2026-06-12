"""
utils/http_client.py — HTTP request wrapper with timing and error handling
SQLSlayer
"""
import urllib.request
import urllib.parse
import urllib.error
import json
import time
from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class HTTPResponse:
    status_code: int
    body: str
    response_time_ms: float
    headers: Dict[str, str]
    error: Optional[str] = None

    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except Exception:
            return {}

    def contains(self, text: str) -> bool:
        return text.lower() in self.body.lower()


def _build_request(url: str, method: str, data: Optional[dict],
                   headers: Dict[str, str]) -> urllib.request.Request:
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")

    req = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
    return req


# Global request throttle (seconds). Set by main.py from --delay / config so ALL
# traffic — scanner probes, oracles, and recon — is rate-limited uniformly.
REQUEST_DELAY = 0.0


def http_request(
    url: str,
    method: str = "GET",
    params: Optional[Dict[str, str]] = None,
    json_body: Optional[dict] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 10,
) -> HTTPResponse:
    """Synchronous HTTP request with timing. Returns HTTPResponse always (no raise)."""
    if REQUEST_DELAY:
        time.sleep(REQUEST_DELAY)
    headers = headers or {"User-Agent": "SQLSlayer/1.0"}

    if params:
        qs = urllib.parse.urlencode(params)
        url = f"{url}?{qs}"

    req = _build_request(url, method, json_body, headers)

    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = (time.perf_counter() - start) * 1000
            body = resp.read().decode("utf-8", errors="replace")
            resp_headers = dict(resp.headers)
            return HTTPResponse(
                status_code=resp.status,
                body=body,
                response_time_ms=elapsed,
                headers=resp_headers,
            )
    except urllib.error.HTTPError as e:
        elapsed = (time.perf_counter() - start) * 1000
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return HTTPResponse(
            status_code=e.code,
            body=body,
            response_time_ms=elapsed,
            headers={},
            error=str(e),
        )
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return HTTPResponse(
            status_code=0,
            body="",
            response_time_ms=elapsed,
            headers={},
            error=str(e),
        )
