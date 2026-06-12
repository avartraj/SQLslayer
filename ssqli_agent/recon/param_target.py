"""
recon/param_target.py — Shared model for an injectable parameter target
SQLSlayer
"""
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class ParamTarget:
    """A single URL + method carrying one or more injectable parameters.

    ``param_type`` mirrors SQLSlayer's notion:
      query  — GET-style query-string parameters
      body   — form/JSON body parameters (POST/PUT)
    """
    url:        str
    method:     str
    params:     Dict[str, str]          # name -> sample/baseline value
    param_type: str = "query"           # query | body
    source:     str = "input"           # where this target was discovered

    @property
    def signature(self) -> str:
        """Stable key for de-duplication: method + url-path + sorted param names."""
        names = ",".join(sorted(self.params.keys()))
        return f"{self.method.upper()} {self.url.split('?')[0]} [{names}]"

    def __repr__(self) -> str:
        return f"<ParamTarget {self.method} {self.url} params={list(self.params)}>"


def dedupe_targets(targets: List[ParamTarget]) -> List[ParamTarget]:
    """Collapse targets that share method + path + parameter-name set."""
    seen = {}
    for t in targets:
        if t.signature not in seen:
            seen[t.signature] = t
    return list(seen.values())
