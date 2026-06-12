"""
config.py — Central configuration for SQLSlayer
SQLSlayer

Configuration is layered:
  1. Dataclass defaults below
  2. Environment variable overrides (CI / .env friendly)
  3. CLI flags (applied in main.py via apply_cli_overrides)
"""
import os
from dataclasses import dataclass, field
from typing import Optional


def _load_dotenv() -> None:
    """Minimal .env loader (no external dependency).

    Reads KEY=VALUE lines from a .env file next to this module and populates
    os.environ for any key that isn't already set. Keeps secrets (API keys)
    out of source code and version control.
    """
    path = os.path.join(os.path.dirname(__file__), ".env")
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


_load_dotenv()


@dataclass
class LLMConfig:
    """LLM selection. Providers/models live in agent/llm_providers.py (the hook).

    Supports multiple cloud providers (Groq, Anthropic, OpenAI, OpenRouter, …)
    and LOCAL models (Ollama, LM Studio, llama.cpp) — anything OpenAI-compatible.
    """
    provider: str = "groq"               # name from the PROVIDERS registry
    model: Optional[str] = None          # None → the provider's default model
    base_url: Optional[str] = None       # None → the provider's default endpoint
    api_key: Optional[str] = None        # None → resolved from the provider's env var
    max_tokens: int = 2048
    temperature: float = 0.1             # Low temp for deterministic analysis

    def spec(self):
        from agent.llm_providers import get_provider
        return get_provider(self.provider)

    @property
    def active_model(self) -> str:
        return self.model or self.spec().default_model

    @property
    def endpoint(self) -> str:
        return self.base_url or self.spec().base_url

    @property
    def api_style(self) -> str:
        return self.spec().api_style

    def requires_key(self) -> bool:
        return self.spec().requires_key

    def resolve_key(self) -> Optional[str]:
        """API key for the active provider: explicit override > provider env var.
        Local providers need no key (returns None, which is fine)."""
        if self.api_key:
            return self.api_key
        env_var = self.spec().env_key
        return os.getenv(env_var) if env_var else None


@dataclass
class TargetConfig:
    """Target REST API configuration (used by the bundled vulnerable-API demo)."""
    base_url: str = "http://127.0.0.1:5050"
    request_timeout: int = 15            # seconds (must exceed time_based delay)
    time_based_threshold: float = 3.0    # seconds delta to flag time-based SQLi
    request_delay: float = 0.0           # seconds between requests (throttle; --delay)
    # Boolean-blind comparison (ghauri/sqlmap-style ratio matching):
    boolean_similarity_threshold: float = 0.95  # TRUE ~ baseline if ratio >= this
    page_stability_threshold: float = 0.98      # two baselines must match above this


@dataclass
class ReconConfig:
    """Domain reconnaissance behaviour (domain-mode scans)."""
    enable_subdomain_enum: bool = True   # query crt.sh certificate transparency
    enable_dns_bruteforce: bool = True   # try a small wordlist of common subdomains
    liveness_workers: int = 20           # parallel host-probe threads
    liveness_timeout: int = 5            # seconds per probe
    crawl_depth: int = 1                 # link-follow depth from each live host
    crawl_max_pages: int = 40            # hard cap on pages fetched per host
    crawl_workers: int = 10              # parallel page-fetch threads
    max_subdomains: int = 100            # cap probed hosts to keep runs bounded
    same_domain_only: bool = True        # only crawl links within the target scope


@dataclass
class AgentConfig:
    """Agent behaviour knobs."""
    max_retries: int = 3
    parallel_workers: int = 5
    risk_threshold: float = 7.0          # CVSS-style 0-10; flag if >= threshold
    # SAFE MODE (default): destructive (DROP/INSERT/UPDATE/CREATE) and heavy
    # (large-randomblob DoS) payloads are NOT fired. Enable only with explicit
    # authorisation via --allow-destructive. Detection still covers every class.
    allow_destructive: bool = False
    enable_llm_analysis: bool = True     # Master switch for LLM confirmation
    # When True, the AI reviews EVERY probe (max visibility, max LLM calls).
    # When False, the AI reviews every probe that produced ANY detection signal
    # (still covers all detection vectors, far cheaper).
    llm_verify_all: bool = False
    # When True, the AI's verdict is authoritative — it can both confirm missed
    # findings AND suppress heuristic false positives. Default True so the report
    # contains only AI-validated true positives.
    llm_authoritative: bool = True
    # A finding is only reported if its final confidence is at least this. Filters
    # weak/uncertain signals that would otherwise show up as false positives.
    min_confidence: float = 0.6
    # AI must be at least this confident to PROMOTE a probe the heuristics missed.
    llm_promote_threshold: float = 0.8
    # After a parameter is confirmed vulnerable, attempt a HARMLESS proof-of-concept
    # extraction (reflect a unique marker we control + read the DBMS version — a
    # benign system value). Never reads application/user data.
    enable_confirmation: bool = True
    # Deeper exploitation: enumerate TABLE NAMES (schema metadata) only — never
    # row data. OFF by default; enabled only via the --exploit flag after the
    # operator confirms authorisation. Requires enable_confirmation's machinery.
    enable_exploit: bool = False
    save_report: bool = True
    # Absolute so reports land in ssqli_agent/reports/ no matter the caller's cwd.
    report_dir: str = os.path.join(os.path.dirname(__file__), "reports")


@dataclass
class AppConfig:
    llm: LLMConfig = field(default_factory=LLMConfig)
    target: TargetConfig = field(default_factory=TargetConfig)
    recon: ReconConfig = field(default_factory=ReconConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)


# ── singleton ──────────────────────────────────────────────────────────────────
CONFIG = AppConfig()

# Allow env-var overrides (CI-friendly)
if os.getenv("LLM_PROVIDER"):
    CONFIG.llm.provider = os.environ["LLM_PROVIDER"].lower()
if os.getenv("LLM_MODEL"):
    CONFIG.llm.model = os.environ["LLM_MODEL"]
if os.getenv("LLM_BASE_URL"):
    CONFIG.llm.base_url = os.environ["LLM_BASE_URL"]
if os.getenv("TARGET_URL"):
    CONFIG.target.base_url = os.environ["TARGET_URL"]
# Note: API keys are resolved lazily per-provider via LLMConfig.resolve_key().
# Setting api_key here would override provider-specific selection, so we don't.
