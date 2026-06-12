"""
agent/llm_providers.py — LLM provider registry (THE HOOK)

╔══════════════════════════════════════════════════════════════════════════╗
║  THIS IS THE ONE PLACE TO UPDATE WHICH MODELS SQLSLAYER CAN USE.          ║
║  Add a provider / change a default model by editing the PROVIDERS dict.   ║
╚══════════════════════════════════════════════════════════════════════════╝

Two wire formats are supported and cover virtually every provider:
  • "anthropic" → Anthropic Messages API
  • "openai"    → OpenAI Chat Completions API — also used by Groq, OpenAI,
                  Ollama, LM Studio, llama.cpp, vLLM, OpenRouter, Together, …

Cloud providers read their key from an env var (`env_key`). Local providers
(Ollama / LM Studio / llama.cpp) need no key (`requires_key=False`).

Select a provider at runtime with `--provider <name>` (and optionally
`--model <name>` / `--base-url <url>`), or set LLM_PROVIDER / LLM_MODEL /
LLM_BASE_URL in `.env`. For any OpenAI-compatible server not listed here, use:
    --provider custom --base-url http://host:port/v1/chat/completions --model <name>
"""
from dataclasses import dataclass
from typing import Optional, Dict, List


@dataclass(frozen=True)
class Provider:
    name:          str
    api_style:     str                 # "anthropic" | "openai"
    base_url:      str                 # full chat/messages endpoint
    default_model: str
    env_key:       Optional[str] = None   # env var holding the API key (cloud)
    requires_key:  bool = True            # False for local servers
    notes:         str = ""


# ─────────────────────────────────────────────────────────────────────────────
# REGISTRY — edit here to add models/providers
# ─────────────────────────────────────────────────────────────────────────────
PROVIDERS: Dict[str, Provider] = {
    # ── Cloud (require an API key) ────────────────────────────────────────────
    "groq": Provider(
        "groq", "openai",
        "https://api.groq.com/openai/v1/chat/completions",
        "llama-3.3-70b-versatile", env_key="GROQ_API_KEY",
        notes="Fast, free tier. Also: openai/gpt-oss-120b, llama-3.1-8b-instant."),
    "anthropic": Provider(
        "anthropic", "anthropic",
        "https://api.anthropic.com/v1/messages",
        "claude-sonnet-4-20250514", env_key="ANTHROPIC_API_KEY",
        notes="Claude. Also: claude-opus-4-20250514, claude-3-5-haiku-20241022."),
    "openai": Provider(
        "openai", "openai",
        "https://api.openai.com/v1/chat/completions",
        "gpt-4o-mini", env_key="OPENAI_API_KEY",
        notes="Also: gpt-4o, o4-mini."),
    "openrouter": Provider(
        "openrouter", "openai",
        "https://openrouter.ai/api/v1/chat/completions",
        "meta-llama/llama-3.3-70b-instruct", env_key="OPENROUTER_API_KEY",
        notes="Gateway to many models."),
    "together": Provider(
        "together", "openai",
        "https://api.together.xyz/v1/chat/completions",
        "meta-llama/Llama-3.3-70B-Instruct-Turbo", env_key="TOGETHER_API_KEY"),

    # ── Local (no key needed; OpenAI-compatible servers) ──────────────────────
    "ollama": Provider(
        "ollama", "openai",
        "http://localhost:11434/v1/chat/completions",
        "llama3.1", env_key=None, requires_key=False,
        notes="Run: `ollama serve` then `ollama pull llama3.1`. Set --model to your pulled tag."),
    "lmstudio": Provider(
        "lmstudio", "openai",
        "http://localhost:1234/v1/chat/completions",
        "local-model", env_key=None, requires_key=False,
        notes="LM Studio → Local Server. --model is whatever LM Studio reports."),
    "llamacpp": Provider(
        "llamacpp", "openai",
        "http://localhost:8080/v1/chat/completions",
        "local-model", env_key=None, requires_key=False,
        notes="llama.cpp `server` / `llama-server`."),

    # ── Generic OpenAI-compatible escape hatch (set --base-url) ───────────────
    "custom": Provider(
        "custom", "openai",
        "http://localhost:8000/v1/chat/completions",
        "local-model", env_key=None, requires_key=False,
        notes="Any OpenAI-compatible server — override with --base-url / --model."),
}

# Friendly alias.
PROVIDERS["local"] = PROVIDERS["ollama"]


def get_provider(name: str) -> Provider:
    """Return the registered provider, or a generic OpenAI-compatible provider
    (no key) for an unknown name so a custom --base-url still works."""
    key = (name or "").strip().lower()
    if key in PROVIDERS:
        return PROVIDERS[key]
    return Provider(key or "custom", "openai",
                    PROVIDERS["custom"].base_url, "local-model",
                    env_key=None, requires_key=False,
                    notes="Unregistered provider — using OpenAI-compatible defaults.")


def list_providers() -> List[Provider]:
    seen, out = set(), []
    for p in PROVIDERS.values():
        if p.name not in seen:
            seen.add(p.name); out.append(p)
    return out
