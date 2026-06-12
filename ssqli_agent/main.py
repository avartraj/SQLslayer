"""
main.py — SQLSlayer entry point

SQLSlayer is a standalone SQL injection detection agent. It scans real targets
you are authorised to test. (The demo vulnerable app and the test suite live in
sibling folders — ../vulnerable_target and ../tests — and are NOT part of the
tool.)

INPUT MODES
    --url   "https://site/page?id=1&q=x"   Scan a single URL's parameters
    --file  urls.txt                        Scan every URL listed in a file
    --domain example.com                    Recon a domain (subdomain enum →
                                            live-host detection → crawl →
                                            parameter discovery) then scan

DIAGNOSTICS
    --list-payloads             Print the payload library summary

GLOBAL OPTIONS
    --provider <name>           LLM provider: groq|anthropic|openai|ollama|
                                lmstudio|llamacpp|openrouter|together|custom
    --model    <model-name>     Override the model for the active provider
    --local                     Shortcut for a local Ollama model (no API key)
    --base-url <url>            Custom OpenAI-compatible endpoint (self-hosted)
    --list-models               List all configured providers / default models
    --no-llm                    Disable LLM analysis (static heuristics only)
    --delay <seconds>           Throttle: pause between every request

SAFE MODE (default)
    Scans are READ-ONLY by default: destructive (DROP/INSERT/UPDATE/CREATE) and
    resource-heavy (large randomblob) payloads are NOT sent. Detection still
    covers every SQLi class. The two dangerous opt-ins below prompt for
    authorisation (or pass --authorized to pre-confirm):
    --exploit                   Enumerate TABLE NAMES (schema only, no row data)
    --allow-destructive         Send data/schema-mutating payloads (DANGER)

EXAMPLES
    python main.py --url "https://demo.test/item?id=1" --provider groq
    python main.py --file targets.txt
    python main.py --domain example.com
"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from config import CONFIG
from colorama import Fore, Style, init
init(autoreset=True)

G  = Fore.GREEN + Style.BRIGHT
GD = Fore.GREEN
C  = Fore.CYAN + Style.BRIGHT
Y  = Fore.YELLOW + Style.BRIGHT
R  = Fore.RED + Style.BRIGHT
DIM = Style.DIM
RST = Style.RESET_ALL

SLAYER_ART = r"""
  ███████╗ ██████╗ ██╗     ███████╗██╗      █████╗ ██╗   ██╗███████╗██████╗
  ██╔════╝██╔═══██╗██║     ██╔════╝██║     ██╔══██╗╚██╗ ██╔╝██╔════╝██╔══██╗
  ███████╗██║   ██║██║     ███████╗██║     ███████║ ╚████╔╝ █████╗  ██████╔╝
  ╚════██║██║▄▄ ██║██║     ╚════██║██║     ██╔══██║  ╚██╔╝  ██╔══╝  ██╔══██╗
  ███████║╚██████╔╝███████╗███████║███████╗██║  ██║   ██║   ███████╗██║  ██║
  ╚══════╝ ╚══▀▀═╝ ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
"""


def print_banner():
    print(G + SLAYER_ART + RST)
    print(f"  {GD}>> agentic SQL injection detection // REST APIs & web apps{RST}")
    print(f"  {DIM}>> v1.0  ·  for authorised security testing only{RST}\n")


def print_status(mode: str):
    key_ok = bool(CONFIG.llm.resolve_key())
    local  = not CONFIG.llm.requires_key()
    avail  = local or key_ok
    llm_on = CONFIG.agent.enable_llm_analysis and avail
    def line(k, v, ok=True):
        mark = f"{G}●{RST}" if ok else f"{R}○{RST}"
        print(f"  {mark} {DIM}{k:<16}{RST}{GD}{v}{RST}")
    print(f"{C}┌──[ SESSION ]{'─' * 58}{RST}")
    line("provider", CONFIG.llm.provider)
    line("model", CONFIG.llm.active_model)
    if local:
        line("endpoint", CONFIG.llm.endpoint)
        line("auth", "local model (no key)")
    else:
        line("api key", "loaded" if key_ok else "MISSING (static-only mode)", key_ok)
    line("llm analysis", "ON" if llm_on else "OFF", llm_on)
    safe = not CONFIG.agent.allow_destructive
    line("safety", "SAFE (read-only)" if safe else "AGGRESSIVE (destructive!)", safe)
    if CONFIG.target.request_delay:
        line("throttle", f"{CONFIG.target.request_delay}s / request")
    line("mode", mode)
    print(f"{C}└{'─' * 70}{RST}\n")


def print_options():
    rows = [
        ("--url <URL>",          "Scan a single URL's parameters"),
        ("--file <FILE>",        "Scan every URL listed in a file (one per line)"),
        ("--domain <DOMAIN>",    "Recon a domain → subdomains → live → crawl → scan"),
        ("--list-payloads",      "Print the payload library summary"),
        ("",                     ""),
        ("--provider <NAME>",    "LLM provider: groq|anthropic|openai|ollama|lmstudio|… (default: groq)"),
        ("--model <NAME>",       "Override the model for the active provider"),
        ("--local",              "Shortcut: use a local Ollama model (no API key)"),
        ("--base-url <URL>",     "Custom OpenAI-compatible endpoint (local/self-hosted)"),
        ("--list-models",        "List all configured providers and their default models"),
        ("--no-llm",             "Static heuristics only (skip LLM analysis)"),
        ("--delay <SECONDS>",    "Throttle: wait between every request (be gentle on targets)"),
        ("--exploit",            "Enumerate TABLE NAMES on confirmed injections (asks to authorise)"),
        ("--allow-destructive",  "Enable DROP/INSERT/UPDATE payloads — DANGER (asks to authorise)"),
    ]
    print(f"{C}┌──[ OPTIONS ]{'─' * 58}{RST}")
    for flag, desc in rows:
        if not flag:
            print(f"{C}│{RST}")
            continue
        print(f"{C}│{RST}  {Y}{flag:<28}{RST}{DIM}{desc}{RST}")
    print(f"{C}└{'─' * 70}{RST}")
    print(f"\n  {GD}examples:{RST}")
    print(f"    {DIM}python main.py --url \"https://demo.test/item?id=1\"{RST}")
    print(f"    {DIM}python main.py --file targets.txt --provider groq{RST}")
    print(f"    {DIM}python main.py --domain example.com{RST}\n")


def _flag_value(args, flag):
    """Return the value following ``flag`` or None."""
    if flag in args:
        idx = args.index(flag) + 1
        if idx < len(args):
            return args[idx]
        print(f"ERROR: {flag} requires a value")
        sys.exit(1)
    return None


def apply_global_options(args):
    """Apply --provider / --model / --no-llm / --delay before anything else runs."""
    provider = _flag_value(args, "--provider")
    if provider:
        CONFIG.llm.provider = provider.lower()
    if "--local" in args:                 # shortcut for a local Ollama model
        CONFIG.llm.provider = "ollama"
    model = _flag_value(args, "--model")
    if model:
        CONFIG.llm.model = model
    base_url = _flag_value(args, "--base-url")
    if base_url:
        CONFIG.llm.base_url = base_url
    if "--no-llm" in args:
        CONFIG.agent.enable_llm_analysis = False
    delay = _flag_value(args, "--delay")
    if delay:
        try:
            from utils import http_client
            CONFIG.target.request_delay = float(delay)
            http_client.REQUEST_DELAY = float(delay)
        except ValueError:
            print(f"ERROR: --delay needs a number of seconds (got {delay!r})")
            sys.exit(1)


def authorize_active_actions(args) -> None:
    """Gate the dangerous opt-ins (--exploit, --allow-destructive) behind an
    explicit authorisation prompt.

      --exploit            enumerates TABLE NAMES (schema metadata, no row data)
      --allow-destructive  fires data/schema-mutating payloads (DROP/INSERT/...)

    Both require confirmation. Pass --authorized to pre-confirm non-interactively.
    """
    wants_exploit = "--exploit" in args
    wants_destructive = "--allow-destructive" in args
    if not (wants_exploit or wants_destructive):
        return

    actions = []
    if wants_exploit:
        actions.append("enumerate database TABLE NAMES (schema only, no row data)")
    if wants_destructive:
        actions.append("fire DESTRUCTIVE payloads (DROP/INSERT/UPDATE/CREATE) that "
                       "can MODIFY OR DESTROY data")
    print(f"{R}╔{'═'*72}╗")
    print(f"║  AUTHORISATION REQUIRED — you requested:{' '*31}║")
    for a in actions:
        print(f"║   • {a[:66]:<66}║")
    print(f"║  Only proceed on systems you OWN or are explicitly authorised to test. ║")
    print(f"║  Unauthorised access is illegal. Prefer a STAGING environment.         ║")
    print(f"╚{'═'*72}╝{RST}")

    if "--authorized" in args:
        ans = "I AM AUTHORISED"
        print(f"{Y}  --authorized supplied — proceeding.{RST}\n")
    else:
        try:
            ans = input(f"{Y}  Type 'I AM AUTHORISED' to continue (anything else aborts): {RST}")
        except (EOFError, KeyboardInterrupt):
            ans = ""
        print()

    if ans.strip().upper() == "I AM AUTHORISED":
        if wants_exploit:
            CONFIG.agent.enable_exploit = True
        if wants_destructive:
            CONFIG.agent.allow_destructive = True
    else:
        print(f"{R}  Authorisation not confirmed — staying in SAFE mode (read-only "
              f"detection still runs).{RST}\n")


def preflight_llm():
    """Probe the configured LLM once; if unreachable, disable the LLM pass for
    the whole run (so we don't warn on every probe) and fall back to static."""
    if not CONFIG.agent.enable_llm_analysis:
        return
    from agent.sqli_agent import LLMClient
    ok, reason = LLMClient().preflight()
    if not ok:
        CONFIG.agent.enable_llm_analysis = False
        print(f"  {Y}[llm]{RST} {DIM}{reason} — continuing in static-only detection mode.{RST}")


def main():
    args = sys.argv[1:]
    print_banner()
    apply_global_options(args)
    authorize_active_actions(args)
    if any(f in args for f in ("--url", "--file", "--domain")):
        preflight_llm()

    # ── Provider / model registry ─────────────────────────────────────────────
    if "--list-models" in args:
        from agent.llm_providers import list_providers
        print(f"{C}┌──[ LLM PROVIDERS ]{'─' * 52}{RST}")
        print(f"{C}│{RST}  {DIM}edit ssqli_agent/agent/llm_providers.py to add/change models{RST}")
        print(f"{C}│{RST}")
        for p in list_providers():
            kind = "local" if not p.requires_key else (p.env_key or "key")
            print(f"{C}│{RST}  {Y}{p.name:<11}{RST}{GD}{p.default_model:<34}{RST}"
                  f"{DIM}[{p.api_style}/{kind}]{RST}")
        print(f"{C}└{'─' * 70}{RST}")
        print(f"\n  {GD}examples:{RST}")
        print(f"    {DIM}python main.py --url \"...\" --provider openai --model gpt-4o{RST}")
        print(f"    {DIM}python main.py --url \"...\" --local --model llama3.1{RST}")
        print(f"    {DIM}python main.py --url \"...\" --provider custom --base-url http://host:8000/v1/chat/completions{RST}\n")
        return

    # ── Payload summary ───────────────────────────────────────────────────────
    if "--list-payloads" in args:
        from agent.payload_engine import PAYLOADS, payload_summary
        print(f"{C}┌──[ PAYLOAD LIBRARY ]{'─' * 50}{RST}")
        print(f"{C}│{RST}  {GD}{len(PAYLOADS)} payloads across all SQLi categories{RST}")
        print(f"{C}│{RST}")
        for cat, info in payload_summary().items():
            print(f"{C}│{RST}  {Y}{cat:<18}{RST}{GD}{info['count']:>3} payloads{RST}  "
                  f"{DIM}({info['critical']} critical, {info['high']} high){RST}")
        print(f"{C}└{'─' * 70}{RST}")
        return

    # ── Mode 1: single URL ────────────────────────────────────────────────────
    url = _flag_value(args, "--url")
    if url:
        print_status("single URL")
        from scanner import scan_single_url
        scan_single_url(url)
        return

    # ── Mode 2: URL file ──────────────────────────────────────────────────────
    url_file = _flag_value(args, "--file")
    if url_file:
        print_status(f"URL file ({url_file})")
        from scanner import scan_url_file
        scan_url_file(url_file)
        return

    # ── Mode 3: domain recon ──────────────────────────────────────────────────
    domain = _flag_value(args, "--domain")
    if domain:
        print_status(f"domain recon ({domain})")
        from scanner import scan_domain
        scan_domain(domain)
        return

    # ── No mode selected → show options menu ──────────────────────────────────
    print_options()


if __name__ == "__main__":
    main()
