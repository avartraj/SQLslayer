# SQLSlayer

An agentic SQL Injection detection tool for REST APIs and web applications.
It fires a comprehensive payload library at target parameters, applies static
heuristics + an LLM analysis pass (Groq or Anthropic) to confirm findings, and
produces CVSS-scored HTML/JSON reports.

> For **authorised** security testing only. Only scan systems you own or have
> explicit written permission to assess.

## Quick start
```powershell
# 1. Clone the tool
git clone https://github.com/avartraj/SQLslayer.git
cd SQLslayer

# 2. Install dependencies (Python 3.10+)
pip install -r ssqli_agent/requirements.txt

# 3. (Optional) add an LLM key for the AI confirmation pass — works without one too
copy ssqli_agent\.env.example ssqli_agent\.env
#    then edit ssqli_agent\.env and set GROQ_API_KEY=...

# 4. Run your first scan
python ssqli_agent/main.py --url "https://your-target.test/item?id=1"
```
No API key? The scan still runs in **static-only** mode (heuristics, no LLM pass).
Want a safe practice target? See [Vulnerable demo target](#vulnerable-demo-target).

## Architecture
The scanner is fully decoupled from anything it scans. The vulnerable demo API
lives in a **separate repository** (see [Vulnerable demo target](#vulnerable-demo-target)).
```
ssqli_agent/                    # THE TOOL
├── agent/
│   ├── sqli_agent.py          # Core detection agent (Groq / Anthropic LLM)
│   ├── payload_engine.py      # SQLi payload library (50+ vectors, 10 categories)
│   └── vulnerability_model.py # Risk scoring, CVSS & CVE mapping, report models
├── recon/                     # Domain → injectable-target discovery pipeline
│   ├── subdomain_enum.py      # crt.sh CT logs + DNS brute-force
│   ├── liveness.py            # Parallel HTTP/HTTPS liveness probing
│   ├── crawler.py             # Same-scope link & form crawler
│   ├── param_discovery.py     # URLs/forms → injectable ParamTargets
│   ├── param_target.py        # ParamTarget model + de-duplication
│   └── recon_orchestrator.py  # Full domain recon pipeline
├── utils/
│   ├── http_client.py         # HTTP request wrapper with timing
│   ├── logger.py              # Structured coloured logging
│   ├── reporter.py            # HTML + JSON report generator
│   └── bughunter_report.py    # AI-written bug-bounty-style Markdown report
├── reports/                   # Auto-generated scan reports (json/html/md)
├── config.py                  # Configuration + .env loader
├── scanner.py                 # Unified scan orchestrator (url/file/domain modes)
└── main.py                    # CLI entry point
```

## Setup
```powershell
pip install -r ssqli_agent/requirements.txt

# Configure the LLM provider/key (Groq by default):
copy ssqli_agent\.env.example ssqli_agent\.env
#   then edit ssqli_agent\.env and set GROQ_API_KEY=...
```
The agent runs **without** an API key too — it falls back to static heuristic
detection only and skips the LLM confirmation pass.

### LLM providers (cloud & local)
SQLSlayer supports multiple providers, configured in one place —
[ssqli_agent/agent/llm_providers.py](ssqli_agent/agent/llm_providers.py) (the
registry / "hook"). Edit that file to add a provider or change a default model.

```powershell
python ssqli_agent/main.py --list-models                         # show all providers + models
python ssqli_agent/main.py --url "..." --provider openai --model gpt-4o
python ssqli_agent/main.py --url "..." --provider anthropic
python ssqli_agent/main.py --url "..." --local --model llama3.1  # local Ollama, no API key
python ssqli_agent/main.py --url "..." --provider custom --base-url http://host:8000/v1/chat/completions
```
- **Cloud** (need a key): `groq`, `anthropic`, `openai`, `openrouter`, `together`.
- **Local** (no key): `ollama`, `lmstudio`, `llamacpp`, or any OpenAI-compatible
  server via `--base-url`.
- Override anywhere via `.env`: `LLM_PROVIDER`, `LLM_MODEL`, `LLM_BASE_URL`.

At startup the agent runs a **one-time reachability check**: if the chosen model
has no key (cloud) or its endpoint is down (local), it prints a single notice and
continues in **static-only** mode — no per-request errors.

## Usage — three input modes

### 1. Single URL with parameters
```powershell
python ssqli_agent/main.py --url "https://demo.test/item?id=1&cat=books"
```
Every query parameter in the URL is probed independently.

### 2. A file containing many URLs
```powershell
python ssqli_agent/main.py --file targets.txt
```
`targets.txt` holds one URL per line (blank lines and `#` comments ignored):
```
https://demo.test/item?id=1
https://demo.test/search?q=phone&sort=price
```

### 3. A domain (full recon)
```powershell
python ssqli_agent/main.py --domain example.com
```
Pipeline: subdomain enumeration (crt.sh + DNS brute-force) → live-host
detection → crawl each live host → extract links & forms → discover parameters
→ run the full SQLi test suite against every discovered parameter.

### Global options
```
--provider groq|anthropic   LLM provider (default: groq)
--model    <name>           Override the model for the active provider
--no-llm                    Static heuristics only (no LLM calls)
--delay    <seconds>        Throttle: pause between every request
--exploit                   Enumerate TABLE NAMES (schema only) — prompts to authorise
--allow-destructive         Send DROP/INSERT/UPDATE payloads — DANGER, prompts to authorise
```

### Safe mode (default) — production-friendly
Scans are **read-only by default**. Destructive payloads (`DROP`, `INSERT`,
`UPDATE`, `CREATE`) and resource-heavy ones (large `randomblob`, a DoS risk) are
**not sent** — detection still covers every SQLi class via safe probes and the
true/false + time oracles. The two dangerous opt-ins (`--exploit`,
`--allow-destructive`) require an explicit `I AM AUTHORISED` confirmation (or
`--authorized` to pre-confirm). Use `--delay` to be gentle on live targets.

### Diagnostics
```powershell
python ssqli_agent/main.py --list-payloads     # payload library summary
```

## Reports
Every scan writes three reports to `ssqli_agent/reports/`, all in a formal
**penetration-test format**, and each finding is labelled with its exact **SQLi
type** (UNION-based, Boolean-blind, Time-based, Error-based, Stacked,
Auth-bypass, …):
- `sqli_report.json` — machine-readable findings (incl. `sqli_type`, `reported_category`, `cvss_vector`, `dbms`, `confirmation`) plus a `category_coverage` block
- `sqli_report.html` — full PT report: cover, executive summary, scope & methodology,
  findings-summary table, detailed per-finding write-ups, recommendations
- `sqli_report.md` — same PT structure, AI-written (deterministic template fallback if no LLM)

### Report structure & category coverage
Each report follows a consistent pentest layout: **1.** Executive Summary · **2.**
Scope & Methodology · **3. SQLi Category Coverage** · **4.** Summary of Findings ·
**5.** Detailed Findings · **6.** Recommendations.

The **Category Coverage** matrix is the at-a-glance answer to *what was checked and
where it was found*. For every SQLi class it shows whether it was **tested**,
whether it was **confirmed vulnerable**, the **severity / max CVSS**, and the exact
**endpoint(s) affected**:

| SQLi Category | Status | Probes | Severity | Max CVSS | Endpoint(s) affected |
| --- | --- | --- | --- | --- | --- |
| In-band SQLi — UNION-based | **VULNERABLE** | 18 | CRITICAL | 9.0 | `GET /api/users`, `POST /api/reports` |
| Blind SQLi — Time-based | **VULNERABLE** | 6 | HIGH | 8.6 | `GET /api/categories` |
| Stacked-queries SQLi | not tested | 0 | — | — | — |

> Each finding's reported **SQLi type** reflects the class actually *demonstrated*,
> not just the payload sent — e.g. a time-based payload that only triggers a DB
> error is reported as **error-based**. *Not tested* usually means that class's
> payloads were withheld (destructive stacked queries are skipped in read-only
> safe mode; enable with `--allow-destructive` only when authorised).

## Vulnerable demo target
A deliberately-vulnerable practice API ("VulnShop") lives in a **separate repo**:
**https://github.com/avartraj/vulnshop-SQli**. Clone it locally and point the
scanner at it:
```powershell
git clone https://github.com/avartraj/vulnshop-SQli.git vulnerable_target
python vulnerable_target/app.py                                  # starts http://127.0.0.1:5050
python ssqli_agent/main.py --url "http://127.0.0.1:5050/api/users?id=1"
```
> ⚠️ VulnShop is intentionally insecure — run it on localhost only, never deploy it.

## Detection methods
For **every** probe, SQLSlayer evaluates **all** detection vectors (no early exit)
and records every signal that fired. Signals are tiered for precision so only
**true positives** are reported:
- **Strong** (flag on their own): leaked DB error, reflected UNION/schema/version
  data, a tautology returning more rows, a reliable time delay.
- **Weak** (status-only / length-only / bare HTTP 500): never flag alone — an
  empty result set or benign error can cause them — they're left for corroboration.
- **Boolean-blind** uses a rigorous **true/false oracle**: it sends a TRUE and a
  FALSE condition and only flags when the response *tracks* the condition (TRUE
  matches the baseline, FALSE diverges). A non-injectable parameter treats both
  as literals, so it produces no false positive.
- A **confidence floor** (`min_confidence`, default 0.6) drops anything uncertain.

### Production-grade techniques (adopted from ghauri / sqlmap)
- **Injection boundary probing** — the boolean oracle tries multiple contexts
  (numeric, single-quote, double-quote, comment-terminated, parenthesised) so it
  finds the injection regardless of how the query quotes the parameter.
- **Similarity-ratio comparison** ([ssqli_agent/agent/response_compare.py](ssqli_agent/agent/response_compare.py)) —
  responses are normalised (reflected payloads stripped, volatile content like
  timestamps/tokens neutralised) and compared with a difflib ratio, with a
  page-stability check so dynamic pages don't cause false positives.
- **Confirmation re-tests** — boolean and time findings are re-fired and must hold
  again before being reported.
- **Jitter-aware time-based oracle** — calibrates normal latency over several
  requests, requires the delay to repeat, and checks a fast control so a
  generally-slow endpoint can't trigger a false positive.
- **DBMS fingerprinting** ([ssqli_agent/agent/dbms_fingerprint.py](ssqli_agent/agent/dbms_fingerprint.py)) —
  identifies the backend (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, …) from error
  signatures, tailors the time payload, and labels every finding with its DBMS.
- **Harmless exploitability confirmation** — once a parameter is confirmed
  vulnerable, the agent runs ONE safe proof-of-concept: it auto-detects the UNION
  column count, reflects a unique marker it controls (`SQLSLAYERxPoC`), and reads
  the **DBMS version** (a benign system value) — or leaks the version via a forced
  error on MySQL/MSSQL. It **never** reads application or user data. The proof
  (marker + version + PoC payload) is attached to the finding and the report.
  Toggle with `enable_confirmation` (default `True`).

### AI as final arbiter (full visibility)
After signals are collected, the AI agent reviews each probe with the **complete
picture** — every signal, the baseline-vs-payload status/timing/length/row-count,
and the raw response bodies. It can:
- **Confirm** heuristic hits and classify the exact SQLi type, impact & fix
- **Catch misses** — promote a finding the heuristics missed (recorded as
  `LLM_ANALYSIS`, tagged `[MISSED BY STATIC]`)
- **Flag false positives** (and, if `llm_authoritative` is on, suppress them)

Relevant `AgentConfig` knobs (in [ssqli_agent/config.py](ssqli_agent/config.py)):
| Flag | Default | Effect |
|------|---------|--------|
| `enable_llm_analysis` | `True` | Master switch for the AI pass |
| `llm_verify_all` | `False` | `True` → AI reviews **every** probe (max visibility/cost); `False` → only probes that produced any signal |
| `llm_authoritative` | `True` | AI verdict can **suppress** false positives and confirm misses |
| `min_confidence` | `0.6` | Findings below this confidence are dropped |
| `llm_promote_threshold` | `0.8` | Min AI confidence to promote a probe the heuristics missed |

## SQLi categories covered
In-band UNION · Boolean blind · Time-based blind · Error-based · Stacked
queries · Comment-strip auth bypass · HTTP header injection · ORDER BY
injection · Second-order (stored) · Tautology — mapped to CWE-89 /
OWASP A03:2021 Injection.
