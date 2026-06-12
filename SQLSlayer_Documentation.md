# SQLSlayer — SQL Injection Detection Agent
### Technical Documentation & Assignment Submission

| | |
|---|---|
| **Project** | SQLSlayer — Agentic SQL Injection Detection for REST APIs |
| **Author** | Avartraj Vishwakarma |
| **Date** | 12 June 2026 |
| **Language / Runtime** | Python 3.10+ (developed on 3.12) |
| **LLM** | Multi-provider: Groq, Anthropic, OpenAI, OpenRouter, Together + **local** (Ollama, LM Studio, llama.cpp) |

---

## 1. Objective

Build an **agent that detects SQL Injection (SQLi) vulnerabilities in REST API
endpoints**, and demonstrate comprehensive testing across **all** SQLi scenarios
using an agentic Python flow.

SQLSlayer is that agent. It accepts a target (a single URL, a list of URLs, or a
whole domain), discovers injectable parameters, fires a comprehensive payload
library, fuses **static heuristics + an LLM reasoning pass** to decide what is
genuinely vulnerable, safely **confirms exploitability**, and produces
professional CVSS-scored reports (JSON, HTML, and an AI-written bug-bounty
Markdown report).

> **Proof of correctness:** to demonstrate the tool works end-to-end I also built
> a **custom intentionally-vulnerable REST API ("VulnShop")** containing one
> endpoint per SQLi class, plus an automated scenario suite that scans it. See
> §9 and the separate **VulnShop_Documentation.md**.

---

## 2. Repository layout

```
SQLI agent/
├── ssqli_agent/            # THE AGENT (the deliverable tool)
│   ├── agent/
│   │   ├── sqli_agent.py            # Core agent: probing, detection, oracles, AI, PoC
│   │   ├── payload_engine.py        # 54-payload library across 10 SQLi categories
│   │   ├── vulnerability_model.py   # Finding/Report models + CVSS scoring
│   │   ├── response_compare.py      # Response normalisation + similarity ratio
│   │   └── dbms_fingerprint.py      # DBMS identification from error signatures
│   ├── recon/              # Domain → injectable-target discovery pipeline
│   │   ├── subdomain_enum.py        # crt.sh CT logs + DNS brute-force
│   │   ├── liveness.py              # Parallel HTTP/HTTPS liveness probing
│   │   ├── crawler.py               # Same-scope link & form crawler
│   │   ├── param_discovery.py       # URLs/forms → injectable parameters
│   │   └── recon_orchestrator.py    # Full recon pipeline
│   ├── utils/
│   │   ├── http_client.py           # Timed HTTP wrapper (stdlib urllib)
│   │   ├── logger.py                # Hacker-style console logger
│   │   ├── reporter.py              # JSON + HTML reports
│   │   └── bughunter_report.py      # AI-written bug-bounty Markdown report
│   ├── config.py           # Central configuration (+ .env loader)
│   ├── scanner.py          # Unified orchestrator (url / file / domain modes)
│   └── main.py             # CLI entry point
│
├── vulnerable_target/      # "VulnShop" — custom vulnerable REST API (the proof target)
├── tests/                  # Unit tests (44) + automated scenario suite
└── reports/                # (under ssqli_agent/) generated scan reports
```

The agent (`ssqli_agent/`) is **self-contained** — it can be shipped on its own.
`vulnerable_target/` and `tests/` exist to *prove* the agent works; neither is
imported by the tool at runtime.

---

## 3. Dependencies

Only two third-party packages; everything else is the Python standard library
(`urllib`, `difflib`, `concurrent.futures`, `re`, `sqlite3`).

```
colorama>=0.4.6     # coloured console output
Flask>=3.0.0        # only needed to run the VulnShop demo target
```

```powershell
pip install -r ssqli_agent/requirements.txt
```

LLM access is **optional**. With a model the agent adds LLM confirmation and the
AI report; without one it runs in static-heuristic mode and still detects/reports.

```powershell
copy ssqli_agent\.env.example ssqli_agent\.env
# edit .env:  LLM_PROVIDER=groq   GROQ_API_KEY=<your key>
```

**Multi-model support (cloud + local).** Providers and default models live in a
single registry — `ssqli_agent/agent/llm_providers.py` (the "hook"). Edit that
file to add a provider or change a model. Select at runtime:

```powershell
python main.py --list-models                         # list all providers/models
python main.py --url "..." --provider anthropic --model claude-opus-4-20250514
python main.py --url "..." --provider openai --model gpt-4o
python main.py --url "..." --local --model llama3.1  # local Ollama — no API key
python main.py --url "..." --provider custom --base-url http://host:8000/v1/chat/completions
```

| Type | Providers | Key |
|------|-----------|-----|
| Cloud | `groq`, `anthropic`, `openai`, `openrouter`, `together` | per-provider env var |
| Local | `ollama`, `lmstudio`, `llamacpp`, `custom` (any OpenAI-compatible) | none |

Two wire formats cover everything: **anthropic** (Messages API) and **openai**
(Chat Completions — Groq, OpenAI, Ollama, LM Studio, llama.cpp, OpenRouter, …).

At startup the agent performs a **one-time LLM reachability check**: a cloud
provider with no key, or a local endpoint that is down, disables the LLM pass for
the run (a single notice is printed) and the scan proceeds in static-only mode —
avoiding a failed call on every probe.

---

## 4. How the agent works (pipeline)

```
            ┌──────────── INPUT MODE ────────────┐
   --url ───┤ parse parameters from the URL       │
  --file ───┤ read URLs from a file               ├──▶ list of injectable targets
--domain ───┤ recon: subdomains → live → crawl    │      (URL, method, params)
            └─────────────────────────────────────┘
                              │
                              ▼
   For each parameter:  baseline request  ──▶  fire 54 payloads
                              │
        ┌─────────────────────┼──────────────────────────────┐
        ▼                     ▼                               ▼
  collect ALL signals   boolean true/false oracle      time-based oracle
  (errors, indicators,  (boundaries + similarity        (calibrated baseline +
   timing, status,       ratio + confirmation)           control + confirmation)
   length, rows, DBMS)
        │
        ▼
  tiered heuristic verdict (strong vs weak)
        │
        ▼
  AI final-arbiter pass (full signal + raw-response visibility)
   • confirms / classifies            • catches what heuristics missed
   • suppresses false positives
        │
        ▼
  CVSS scoring  ──▶  harmless confirmation (marker + DBMS version)
                          │
                          ▼  (only with --exploit + authorisation)
                    enumerate TABLE NAMES (schema only, no row data)
                          │
                          ▼
                JSON + HTML + AI Markdown reports
```

---

## 5. Detection techniques

SQLSlayer fuses several independent techniques and only reports **true positives**.

### 5.1 Comprehensive signal collection
For **every** probe it evaluates **all** vectors (no early exit): DB-error
signatures, SQLi indicator patterns, response timing delta, status-code change,
body-length differential, result-row count, expected indicators, and HTTP 500s.

### 5.2 Tiered verdict (precision-first)
- **Strong signals** (leaked SQL error, reflected UNION/schema data, tautology
  returning extra rows, confirmed time delay) flag on their own.
- **Weak signals** (status-only, length-only, bare HTTP 500) never flag alone —
  an empty result set or benign error can cause them — so they cannot create
  false positives.

### 5.3 Boolean true/false oracle  *(adopted from ghauri/sqlmap)*
Sends a TRUE and a FALSE condition across multiple **injection boundaries**
(numeric, single-quote, double-quote, comment-terminated, parenthesised). Using
**normalised similarity ratio** (reflections + volatile content stripped, then
`difflib` ratio), it flags only when the TRUE response tracks the baseline and
the FALSE response diverges — then **re-tests to confirm**. A non-injectable
parameter treats both as literals, so it produces no false positive.

### 5.4 Jitter-aware time-based oracle
Calibrates normal latency over several requests, requires the injected delay to
**repeat**, and verifies a fast **control** request — so network jitter or a
generally-slow endpoint can't trigger a finding.

### 5.5 DBMS fingerprinting
Identifies the backend (MySQL, PostgreSQL, MS SQL Server, Oracle, SQLite, …)
from error signatures, tailors the time/exploit payloads, and labels every
finding with its DBMS.

### 5.6 AI final arbiter (full visibility)
The LLM reviews each signal-bearing probe with the **complete** picture — every
signal plus the raw responses — and acts as the final decision-maker: confirms
and classifies real findings, catches injections the heuristics missed, and
suppresses false positives. Tunable via `min_confidence`, `llm_authoritative`,
`llm_promote_threshold`.

### 5.7 Harmless exploitability confirmation
Once a parameter is confirmed, the agent runs **one safe PoC**: it auto-detects
the UNION column count, reflects a unique marker it controls (`SQLSLAYERxPoC`),
and reads the **DBMS version** (a benign system value) — or leaks the version via
a forced error on MySQL/MSSQL. **It never reads application or user data.**

### 5.8 Gated deeper exploitation (`--exploit`)
On explicit authorisation, the agent enumerates **table names** (schema metadata
only — still **no row data**). It is OFF by default and requires either an
interactive `I AM AUTHORISED` confirmation or the `--authorized` flag.

### 5.9 Safe mode (default) & throttling — production-friendly
Scans are **read-only by default**. Payloads are classified (`destructive`,
`heavy`); destructive ones (`DROP`/`INSERT`/`UPDATE`/`CREATE`) and resource-heavy
ones (large `randomblob` → DoS risk) are filtered out unless `--allow-destructive`
is authorised. A global `--delay` throttle rate-limits every request (scanner,
oracles, and recon). This makes the tool safe to point at an authorised live
target without risking data loss or denial of service, while still detecting
every SQLi class via safe probes plus the true/false and time oracles.

---

## 6. SQLi categories covered (CWE-89 / OWASP A03:2021)

In-band UNION · Boolean blind · Time-based blind · Error-based · Stacked
queries · Comment-strip authentication bypass · HTTP header injection · ORDER BY
injection · Second-order (stored) · Tautology — **54 payloads across 10
categories** (`python ssqli_agent/main.py --list-payloads`).

---

## 7. Usage

```powershell
# Single URL (every query parameter is probed)
python ssqli_agent\main.py --url "https://demo.test/item?id=1&cat=books"

# A file of URLs (one per line)
python ssqli_agent\main.py --file targets.txt

# A whole domain (recon → live hosts → crawl → params → scan)
python ssqli_agent\main.py --domain example.com

# Options
#   --provider groq|anthropic   --model <name>   --no-llm
#   --delay <seconds>           throttle between requests
#   --exploit [--authorized]    enumerate table names (schema only)
#   --allow-destructive         send DROP/INSERT/UPDATE payloads (DANGER)
#   --list-payloads
```

Scans are **read-only by default (safe mode)**; `--exploit` and
`--allow-destructive` require an explicit `I AM AUTHORISED` confirmation.

Every scan writes three reports to `ssqli_agent/reports/`:
- `sqli_report.json` — machine-readable findings (incl. `dbms`, `confirmation`, `exploitation`)
- `sqli_report.html` — styled dashboard
- `sqli_report.md` — **AI-written bug-bounty report** (exec summary, per-finding
  CVSS/CWE/DBMS, curl PoC, confirmation, impact, remediation)

---

## 8. Reporting

All three reports follow a formal **penetration-test report** structure —
cover/metadata, executive summary, scope & methodology, a findings-summary table,
detailed per-finding write-ups, recommendations, and a disclaimer. **Every finding
names its exact SQLi type** (UNION-based, Boolean-blind, Time-based, Error-based,
Stacked-queries, Authentication-bypass, ORDER BY, Second-order, …) via a fixed
taxonomy, alongside CVSS score + vector, CWE-89 / OWASP classification, DBMS,
detection method, PoC, harmless confirmation, impact, and remediation.

Findings are scored on a simplified CVSS v3.1 scale and grouped per endpoint. The
Markdown report is written by the LLM in a professional consulting voice and
gracefully falls back to a deterministic PT-format template if the LLM is
unavailable (e.g. rate-limited) — so a report is always produced.

---

## 9. Testing & proof of correctness

Because a detection tool is only credible if it actually finds real bugs, I built
a **custom vulnerable REST API, "VulnShop"** (`vulnerable_target/`), with one
endpoint per SQLi class, and an automated suite that scans it.

**Test assets (`tests/`):**
- `test_agent_unit.py` — 22 unit tests (payload library, CVSS scoring, detection patterns)
- `test_recon_unit.py` — 16 unit tests (URL parsing, link/form extraction, scope, dedupe)
- `test_detection_unit.py` — response-normalisation/similarity-ratio + DBMS fingerprinting
- `test_scenarios.py` — 10 end-to-end SQLi scenarios (one per category)
- `test_runner.py` — launches VulnShop as a **separate process**, runs all 10
  scenarios through the agent, and generates the reports

**Run:**
```powershell
python tests\test_agent_unit.py      # 22 tests
python tests\test_recon_unit.py      # 16 tests
python tests\test_detection_unit.py  # detection-helper tests
python tests\test_runner.py          # full scenario scan against VulnShop
```

**Latest results:** **44/44 unit tests pass**; the scenario suite scans 10
endpoints, fires 95 scenario payloads, and confirms injection in **all 10 SQLi
categories** (overall risk CRITICAL), including a harmless confirmation that
extracted the SQLite version via a controlled marker, and — under `--exploit` —
enumeration of table names (schema only).

---

## 10. Configuration reference (`config.py`)

| Setting | Default | Purpose |
|---|---|---|
| `llm.provider` | `groq` | LLM provider — any name from `agent/llm_providers.py` (cloud or local) |
| `llm.model` / `llm.base_url` | provider default | Override model / endpoint (e.g. local) |
| `agent.enable_llm_analysis` | `True` | AI confirmation pass |
| `agent.llm_authoritative` | `True` | AI may suppress false positives |
| `agent.min_confidence` | `0.6` | Confidence floor for reporting |
| `agent.llm_promote_threshold` | `0.8` | Min AI confidence to promote a missed probe |
| `agent.enable_confirmation` | `True` | Harmless marker + version PoC |
| `agent.allow_destructive` | `False` | Safe mode: destructive/heavy payloads off (set via `--allow-destructive`) |
| `agent.enable_exploit` | `False` | Table-name enumeration (set via `--exploit`) |
| `target.request_delay` | `0.0 s` | Throttle between requests (set via `--delay`) |
| `target.boolean_similarity_threshold` | `0.95` | Boolean ratio threshold |
| `target.time_based_threshold` | `3.0 s` | Time-based delay threshold |
| `recon.*` | — | Subdomain/crawl limits |

---

## 11. Ethics & authorisation

SQLSlayer is for **authorised** security testing only. The bundled VulnShop
target binds to localhost. Domain mode performs active reconnaissance; only run
it against assets you own or are explicitly permitted to test.

Built-in safety controls:
- **Safe mode is the default** — read-only; destructive and DoS-capable payloads
  are not sent.
- **`--allow-destructive`** and **`--exploit`** are gated behind an explicit
  `I AM AUTHORISED` confirmation and a clear warning.
- **`--delay`** throttles request rate to avoid loading the target.
- The harmless confirmation and the gated `--exploit` step read **system
  metadata only** (version, table names) — **never row/user data**.

Recommended for any live target: test a **staging** copy first, run with
`--delay`, keep the default safe mode, and obtain written authorisation.

---

## 12. Limitations & future work

- **Detection + ethical PoC**, not full data exfiltration (by design).
- UNION column-count is auto-detected; column *type* tuning is basic.
- SQLite time-based relies on heavy `randomblob` (no native `SLEEP`); the
  `SLEEP`/`pg_sleep`/`WAITFOR` oracle is fully reliable on MySQL/PG/MSSQL.
- Future: authenticated-session scanning, WAF-bypass tampering, second-order
  cross-endpoint correlation.
