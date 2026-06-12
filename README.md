# SQLSlayer — SQL Injection Detection Suite

Three cleanly separated components:

```
SQLI agent/
├── ssqli_agent/        # THE TOOL — SQLSlayer scanner (this is what you run)
├── vulnerable_target/  # "VulnShop" — a standalone deliberately-vulnerable demo API
└── tests/              # Unit tests + the demo scenario suite (decoupled from the tool)
```

- **`ssqli_agent/`** — the SQLSlayer agent. Scans real targets via three input modes
  (single URL, a file of URLs, or a full domain recon). See `ssqli_agent/README.md`.
- **`vulnerable_target/`** — **VulnShop**, a separate Flask app intentionally
  vulnerable to every SQLi category. It has **no dependency** on the tool; it's just
  something to point the scanner at. Run with `python vulnerable_target/app.py`.
- **`tests/`** — unit tests for the tool plus `test_runner.py`, which launches
  VulnShop as its own process and runs the full scenario suite against it.

### Is the `tests/` folder required to use the tool?
**No.** `ssqli_agent/` is fully self-contained — you can copy just that folder and
scan real targets with `python ssqli_agent/main.py --url ...`. `tests/` and
`vulnerable_target/` exist only for local validation and the demo; neither is
imported by the tool at runtime. (`tests/` is recommended to keep if you want to
run the unit tests / regression demo.)

## Quick start
```powershell
# 1. install deps (Flask is only needed for the demo target)
pip install -r ssqli_agent/requirements.txt

# 2. set your Groq key
copy ssqli_agent\.env.example ssqli_agent\.env   # then edit .env

# 3a. run the demo end-to-end (starts target, scans it, writes reports)
python tests\test_runner.py

# 3b. or scan a real target you are authorised to test
python ssqli_agent\main.py --url "https://demo.test/item?id=1"
```

## Reports
Written to `ssqli_agent/reports/`:
- `sqli_report.json` — machine-readable findings
- `sqli_report.html` — styled dashboard
- `sqli_report.md` — **AI-written bug-bounty-style report** (executive summary,
  per-finding writeups with CVSS/CWE, curl PoCs, impact, remediation)

## Run the tests
```powershell
python tests\test_agent_unit.py     # tool unit tests
python tests\test_recon_unit.py     # recon pipeline unit tests
python tests\test_runner.py         # full demo scenario scan
```

> For authorised security testing only. The vulnerable target is for localhost
> practice; only scan external systems you own or have written permission to assess.
