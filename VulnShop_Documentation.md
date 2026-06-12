# VulnShop — Deliberately Vulnerable REST API
### Application Documentation

| | |
|---|---|
| **Application** | VulnShop — an intentionally-vulnerable demo REST API |
| **Purpose** | A controlled target to prove the SQLSlayer agent detects every SQLi class |
| **Author** | Avartraj Vishwakarma |
| **Date** | 12 June 2026 |
| **Stack** | Python 3.10+, Flask 3.x, SQLite (standard library) |
| **Location** | `vulnerable_target/` (`app.py`, `db.py`) |

> ⚠️ **WARNING — intentionally insecure.** Every endpoint concatenates user
> input directly into SQL (no parameterisation). It exists **only** as a local
> testing target. Run it **only on `127.0.0.1`**. Never deploy it or expose it
> to a network.

---

## 1. What it is

VulnShop is a small e-commerce-style REST API (users, products, orders, login,
reports, etc.) deliberately written **without** parameterised queries. It is a
**standalone** application — it has **no dependency** on the SQLSlayer tool. Its
job is to be a realistic, fully-controlled target so the scanner's detection can
be demonstrated and verified against every SQL-injection category.

The database (`vulnerable_app.db`, SQLite) is **created and seeded automatically**
on startup, and re-seeded on every run (AUTOINCREMENT counters are reset so
record IDs are deterministic). Seed data includes an `admin` user and a
`secrets` table so findings are meaningful.

---

## 2. Features

- **Self-contained**: one `python` command starts it; no external services.
- **One endpoint per SQLi category** (10 categories — see §4).
- **Auto-seeded SQLite DB** with deterministic data (idempotent).
- **Realistic surfaces**: query params, JSON bodies, form login, HTTP headers,
  `ORDER BY`, stacked `DELETE`.
- **Verbose errors** on some endpoints (to model error-based leakage).
- **Health endpoint** for readiness checks.
- **Landing page** with parameterised links + a login form (so crawlers/
  parameter-discovery can find inputs automatically).

---

## 3. How to run (local)

```powershell
# from the repository root
pip install flask                       # if not already installed

python vulnerable_target\app.py
# → [VulnShop] Starting deliberately-vulnerable API on http://127.0.0.1:5050
```

Verify it is reachable:
```powershell
# health check
curl http://127.0.0.1:5050/health
# → {"name":"VulnShop","service":"VulnShop","status":"healthy"}

# or open the landing page in a browser
start http://127.0.0.1:5050/
```

Stop it with **Ctrl+C**. The listening port is **5050** (loopback only).

---

## 4. Endpoints

| # | Endpoint | Method | Parameter(s) | Injectable via | SQLi category |
|---|----------|--------|--------------|----------------|---------------|
| 1 | `/api/users?id=` | GET | `id` | query string (numeric) | Tautology / UNION / Boolean |
| 2 | `/api/products?name=` | GET | `name` | query string (string `LIKE`) | In-band UNION / Error-based |
| 3 | `/api/orders?order_id=` | GET | `order_id` | query string (numeric) | Boolean-blind / Time-based |
| 4 | `/api/categories?cat=` | GET | `cat` | query string (string) | Error-based (verbose error) |
| 5 | `/api/login` | POST | `username`, `password` | JSON / form body | Comment-strip auth bypass |
| 6 | `/api/audit` | GET | `User-Agent`, `X-Forwarded-For` | HTTP headers | Header injection |
| 7 | `/api/reports` | POST | `report_id`, `format` | JSON body | JSON body injection / UNION |
| 8 | `/api/profile` | PUT | `bio`, `user_id` | JSON body (stored→read) | Second-order (stored) |
| 9 | `/api/leaderboard?sort=` | GET | `sort`, `order` | query string (`ORDER BY`) | ORDER BY injection |
| 10 | `/api/messages?msg_id=` | DELETE | `msg_id` | query string (`executescript`) | Stacked (multi-statement) |
| — | `/health` | GET | — | — | safe baseline |
| — | `/` | GET | — | — | landing page (links + form) |

> Endpoint #10 uses SQLite's `executescript`, so stacked payloads (e.g.
> `1; DROP TABLE users--`) genuinely execute. The DB re-seeds on the next start.

---

## 5. Database schema (seeded)

| Table | Notable columns | Seed rows |
|-------|-----------------|-----------|
| `users` | id, username, email, password, role, bio, score | admin / alice / bob |
| `products` | id, name, price, cat | 4 products |
| `categories` | id, name | electronics / kitchen / furniture |
| `orders` | order_id, user_id, product_id, total | 3 orders |
| `audit_log` | id, user_agent, ip, action, ts | 1 row |
| `reports` | id, name, format | 2 reports |
| `messages` | id, user_id, content | 2 messages |
| `secrets` | id, name, value | api_key, db_root_pw |

---

## 6. Try it by hand (sample injections)

```powershell
# Authentication bypass (logs in as admin without the password)
curl -X POST http://127.0.0.1:5050/api/login -H "Content-Type: application/json" -d "{\"username\":\"admin'--\",\"password\":\"x\"}"

# UNION-based data retrieval
curl "http://127.0.0.1:5050/api/users?id=' UNION SELECT 1,username,password FROM users--"

# Error-based leak (verbose DB error reveals the backend)
curl "http://127.0.0.1:5050/api/categories?cat='"

# Boolean differential (true vs false)
curl "http://127.0.0.1:5050/api/orders?order_id=1 AND 1=1"
curl "http://127.0.0.1:5050/api/orders?order_id=1 AND 1=2"
```

---

## 7. Scan it with SQLSlayer

```powershell
# 1) start VulnShop (terminal A)
python vulnerable_target\app.py

# 2) scan a single endpoint (terminal B)
python ssqli_agent\main.py --url "http://127.0.0.1:5050/api/users?id=1"

# 3) or run the full automated scenario suite (auto-starts/stops VulnShop)
python tests\test_runner.py
```

Reports are written to `ssqli_agent/reports/` (`sqli_report.json` / `.html` / `.md`)
in penetration-test format, each finding labelled with its SQLi type.

---

## 8. Notes & safety

- Binds to `127.0.0.1:5050` only (loopback) — not reachable from other machines.
- The SQLite DB file (`vulnerable_target/vulnerable_app.db`) is created on first
  run and reset on every start; safe to delete at any time.
- Intended lifetime is a single local test session; shut it down afterwards.
