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


# Which time-delay payload form is expected to work per DBMS (for the time oracle).
TIME_PAYLOADS = {
    "MySQL":                "{bv} AND SLEEP({d})",
    "PostgreSQL":           "{bv};SELECT pg_sleep({d})-- -",
    "Microsoft SQL Server": "{bv};WAITFOR DELAY '0:0:{d}'-- -",
    "SQLite":               "{bv} AND 1=(SELECT 1 FROM (SELECT randomblob(300000000))x)",
}
