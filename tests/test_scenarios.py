"""
tests/test_scenarios.py — 10 Comprehensive SQL Injection Test Scenarios
SQLSlayer

Each scenario maps to a specific SQLi category and target endpoint.
Scenarios are designed to demonstrate detection across ALL major SQLi types.
"""
import _bootstrap  # noqa: F401  (adds the SQLSlayer tool to sys.path)
from dataclasses import dataclass, field
from typing import List, Optional
from agent.payload_engine import PayloadCategory, Payload, PAYLOADS, get_payloads_by_category


@dataclass
class TestScenario:
    scenario_id:   str
    name:          str
    description:   str
    sqli_type:     str
    endpoint:      str
    method:        str
    param_name:    str
    param_type:    str                   # query | body | header | json
    baseline_value: str = "1"
    extra_body:    Optional[dict] = None
    categories:    List[PayloadCategory] = field(default_factory=list)
    expected_vulnerable: bool = True
    cwe: str = "CWE-89"
    owasp: str = "A03:2021 – Injection"


SCENARIOS: List[TestScenario] = [

    # ── SCENARIO 1: Classic In-Band (UNION) ─────────────────────────────────
    TestScenario(
        scenario_id    = "SC-001",
        name           = "Classic In-Band UNION Injection",
        description    = (
            "Tests GET /api/users?id= endpoint for UNION-based SQL injection. "
            "Attacker can enumerate columns and extract data from any table "
            "using UNION SELECT statements."
        ),
        sqli_type      = "IN_BAND_UNION",
        endpoint       = "/api/users",
        method         = "GET",
        param_name     = "id",
        param_type     = "query",
        baseline_value = "1",
        categories     = [PayloadCategory.IN_BAND_UNION, PayloadCategory.TAUTOLOGY],
        expected_vulnerable = True,
    ),

    # ── SCENARIO 2: Boolean Blind ────────────────────────────────────────────
    TestScenario(
        scenario_id    = "SC-002",
        name           = "Boolean-Based Blind SQL Injection",
        description    = (
            "Tests GET /api/orders?order_id= for boolean blind injection. "
            "No data is returned in the response — attacker infers DB content "
            "by observing True vs False response differences."
        ),
        sqli_type      = "BOOLEAN_BLIND",
        endpoint       = "/api/orders",
        method         = "GET",
        param_name     = "order_id",
        param_type     = "query",
        baseline_value = "1",
        categories     = [PayloadCategory.BOOLEAN_BLIND],
        expected_vulnerable = True,
    ),

    # ── SCENARIO 3: Time-Based Blind ─────────────────────────────────────────
    TestScenario(
        scenario_id    = "SC-003",
        name           = "Time-Based Blind SQL Injection",
        description    = (
            "Tests GET /api/categories?cat= for time-based blind injection. "
            "Uses SQLite randomblob() to introduce measurable delays when "
            "the conditional expression is true, allowing data extraction "
            "one bit at a time."
        ),
        sqli_type      = "TIME_BASED",
        endpoint       = "/api/categories",
        method         = "GET",
        param_name     = "cat",
        param_type     = "query",
        baseline_value = "electronics",
        categories     = [PayloadCategory.TIME_BASED],
        expected_vulnerable = True,
    ),

    # ── SCENARIO 4: Error-Based ───────────────────────────────────────────────
    TestScenario(
        scenario_id    = "SC-004",
        name           = "Error-Based SQL Injection",
        description    = (
            "Tests GET /api/categories?cat= for error-based injection. "
            "The endpoint leaks full DB error messages to the client, "
            "allowing attackers to extract DB metadata via crafted "
            "syntax errors."
        ),
        sqli_type      = "ERROR_BASED",
        endpoint       = "/api/categories",
        method         = "GET",
        param_name     = "cat",
        param_type     = "query",
        baseline_value = "electronics",
        categories     = [PayloadCategory.ERROR_BASED],
        expected_vulnerable = True,
    ),

    # ── SCENARIO 5: Authentication Bypass (Comment Strip) ────────────────────
    TestScenario(
        scenario_id    = "SC-005",
        name           = "Authentication Bypass via Comment Injection",
        description    = (
            "Tests POST /api/login for classic auth bypass. "
            "Payloads inject SQL comments (--) to short-circuit the "
            "password check, granting admin access without valid credentials."
        ),
        sqli_type      = "COMMENT_STRIP",
        endpoint       = "/api/login",
        method         = "POST",
        param_name     = "username",
        param_type     = "body",
        baseline_value = "alice",
        extra_body     = {"password": "wrongpassword"},
        categories     = [PayloadCategory.COMMENT_STRIP, PayloadCategory.TAUTOLOGY],
        expected_vulnerable = True,
    ),

    # ── SCENARIO 6: HTTP Header Injection ────────────────────────────────────
    TestScenario(
        scenario_id    = "SC-006",
        name           = "HTTP Header SQL Injection (User-Agent)",
        description    = (
            "Tests GET /api/audit where User-Agent header is interpolated "
            "directly into a SQL WHERE clause. Common in WAF-bypassing "
            "attacks since header values are rarely validated."
        ),
        sqli_type      = "HEADER_INJECT",
        endpoint       = "/api/audit",
        method         = "GET",
        param_name     = "User-Agent",
        param_type     = "header",
        baseline_value = "Mozilla/5.0 (legitimate)",
        categories     = [PayloadCategory.HEADER_INJECT, PayloadCategory.TAUTOLOGY],
        expected_vulnerable = True,
    ),

    # ── SCENARIO 7: JSON Body Injection ──────────────────────────────────────
    TestScenario(
        scenario_id    = "SC-007",
        name           = "JSON Parameter SQL Injection",
        description    = (
            "Tests POST /api/reports where JSON body parameters are "
            "interpolated unsafely. JSON APIs are a frequent blind spot "
            "as developers assume structured input is safe."
        ),
        sqli_type      = "IN_BAND_UNION",
        endpoint       = "/api/reports",
        method         = "POST",
        param_name     = "report_id",
        param_type     = "json",
        baseline_value = "1",
        extra_body     = {"format": "pdf"},
        categories     = [PayloadCategory.IN_BAND_UNION, PayloadCategory.TAUTOLOGY,
                          PayloadCategory.ERROR_BASED],
        expected_vulnerable = True,
    ),

    # ── SCENARIO 8: Second-Order Injection ───────────────────────────────────
    TestScenario(
        scenario_id    = "SC-008",
        name           = "Second-Order (Stored) SQL Injection",
        description    = (
            "Tests PUT /api/profile where malicious payload is stored in DB "
            "then re-executed in a subsequent query. The injection point is "
            "decoupled from the execution point — evades input-only scanners."
        ),
        sqli_type      = "SECOND_ORDER",
        endpoint       = "/api/profile",
        method         = "PUT",
        param_name     = "bio",
        param_type     = "body",
        baseline_value = "Hello world",
        extra_body     = {"user_id": 2},
        categories     = [PayloadCategory.SECOND_ORDER, PayloadCategory.COMMENT_STRIP],
        expected_vulnerable = True,
    ),

    # ── SCENARIO 9: ORDER BY Injection ───────────────────────────────────────
    TestScenario(
        scenario_id    = "SC-009",
        name           = "ORDER BY Clause Injection",
        description    = (
            "Tests GET /api/leaderboard?sort= where ORDER BY column is "
            "user-controlled. Cannot use parameterised queries for ORDER BY "
            "directly — requires whitelist validation instead. "
            "Enables conditional extraction and time-based attacks."
        ),
        sqli_type      = "ORDERBY",
        endpoint       = "/api/leaderboard",
        method         = "GET",
        param_name     = "sort",
        param_type     = "query",
        baseline_value = "score",
        categories     = [PayloadCategory.ORDERBY, PayloadCategory.ERROR_BASED],
        expected_vulnerable = True,
    ),

    # ── SCENARIO 10: Stacked Queries ─────────────────────────────────────────
    TestScenario(
        scenario_id    = "SC-010",
        name           = "Stacked Queries (Multiple Statement) Injection",
        description    = (
            "Tests DELETE /api/messages?msg_id= for stacked query injection. "
            "Attacker appends a second SQL statement (INSERT admin user, "
            "DROP table, UPDATE passwords) after the legitimate statement. "
            "Highest severity class — can cause full DB compromise."
        ),
        sqli_type      = "STACKED",
        endpoint       = "/api/messages",
        method         = "DELETE",
        param_name     = "msg_id",
        param_type     = "query",
        baseline_value = "1",
        categories     = [PayloadCategory.STACKED, PayloadCategory.TAUTOLOGY],
        expected_vulnerable = True,
        cwe            = "CWE-89",
    ),
]


def get_scenario_by_id(sid: str) -> Optional[TestScenario]:
    return next((s for s in SCENARIOS if s.scenario_id == sid), None)


def get_payloads_for_scenario(scenario: TestScenario) -> List[Payload]:
    if scenario.categories:
        payloads = []
        for cat in scenario.categories:
            payloads.extend(get_payloads_by_category(cat))
        return payloads
    return PAYLOADS
