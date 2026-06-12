"""
tests/test_agent_unit.py — Unit tests for SQLi Agent components
SQLSlayer

Run with: python -m pytest tests/test_agent_unit.py -v
"""
import _bootstrap  # noqa: F401  (adds the SQLSlayer tool to sys.path)
import unittest
import json

from agent.payload_engine import (
    PAYLOADS, PayloadCategory, payload_summary,
    get_payloads_by_category, get_payloads_by_severity
)
from agent.vulnerability_model import (
    score_finding, RiskLevel, SEVERITY_TO_CVSS, REMEDIATION_MAP
)
from utils.http_client import HTTPResponse


# ─────────────────────────────────────────────────────────────────────────────
# PAYLOAD ENGINE TESTS
# ─────────────────────────────────────────────────────────────────────────────
class TestPayloadEngine(unittest.TestCase):

    def test_payload_count_sufficient(self):
        """Should have a robust payload library (≥40 payloads)."""
        self.assertGreaterEqual(len(PAYLOADS), 40,
                                f"Expected ≥40 payloads, got {len(PAYLOADS)}")

    def test_all_categories_represented(self):
        """Every PayloadCategory must have at least one payload."""
        for cat in PayloadCategory:
            payloads = get_payloads_by_category(cat)
            self.assertGreater(len(payloads), 0,
                               f"No payloads for category {cat.value}")

    def test_critical_payloads_exist(self):
        """Must have CRITICAL severity payloads."""
        critical = get_payloads_by_severity("CRITICAL")
        self.assertGreater(len(critical), 5,
                           "Expected >5 CRITICAL payloads")

    def test_union_payloads_have_select(self):
        """All UNION payloads should contain SELECT keyword."""
        union_payloads = get_payloads_by_category(PayloadCategory.IN_BAND_UNION)
        for p in union_payloads:
            self.assertIn("SELECT", p.value.upper(),
                          f"UNION payload missing SELECT: {p.value}")

    def test_time_based_payloads_have_delay_mechanism(self):
        """Time-based payloads should reference a delay function."""
        delay_funcs = ["sleep", "randomblob", "waitfor", "pg_sleep"]
        time_payloads = get_payloads_by_category(PayloadCategory.TIME_BASED)
        for p in time_payloads:
            has_delay = any(fn in p.value.lower() for fn in delay_funcs)
            self.assertTrue(has_delay,
                            f"Time-based payload lacks delay mechanism: {p.value}")

    def test_payload_categories_valid_enum(self):
        """All payload categories should be valid enum values."""
        for p in PAYLOADS:
            self.assertIsInstance(p.category, PayloadCategory)

    def test_payload_severity_valid(self):
        """All payload severities should be CRITICAL/HIGH/MEDIUM/LOW."""
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for p in PAYLOADS:
            self.assertIn(p.severity, valid,
                          f"Invalid severity '{p.severity}' for payload: {p.value}")

    def test_payload_summary_structure(self):
        """payload_summary() should return dict with all categories."""
        summary = payload_summary()
        self.assertEqual(len(summary), len(PayloadCategory))
        for k, v in summary.items():
            self.assertIn("count", v)
            self.assertIn("critical", v)


# ─────────────────────────────────────────────────────────────────────────────
# VULNERABILITY MODEL TESTS
# ─────────────────────────────────────────────────────────────────────────────
class TestVulnerabilityModel(unittest.TestCase):

    def test_score_finding_not_vulnerable(self):
        risk, cvss, remediation = score_finding("IN_BAND_UNION", "CRITICAL", False, 0.0)
        self.assertEqual(risk, RiskLevel.INFO)
        self.assertEqual(cvss, 0.0)
        self.assertEqual(remediation, "")

    def test_score_finding_critical(self):
        risk, cvss, remediation = score_finding("IN_BAND_UNION", "CRITICAL", True, 1.0)
        self.assertEqual(risk, RiskLevel.CRITICAL)
        self.assertGreaterEqual(cvss, 9.0)
        self.assertIn("parameterised", remediation.lower())

    def test_score_finding_high_confidence(self):
        """HIGH severity at full confidence should yield MEDIUM or above."""
        risk, cvss, remediation = score_finding("BOOLEAN_BLIND", "HIGH", True, 0.9)
        self.assertIn(risk, [RiskLevel.HIGH, RiskLevel.CRITICAL, RiskLevel.MEDIUM])
        self.assertGreater(cvss, 0.0)

    def test_score_finding_low_confidence_reduces_cvss(self):
        _, cvss_high,  _ = score_finding("STACKED", "CRITICAL", True, 1.0)
        _, cvss_low,   _ = score_finding("STACKED", "CRITICAL", True, 0.3)
        self.assertGreater(cvss_high, cvss_low)

    def test_all_categories_have_remediation(self):
        for cat in PayloadCategory:
            self.assertIn(cat.value, REMEDIATION_MAP,
                          f"No remediation for category {cat.value}")

    def test_cvss_range(self):
        """CVSS scores should be between 0 and 10."""
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            _, cvss, _ = score_finding("IN_BAND_UNION", severity, True, 0.9)
            self.assertGreaterEqual(cvss, 0.0)
            self.assertLessEqual(cvss, 10.0)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP CLIENT TESTS
# ─────────────────────────────────────────────────────────────────────────────
class TestHTTPResponse(unittest.TestCase):

    def _make_resp(self, body: str, status: int = 200):
        return HTTPResponse(
            status_code=status, body=body,
            response_time_ms=50.0, headers={},
        )

    def test_contains_case_insensitive(self):
        resp = self._make_resp('{"status": "Error: sqlite3.OperationalError"}')
        self.assertTrue(resp.contains("sqlite"))
        self.assertTrue(resp.contains("SQLITE"))
        self.assertFalse(resp.contains("mysql"))

    def test_json_parse(self):
        resp = self._make_resp('{"status": "ok", "data": [1, 2]}')
        data = resp.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(len(data["data"]), 2)

    def test_json_parse_invalid(self):
        resp = self._make_resp("not json")
        self.assertEqual(resp.json(), {})


# ─────────────────────────────────────────────────────────────────────────────
# STATIC DETECTION PATTERN TESTS (integration-like)
# ─────────────────────────────────────────────────────────────────────────────
class TestStaticDetectionPatterns(unittest.TestCase):
    """Test that DB error patterns are correctly detected."""

    def setUp(self):
        from agent.sqli_agent import COMPILED_ERROR_PATTERNS, COMPILED_INDICATOR_PATTERNS
        self.error_patterns = COMPILED_ERROR_PATTERNS
        self.indicator_patterns = COMPILED_INDICATOR_PATTERNS

    def _matches_any(self, patterns, text: str) -> bool:
        return any(p.search(text) for p in patterns)

    def test_sqlite_error_detected(self):
        self.assertTrue(self._matches_any(
            self.error_patterns,
            'sqlite3.OperationalError: near "\'": syntax error'
        ))

    def test_syntax_error_detected(self):
        self.assertTrue(self._matches_any(
            self.error_patterns,
            'syntax error near "1 UNION SELECT"'
        ))

    def test_no_false_positive_on_clean_response(self):
        self.assertFalse(self._matches_any(
            self.error_patterns,
            '{"status": "ok", "data": [{"id": 1, "name": "laptop"}]}'
        ))

    def test_union_select_indicator(self):
        self.assertTrue(self._matches_any(
            self.indicator_patterns,
            '{"data": [{"union select username from users": "..."}]}'
        ))

    def test_sqlite_master_indicator(self):
        self.assertTrue(self._matches_any(
            self.indicator_patterns,
            "SELECT name FROM sqlite_master WHERE type='table'"
        ))


if __name__ == "__main__":
    unittest.main(verbosity=2)
