"""
tests/test_detection_unit.py — Unit tests for the ghauri-style detection helpers
(response normalisation / similarity ratio, DBMS fingerprinting). No network I/O.
"""
import _bootstrap  # noqa: F401
import unittest

from agent import response_compare as rc
from agent.dbms_fingerprint import fingerprint


class TestResponseCompare(unittest.TestCase):

    def test_identical_ratio_is_one(self):
        self.assertEqual(rc.ratio("hello world", "hello world"), 1.0)

    def test_reflection_is_stripped(self):
        body = '{"q":"\' OR 1=1--","data":[]}'
        norm = rc.normalize(body, ["' OR 1=1--"])
        self.assertNotIn("OR 1=1", norm)

    def test_volatile_timestamp_removed(self):
        a = rc.normalize('{"t":"2026-06-12 10:00:00","data":[1]}')
        b = rc.normalize('{"t":"2025-01-01 23:59:59","data":[1]}')
        self.assertEqual(a, b)        # timestamps neutralised → identical

    def test_page_stable_for_identical(self):
        self.assertTrue(rc.page_is_stable('{"data":[1,2,3]}', '{"data":[1,2,3]}'))

    def test_page_unstable_for_different(self):
        self.assertFalse(rc.page_is_stable('{"data":[1,2,3]}',
                                           '{"totally":"different","x":99}'))

    def test_true_tracks_baseline_false_diverges(self):
        baseline = '{"data":[{"id":1,"u":"admin"}],"status":"ok"}'
        true_resp = '{"data":[{"id":1,"u":"admin"}],"status":"ok"}'   # AND 1=1
        false_resp = '{"data":[],"status":"ok"}'                       # AND 1=2
        nb = rc.normalize(baseline)
        self.assertGreaterEqual(rc.ratio(rc.normalize(true_resp), nb), 0.95)
        self.assertLess(rc.ratio(rc.normalize(false_resp), rc.normalize(true_resp)), 0.95)


class TestDbmsFingerprint(unittest.TestCase):

    def test_sqlite(self):
        self.assertEqual(fingerprint('sqlite3.OperationalError: unrecognized token'), "SQLite")

    def test_mysql(self):
        self.assertEqual(
            fingerprint("You have an error in your SQL syntax; check the manual "
                        "that corresponds to your MySQL server version"), "MySQL")

    def test_postgres(self):
        self.assertEqual(fingerprint("PostgreSQL query failed: ERROR: syntax error "
                                     "at or near"), "PostgreSQL")

    def test_mssql(self):
        self.assertEqual(fingerprint("Unclosed quotation mark after the character string"),
                         "Microsoft SQL Server")

    def test_oracle(self):
        self.assertEqual(fingerprint("ORA-01756: quoted string not properly terminated"),
                         "Oracle")

    def test_clean_response_none(self):
        self.assertIsNone(fingerprint('{"status":"ok","data":[1,2,3]}'))


if __name__ == "__main__":
    unittest.main(verbosity=2)
