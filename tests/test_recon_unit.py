"""
tests/test_recon_unit.py — Unit tests for the recon pipeline (no network I/O)

Covers URL parsing, parameter discovery, HTML link/form extraction, scope
checks, and target de-duplication.

Run with: python -m unittest tests.test_recon_unit -v
"""
import _bootstrap  # noqa: F401  (adds the SQLSlayer tool to sys.path)
import unittest

from agent.sqli_agent import _split_url
from recon.param_target import ParamTarget, dedupe_targets
from recon.param_discovery import url_to_target, form_to_target, targets_from_urls
from recon.crawler import (
    _extract_links, _extract_forms, _same_scope, Form,
)


# ─────────────────────────────────────────────────────────────────────────────
# URL SPLITTING
# ─────────────────────────────────────────────────────────────────────────────
class TestSplitUrl(unittest.TestCase):

    def test_splits_query_params(self):
        clean, query = _split_url("https://site.com/path?id=1&q=abc")
        self.assertEqual(clean, "https://site.com/path")
        self.assertEqual(query, {"id": "1", "q": "abc"})

    def test_no_query(self):
        clean, query = _split_url("https://site.com/path")
        self.assertEqual(clean, "https://site.com/path")
        self.assertEqual(query, {})

    def test_repeated_param_keeps_first(self):
        _, query = _split_url("https://site.com/x?a=1&a=2")
        self.assertEqual(query["a"], "1")


# ─────────────────────────────────────────────────────────────────────────────
# PARAMETER DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────
class TestParamDiscovery(unittest.TestCase):

    def test_url_to_target_with_params(self):
        t = url_to_target("https://site.com/item?id=5&cat=books")
        self.assertIsNotNone(t)
        self.assertEqual(t.method, "GET")
        self.assertEqual(t.param_type, "query")
        self.assertEqual(set(t.params), {"id", "cat"})
        self.assertEqual(t.url, "https://site.com/item")

    def test_url_to_target_without_params_returns_none(self):
        self.assertIsNone(url_to_target("https://site.com/home"))

    def test_form_to_target_post_is_body(self):
        form = Form(action="https://site.com/login", method="POST",
                    fields={"username": "test", "password": "test"})
        t = form_to_target(form)
        self.assertEqual(t.param_type, "body")
        self.assertEqual(t.method, "POST")
        self.assertEqual(set(t.params), {"username", "password"})

    def test_form_to_target_get_is_query(self):
        form = Form(action="https://site.com/search", method="GET",
                    fields={"q": "test"})
        self.assertEqual(form_to_target(form).param_type, "query")

    def test_targets_from_urls_skips_paramless(self):
        targets = targets_from_urls([
            "https://site.com/a?x=1",
            "https://site.com/b",            # skipped (no params)
            "https://site.com/c?y=2",
        ])
        self.assertEqual(len(targets), 2)


# ─────────────────────────────────────────────────────────────────────────────
# HTML EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────
class TestHtmlExtraction(unittest.TestCase):

    HTML = """
    <html><body>
      <a href="/products?id=1">Product</a>
      <a href="https://site.com/search?q=x">Search</a>
      <a href="javascript:void(0)">Ignore me</a>
      <img src="/static/logo.png">
      <form action="/login" method="post">
        <input type="text" name="username" value="">
        <input type="password" name="password">
        <button>Go</button>
      </form>
    </body></html>
    """

    def test_extract_links_resolves_relative(self):
        links = _extract_links(self.HTML, "https://site.com/page")
        self.assertIn("https://site.com/products?id=1", links)
        self.assertIn("https://site.com/search?q=x", links)

    def test_extract_links_skips_javascript(self):
        links = _extract_links(self.HTML, "https://site.com/page")
        self.assertFalse(any("javascript" in l for l in links))

    def test_extract_forms(self):
        forms = _extract_forms(self.HTML, "https://site.com/page")
        self.assertEqual(len(forms), 1)
        f = forms[0]
        self.assertEqual(f.method, "POST")
        self.assertEqual(f.action, "https://site.com/login")
        self.assertEqual(set(f.fields), {"username", "password"})


# ─────────────────────────────────────────────────────────────────────────────
# SCOPE & DEDUPE
# ─────────────────────────────────────────────────────────────────────────────
class TestScopeAndDedupe(unittest.TestCase):

    def test_same_scope_subdomain(self):
        self.assertTrue(_same_scope("https://api.site.com/x", "site.com"))
        self.assertTrue(_same_scope("https://site.com/x", "site.com"))

    def test_out_of_scope(self):
        self.assertFalse(_same_scope("https://evil.com/x", "site.com"))

    def test_relative_is_in_scope(self):
        self.assertTrue(_same_scope("/relative/path?a=1", "site.com"))

    def test_dedupe_collapses_same_signature(self):
        t1 = ParamTarget(url="https://s.com/x", method="GET",
                         params={"id": "1"}, param_type="query")
        t2 = ParamTarget(url="https://s.com/x?id=9", method="GET",
                         params={"id": "9"}, param_type="query")
        deduped = dedupe_targets([t1, t2])
        self.assertEqual(len(deduped), 1)

    def test_dedupe_keeps_distinct(self):
        t1 = ParamTarget(url="https://s.com/x", method="GET",
                         params={"id": "1"}, param_type="query")
        t2 = ParamTarget(url="https://s.com/y", method="GET",
                         params={"id": "1"}, param_type="query")
        self.assertEqual(len(dedupe_targets([t1, t2])), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
