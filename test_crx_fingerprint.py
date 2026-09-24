#!/usr/bin/env python3
"""
Regression tests for crx-fingerprint.

Every case here is one that previously produced a wrong answer. Run with:

    python test_crx_fingerprint.py

No network access. Archive tests build small zips in memory.
"""

import contextlib
import importlib.util
import io
import json
import unittest
import warnings
import zipfile

spec = importlib.util.spec_from_file_location("cf", "crx-fingerprint.py")
cf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cf)

KNOWN = cf.INFRA + cf.MERCHANTS


def bare_matches(text, domain):
    """Does a known domain appear as a bare token in this text?"""
    return any(cf.host_matches(m.group(1).lower(), domain)
               for m in cf.BARE_TOKEN.finditer(text))


def url_matches(text, domain):
    """Does a known domain appear as the host of a literal URL in this text?"""
    hosts = (cf.url_hostname(m.group(0)) for m in cf.URL_CANDIDATE.finditer(text))
    return any(cf.host_matches(h, domain) for h in hosts if h)


class DomainMatching(unittest.TestCase):
    def test_exact_and_subdomain_match(self):
        self.assertTrue(cf.host_matches("cbmaster.pro", "cbmaster.pro"))
        self.assertTrue(cf.host_matches("l.cbmaster.pro", "cbmaster.pro"))
        self.assertTrue(cf.host_matches("static.cbmaster.pro", "cbmaster.pro"))

    def test_substring_is_not_a_match(self):
        self.assertFalse(cf.host_matches("notcbmaster.pro", "cbmaster.pro"))

    def test_longer_hostname_is_not_a_match(self):
        for host in ("cbmaster.pro.invalid",
                     "cbmaster.pro.123.attacker.example",
                     "cbmaster.pro.рф"):
            self.assertFalse(cf.host_matches(host, "cbmaster.pro"), host)

    def test_boring_filter_matches_domains_not_substrings(self):
        boring = lambda h: any(cf.host_matches(h, b) for b in cf.BORING_DOMAINS)
        self.assertTrue(boring("google.com"))
        self.assertTrue(boring("www.google.com"))
        self.assertFalse(boring("google.com.attacker.example"))
        self.assertFalse(boring("notgithub.com"))


class UrlHostParsing(unittest.TestCase):
    def test_ip_address_host(self):
        self.assertEqual(cf.url_hostname("https://203.0.113.7/collect"), "203.0.113.7")

    def test_userinfo_is_not_the_host(self):
        self.assertEqual(
            cf.url_hostname("https://cbmaster.pro@collector.example/"),
            "collector.example")

    def test_userinfo_cannot_fake_a_fingerprint_hit(self):
        self.assertFalse(
            url_matches('"https://cbmaster.pro@collector.example/"', "cbmaster.pro"))

    def test_internationalised_host_kept_whole(self):
        self.assertEqual(
            cf.url_hostname("https://cbmaster.pro.рф/"),
            "cbmaster.pro.рф")
        self.assertFalse(
            url_matches('"https://cbmaster.pro.рф/"', "cbmaster.pro"))

    def test_port_and_case_normalised(self):
        self.assertEqual(cf.url_hostname("https://tp.cbmaster.pro:8443/ty"),
                         "tp.cbmaster.pro")
        self.assertEqual(cf.url_hostname("https://CBMaster.PRO/x"), "cbmaster.pro")

    def test_trailing_dot_stripped(self):
        self.assertEqual(cf.url_hostname("https://l.cbmaster.pro./"), "l.cbmaster.pro")

    def test_real_reference_still_matches(self):
        self.assertTrue(url_matches('"https://tp.cbmaster.pro/ty"', "cbmaster.pro"))

    def test_runtime_built_tld_is_not_reported_as_a_host(self):
        # "https://www.google." + countryCode
        self.assertIsNone(cf.url_hostname("https://www.google."))
        self.assertEqual(cf.partial_hostname("https://www.google."), "www.google")

    def test_a_fully_qualified_name_with_a_path_is_not_partial(self):
        self.assertEqual(cf.url_hostname("https://l.cbmaster.pro./"), "l.cbmaster.pro")
        self.assertIsNone(cf.partial_hostname("https://l.cbmaster.pro./"))

    def test_partial_host_cannot_score(self):
        self.assertFalse(url_matches('"https://tp.cbmaster."', "cbmaster.pro"))

    def test_ipv6_literal_is_not_dropped(self):
        js = 'fetch("https://[2001:db8::1]/collect"); fetch("http://[::1]:8080/x")'
        hosts = [cf.url_hostname(m.group(0)) for m in cf.URL_CANDIDATE.finditer(js)]
        self.assertEqual([h for h in hosts if h], ["2001:db8::1", "::1"])

    def test_schemeless_and_empty_hosts_are_rejected(self):
        for candidate in ("https://", "https:///path", "http://:8080/"):
            self.assertIsNone(cf.url_hostname(candidate), candidate)


class BareTokenScanning(unittest.TestCase):
    def test_javascript_is_not_a_host(self):
        js = 'document.body; window.location; console.log("hi"); a.b.c();'
        self.assertFalse(any(bare_matches(js, d) for d in KNOWN))

    def test_bare_known_domain_is_found(self):
        self.assertTrue(bare_matches('{"host":"kiwi.com"}', "kiwi.com"))

    def test_unicode_suffix_cannot_truncate(self):
        self.assertFalse(
            bare_matches('"cbmaster.pro.рф"', "cbmaster.pro"))
        self.assertFalse(bare_matches('"kiwi.com.xn--p1ai"', "kiwi.com"))


class MatchPatterns(unittest.TestCase):
    def test_broad_host_permission_ignores_path(self):
        for p in ("<all_urls>", "https://*/*", "https://*/", "*://*/*", "http://*/foo"):
            self.assertTrue(cf.is_broad_host_permission(p), p)
        self.assertFalse(cf.is_broad_host_permission("https://example.com/*"))

    def test_broad_content_match_requires_path(self):
        self.assertTrue(cf.is_broad_content_match("<all_urls>"))
        self.assertTrue(cf.is_broad_content_match("https://*/*"))
        self.assertFalse(cf.is_broad_content_match("https://*/"))
        self.assertFalse(cf.is_broad_content_match("https://example.com/*"))


def make_zip(entries):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for name, data in entries:
            z.writestr(name, data)
    b.seek(0)
    return zipfile.ZipFile(b)


class ArchiveLimits(unittest.TestCase):
    def test_entry_count_limit(self):
        original = cf.MAX_ENTRIES
        try:
            cf.MAX_ENTRIES = 2
            z = make_zip([(f"f{i}.js", "x") for i in range(5)])
            self.assertTrue(cf.check_archive_limits(z.infolist()))
        finally:
            cf.MAX_ENTRIES = original

    def test_total_size_limit(self):
        original = cf.MAX_TOTAL_BYTES
        try:
            cf.MAX_TOTAL_BYTES = 512
            z = make_zip([("manifest.json",
                           json.dumps({"name": "x", "version": "1"}) + " " * 3000)])
            self.assertTrue(cf.check_archive_limits(z.infolist()))
        finally:
            cf.MAX_TOTAL_BYTES = original

    def test_within_limits_passes(self):
        z = make_zip([("manifest.json", json.dumps({"name": "x", "version": "1"}))])
        self.assertEqual(cf.check_archive_limits(z.infolist()), [])


class DuplicateEntries(unittest.TestCase):
    def test_read_by_zipinfo_returns_the_checked_entry(self):
        b = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")   # the duplicate name is the point
            with zipfile.ZipFile(b, "w") as zf:
                zf.writestr("dup.js", "small")
                zf.writestr("dup.js", "LARGE" * 200)
        b.seek(0)
        z = zipfile.ZipFile(b)
        entries = [i for i in z.infolist() if i.filename == "dup.js"]
        self.assertEqual(len(entries), 2)
        first = entries[0]
        # reading by ZipInfo returns the entry whose size was checked
        self.assertEqual(len(z.read(first)), first.file_size)
        # reading by name may resolve to a different entry entirely
        self.assertNotEqual(len(z.read("dup.js")), first.file_size)


def make_crx(entries):
    """A CRX is a short header followed by a plain zip."""
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for name, data in entries:
            z.writestr(name, data)
    return b"Cr24" + b"\x03\x00\x00\x00" + b"\x00" * 16 + b.getvalue()


def manifest(**overrides):
    m = {
        "name": "Example Cashback",
        "version": "1.0.0.2",
        "manifest_version": 3,
        "permissions": sorted(cf.FINGERPRINT_PERMS),
        "host_permissions": ["http://*/*", "https://*/*"],
        "content_scripts": [{"matches": ["http://*/*", "https://*/*"],
                             "js": ["content.js"],
                             "run_at": "document_start"}],
    }
    m.update(overrides)
    return json.dumps(m)


class EndToEnd(unittest.TestCase):
    """Drive analyse() itself, with the download replaced by a built archive."""

    def analyse(self, entries):
        original = cf.fetch_crx
        cf.fetch_crx = lambda ext_id: make_crx(entries)
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                rc = cf.analyse("a" * 32)
        finally:
            cf.fetch_crx = original
        return rc, out.getvalue()

    def test_matching_extension_scores_and_exits_clean(self):
        rc, out = self.analyse([
            ("manifest.json", manifest()),
            ("background.js", 'fetch("https://tp.cbmaster.pro/ty?x=1");'),
            ("content.js", 'var s="https://static.cbmaster.pro/a.js";'),
        ])
        self.assertEqual(rc, 0)
        self.assertIn("STRONG MATCH", out)
        self.assertIn("tp.cbmaster.pro", out)
        self.assertIn("+2 exact fingerprint permission set", out)
        self.assertNotIn("INCOMPLETE", out)

    def test_localised_name_is_resolved_from_locales(self):
        rc, out = self.analyse([
            ("manifest.json", manifest(name="__MSG_appName__",
                                       default_locale="en")),
            ("_locales/en/messages.json",
             json.dumps({"appName": {"message": "Cashback Master"}})),
            ("background.js", 'fetch("https://tp.cbmaster.pro/ty");'),
        ])
        self.assertEqual(rc, 0)
        self.assertIn("Cashback Master", out)
        self.assertNotIn("__MSG_appName__", out)

    def test_unresolvable_localised_name_is_left_alone(self):
        rc, out = self.analyse([
            ("manifest.json", manifest(name="__MSG_appName__")),
            ("background.js", "var x=1;"),
        ])
        self.assertEqual(rc, 0)
        self.assertIn("__MSG_appName__", out)

    def test_benign_extension_does_not_match(self):
        rc, out = self.analyse([
            ("manifest.json", manifest(permissions=["storage"],
                                       host_permissions=["https://example.com/*"],
                                       content_scripts=[])),
            ("background.js", 'fetch("https://api.example.com/v1");'),
        ])
        self.assertEqual(rc, 0)
        self.assertIn("no fingerprint match", out)

    def test_a_domain_split_across_two_files_does_not_score(self):
        rc, out = self.analyse([
            ("manifest.json", manifest(permissions=["storage"],
                                       host_permissions=[], content_scripts=[])),
            ("a.js", 'var a="https://tp.cbmaster'),
            ("b.js", '.pro/ty";'),
        ])
        self.assertEqual(rc, 0)
        self.assertIn("no fingerprint match", out)
        self.assertNotIn("cbmaster.pro", out)

    def test_ipv6_endpoint_is_reported(self):
        rc, out = self.analyse([
            ("manifest.json", manifest(permissions=["storage"],
                                       host_permissions=[], content_scripts=[])),
            ("background.js", 'fetch("https://[2001:db8::1]/collect");'),
        ])
        self.assertEqual(rc, 0)
        self.assertIn("2001:db8::1", out)

    def test_oversized_member_marks_the_analysis_incomplete(self):
        original = cf.MAX_MEMBER_BYTES
        try:
            cf.MAX_MEMBER_BYTES = 600      # above the manifest, below the padded file
            rc, out = self.analyse([
                ("manifest.json", manifest()),
                ("background.js", 'fetch("https://tp.cbmaster.pro/ty");' + "/*pad*/" * 200),
            ])
        finally:
            cf.MAX_MEMBER_BYTES = original
        self.assertEqual(rc, 1)
        self.assertIn("[INCOMPLETE ANALYSIS]", out)
        self.assertIn("oversized", out)

    def test_archive_over_the_entry_limit_is_refused_before_any_read(self):
        original = cf.MAX_ENTRIES
        try:
            cf.MAX_ENTRIES = 2
            rc, out = self.analyse(
                [("manifest.json", manifest())]
                + [(f"f{i}.js", "x") for i in range(5)])
        finally:
            cf.MAX_ENTRIES = original
        self.assertEqual(rc, 1)
        self.assertIn("refused", out)
        self.assertIn("nothing was read or extracted", out)
        self.assertNotIn("VERDICT", out)

    def test_missing_manifest_fails(self):
        rc, out = self.analyse([("background.js", "var x=1;")])
        self.assertEqual(rc, 1)
        self.assertIn("no manifest.json", out)

    def test_not_a_crx_fails_to_unpack(self):
        original = cf.fetch_crx
        cf.fetch_crx = lambda ext_id: b"<html>404</html>"
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                rc = cf.analyse("a" * 32)
        finally:
            cf.fetch_crx = original
        self.assertEqual(rc, 1)
        self.assertIn("unpack failed", out.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
