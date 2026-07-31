import argparse
import importlib
import os
import tempfile
import types
import unicodedata
import unittest
from unittest import mock

import content
from lib import database, firewall_found, report, settings, tamper_engine
from lib.cmd import StoreDictKeyPairs


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.home = settings.HOME
        self.database_filename = settings.DATABASE_FILENAME
        settings.HOME = self.temp_dir.name
        settings.DATABASE_FILENAME = os.path.join(self.temp_dir.name, "cache.sqlite")
        self.cursor = database.initialize()

    def tearDown(self):
        self.cursor.connection.close()
        settings.HOME = self.home
        settings.DATABASE_FILENAME = self.database_filename
        self.temp_dir.cleanup()

    def test_payloads_are_deduplicated(self):
        self.assertTrue(database.insert_payload("payload", self.cursor))
        self.assertTrue(database.insert_payload("payload", self.cursor))
        self.assertEqual(1, len(database.fetch_data(self.cursor)))

    def test_url_fields_and_tamper_modules_are_serialized_correctly(self):
        tamper = types.ModuleType("content.tampers.example")
        result = database.insert_url(
            "example.com",
            {("Example", "payload", tamper)},
            {"Cloudflare", settings.UNKNOWN_FIREWALL_NAME},
            self.cursor,
            webserver="nginx",
        )
        self.assertTrue(result)

        row = database.fetch_data(self.cursor, is_payload=False)[0]
        self.assertEqual("example.com", row[1])
        self.assertEqual("content.tampers.example", row[2])
        self.assertEqual("Cloudflare", row[3])
        self.assertEqual("nginx", row[4])
        self.assertFalse(
            database.insert_url("example.com", [], [], self.cursor)
        )
        self.assertEqual(
            row,
            database.insert_url(
                "example.com", [], [], self.cursor, return_found=True
            ),
        )


class ReportTests(unittest.TestCase):
    def test_html_report_escapes_untrusted_values(self):
        generated = report.generate_html_report(
            'https://example.test/?q=<script>alert("x")</script>',
            ['<img src=x onerror=alert(1)>'],
            {("Technique", "<svg onload=alert(1)>", "content.tampers.demo")},
            {"X-Test": "<b>unsafe</b>"},
            403,
            "<server>",
            1,
            "GET",
            [{"time": "12:00", "event": "<script>event</script>"}],
        )
        self.assertNotIn("<script>alert", generated)
        self.assertNotIn("<svg onload", generated)
        self.assertNotIn("<img src=x", generated)
        self.assertIn("&lt;script&gt;", generated)
        self.assertIn("&lt;server&gt;", generated)


class CommandLineTests(unittest.TestCase):
    def _parser(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--headers", action=StoreDictKeyPairs)
        return parser

    def test_headers_split_only_on_first_separator(self):
        parsed = self._parser().parse_args(
            ["--headers", "Authorization=Bearer a:b,X-URL:https://example.test/a:b"]
        )
        self.assertEqual("Bearer a:b", parsed.headers["Authorization"])
        self.assertEqual("https://example.test/a:b", parsed.headers["X-URL"])

    def test_header_state_does_not_leak_between_parses(self):
        parser = self._parser()
        first = parser.parse_args(["--headers", "A=1"])
        second = parser.parse_args(["--headers", "B=2"])
        self.assertEqual({"A": "1"}, first.headers)
        self.assertEqual({"B": "2"}, second.headers)


class RequestTests(unittest.TestCase):
    def test_get_request_does_not_send_a_body(self):
        response = mock.Mock()
        response.content = b"<html>ok</html>"
        response.status_code = 200
        response.headers = {}
        with mock.patch("lib.settings.requests.get", return_value=response) as get:
            settings.get_page("https://example.test/")
        self.assertNotIn("data", get.call_args.kwargs)
        self.assertTrue(get.call_args.kwargs["verify"])

    def test_tls_verification_can_be_explicitly_disabled(self):
        response = mock.Mock(content=b"ok", status_code=200, headers={})
        settings.configure_tls_verification(False)
        try:
            with mock.patch("lib.settings.requests.get", return_value=response) as get:
                settings.get_page("https://example.test/")
            self.assertFalse(get.call_args.kwargs["verify"])
        finally:
            settings.configure_tls_verification(True)


class DetectionProbeTests(unittest.TestCase):
    def test_smart_detection_depth_adds_encoded_and_header_probes(self):
        detector = content.DetectionQueue(
            "https://example.test/?q=",
            ["' OR 1=1"],
            detection_depth="smart",
        )
        probes = detector._build_probe_requests("' OR 1=1")
        urls = [probe[0] for probe in probes]
        headers = [probe[2] for probe in probes]

        self.assertEqual(4, len(probes))
        self.assertIn("https://example.test/?q=' OR 1=1", urls)
        self.assertTrue(any("%27%20OR%201%3D1" in url for url in urls))
        self.assertTrue(any(
            isinstance(header, dict) and "X-Original-URL" in header
            for header in headers
        ))

    def test_basic_detection_depth_preserves_low_request_count(self):
        detector = content.DetectionQueue(
            "https://example.test/?q=",
            ["<script>alert(1)</script>"],
            detection_depth="basic",
        )
        probes = detector._build_probe_requests("<script>alert(1)</script>")

        self.assertEqual(2, len(probes))
        self.assertFalse(any(
            isinstance(probe[2], dict) and "X-Original-URL" in probe[2]
            for probe in probes
        ))


class IssueDraftTests(unittest.TestCase):
    def test_sensitive_argument_values_are_redacted_without_mutating_input(self):
        args = ["wafbypass", "-u", "https://secret.test", "--verbose"]
        original = list(args)
        redacted = firewall_found._redacted_command(args)
        self.assertEqual(original, args)
        self.assertNotIn("secret.test", redacted)
        self.assertIn("***", redacted)


class TamperEngineTests(unittest.TestCase):
    def test_all_tamper_modules_import_and_execute_examples(self):
        modules = []
        for filename in os.listdir(settings.TAMPERS_DIRECTORY):
            if filename.endswith(".py") and not filename.startswith("__"):
                modules.append(
                    importlib.import_module(
                        "content.tampers.{}".format(filename[:-3])
                    )
                )
        self.assertGreaterEqual(len(modules), 77)
        for module in modules:
            result = module.tamper(module.__example_payload__)
            self.assertIsInstance(result, str, module.__name__)

    def test_chain_generation_is_bounded_and_keeps_encoders_terminal(self):
        modules = [
            importlib.import_module("content.tampers.{}".format(name))
            for name in tamper_engine.TAMPER_PROFILES["sqli"]
        ]
        chains = tamper_engine.build_chain_candidates(
            modules,
            profile="sqli",
            payload_type="sqli",
            max_depth=3,
            budget=7,
            seed=42,
        )
        self.assertEqual(7, len(chains))
        for chain in chains:
            names = [tamper_engine.tamper_name(item) for item in chain.tampers]
            self.assertFalse(
                any(name in tamper_engine.TERMINAL_TAMPERS for name in names[:-1])
            )

    def test_chain_generation_explores_useful_ordered_permutations(self):
        modules = [
            importlib.import_module("content.tampers.keyword_avoidance"),
            importlib.import_module("content.tampers.randomcase"),
        ]
        chains = tamper_engine.build_chain_candidates(
            modules,
            profile="sqli",
            payload_type="sqli",
            max_depth=2,
            budget=2,
        )
        chain_names = {
            tuple(tamper_engine.tamper_name(item) for item in chain.tampers)
            for chain in chains
        }
        self.assertEqual({
            ("keyword_avoidance", "randomcase"),
            ("randomcase", "keyword_avoidance"),
        }, chain_names)

    def test_seeded_random_tampers_are_reproducible(self):
        randomcase = importlib.import_module("content.tampers.randomcase")
        first = tamper_engine.apply_candidate(
            randomcase, "SELECT Payload", seed=1234, variant=2
        )
        second = tamper_engine.apply_candidate(
            randomcase, "SELECT Payload", seed=1234, variant=2
        )
        self.assertEqual(first, second)

    def test_chain_variants_change_randomized_stages_reproducibly(self):
        randomcase = importlib.import_module("content.tampers.randomcase")
        urlencode = importlib.import_module("content.tampers.urlencode")
        chain = tamper_engine.TamperChain((randomcase, urlencode), seed=99)
        first = tamper_engine.apply_candidate(
            chain, "SELECT Payload", seed=99, variant=0
        )
        repeated = tamper_engine.apply_candidate(
            chain, "SELECT Payload", seed=99, variant=0
        )
        alternative = tamper_engine.apply_candidate(
            chain, "SELECT Payload", seed=99, variant=1
        )
        self.assertEqual(first, repeated)
        self.assertNotEqual(first, alternative)

    def test_new_context_tampers_transform_expected_characters(self):
        sql = importlib.import_module("content.tampers.sql_versioned_keywords")
        selective = importlib.import_module("content.tampers.selective_urlencode")
        html = importlib.import_module("content.tampers.html_hex_entities")
        unicode_tamper = importlib.import_module("content.tampers.unicode_normalize")

        self.assertIn("/*!50000SELECT*/", sql.tamper("SELECT id FROM users"))
        self.assertEqual("a%20b=1&c=2", selective.tamper("a b=1&c=2"))
        self.assertEqual("&#x3c;b&#x3e;", html.tamper("<b>"))
        normalized = unicode_tamper.tamper("SELECT 1")
        self.assertNotEqual("SELECT 1", normalized)
        self.assertEqual("SELECT 1", unicodedata.normalize("NFKC", normalized))

    def test_bypass_detection_rejects_block_statuses(self):
        fake = types.SimpleNamespace(
            __name__="content.tampers.fake",
            __type__="fake",
            __example_payload__="example",
            tamper=lambda payload: payload + "-changed",
        )
        normal = ("GET /", 200, "normal", {})
        with mock.patch.object(content.ScriptQueue, "load_scripts", return_value=[fake]):
            with mock.patch("lib.settings.get_page", return_value=("GET /", 403, "ok", {})):
                found = content.get_working_tampers(
                    "https://example.test/?q=",
                    normal,
                    ["test"],
                    tamper_int=1,
                )
        self.assertEqual(set(), found)

    def test_bypass_detection_records_successful_chain_candidates(self):
        modules = [
            importlib.import_module("content.tampers.randomcase"),
            importlib.import_module("content.tampers.keyword_avoidance"),
        ]
        normal = ("GET /", 200, "normal", {})
        with mock.patch.object(content.ScriptQueue, "load_scripts", return_value=modules):
            with mock.patch("lib.settings.get_page", return_value=("GET /", 200, "ok", {})):
                found = content.get_working_tampers(
                    "https://example.test/?q=",
                    normal,
                    ["select value"],
                    tamper_int=3,
                    tamper_profile="sqli",
                    tamper_chain_depth=2,
                    tamper_chain_budget=1,
                    tamper_seed=7,
                )
        paths = {tamper_engine.tamper_path(item[2]) for item in found}
        self.assertTrue(any("chain[" in path for path in paths))


class NewTamperTests(unittest.TestCase):
    def _load(self, name):
        return importlib.import_module("content.tampers.{}".format(name))

    def test_operator_swap_rewrites_equality_and_booleans(self):
        operator_swap = self._load("operator_swap")
        payload = "' AND 1=1 OR 2>1--"

        between = operator_swap.tamper(payload, strategy=0)
        self.assertIn("BETWEEN 1 AND 1", between)
        self.assertNotIn("1=1", between)

        symbolic = operator_swap.tamper(payload, strategy=1)
        self.assertIn("&&", symbolic)
        self.assertIn("||", symbolic)

        combined = operator_swap.tamper(payload, strategy=3)
        self.assertIn("BETWEEN 1 AND 1 ||", combined)
        self.assertIn("&&", combined)
        # the literal AND introduced by BETWEEN must survive the boolean swap
        self.assertIn("1 BETWEEN 1 AND 1", combined)

    def test_sql_literal_encoders_preserve_leading_injection_quote(self):
        hex_literal = self._load("hex_string_literal")
        char_concat = self._load("char_concat")
        unhex_concat = self._load("unhex_concat")
        payload = "' UNION SELECT 'admin'--"

        self.assertEqual("' UNION SELECT 0x61646d696e--", hex_literal.tamper(payload))
        self.assertEqual("' UNION SELECT CHAR(97,100,109,105,110)--", char_concat.tamper(payload))
        self.assertEqual("' UNION SELECT UNHEX('61646d696e')--", unhex_concat.tamper(payload))

    def test_scientific_notation_rewrites_standalone_integers(self):
        scientific = self._load("scientific_notation")
        self.assertEqual("1e0 AND 1e0=1e0", scientific.tamper("1 AND 1=1"))
        # decimals and hex-literal prefixes stay untouched
        self.assertEqual("1.5", scientific.tamper("1.5"))
        self.assertEqual("0x1f=31e0", scientific.tamper("0x1f=31"))
        self.assertEqual("v2.4", scientific.tamper("v2.4"))

    def test_cmd_obfuscation_variants(self):
        cmd = self._load("cmd_obfuscation")
        self.assertIn("${IFS}", cmd.tamper("whoami && cat /etc/passwd", strategy=0))
        split = cmd.tamper("whoami", strategy=1)
        self.assertTrue('"' in split or "'" in split, split)
        self.assertIn("\\w", cmd.tamper("whoami", strategy=2))
        self.assertEqual("WHOAMI", cmd.tamper("whoami", strategy=3))

    def test_path_traversal_variants_encode_traversal(self):
        path = self._load("path_traversal_obfuscation")
        payload = "../../etc/passwd"
        seen_variants = set()
        for _ in range(40):
            out = path.tamper(payload)
            self.assertNotEqual(payload, out)
            self.assertIn("etc/passwd", out)
            seen_variants.add(out[:8])
        # multiple distinct encodings should be produced, not a single one
        self.assertGreater(len(seen_variants), 3)

    def test_decimal_entities_use_decimal_references(self):
        decimal = self._load("decimal_entities")
        self.assertEqual("&#60;b&#62;", decimal.tamper("<b>"))
        self.assertNotIn("<", decimal.tamper("<script>alert(1)</script>"))

    def test_xss_attribute_injection_splits_tags(self):
        xss_attr = self._load("xss_attribute_injection")
        for _ in range(20):
            out = xss_attr.tamper('<img src=x onerror="alert(1)">')
            self.assertTrue(out.startswith("<img") and not out.startswith("<img "))
            self.assertIn("onerror", out)

    def test_xss_javascript_obfuscation_variants(self):
        js = self._load("xss_javascript_obfuscation")
        payload = "<script>alert(1)</script>"
        hexed = js.tamper(payload, strategy=0)
        self.assertIn("\\x61\\x6c\\x65\\x72\\x74", hexed)
        charcoded = js.tamper(payload, strategy=1)
        self.assertIn("String.fromCharCode", charcoded)
        split = js.tamper(payload, strategy=2)
        self.assertIn("(\n1\n)", split)

    def test_ssti_obfuscation_spaces_and_splits_delimiters(self):
        ssti = self._load("ssti_obfuscation")
        self.assertEqual("{{ 7*7 }}", ssti.tamper("{{7*7}}", strategy=0))
        self.assertEqual("{{7 * 7}}", ssti.tamper("{{7*7}}", strategy=1))
        self.assertIn("\n", ssti.tamper("{{7*7}}", strategy=2))

    def test_new_profiles_resolve_for_payload_types(self):
        self.assertEqual("cmdi", tamper_engine.resolve_profile("auto", "cmdi"))
        self.assertEqual("lfi", tamper_engine.resolve_profile("auto", "lfi"))
        self.assertEqual("ssti", tamper_engine.resolve_profile("auto", "ssti"))
        self.assertEqual("sqli", tamper_engine.resolve_profile("auto", "sqli"))

    def test_new_encoders_are_terminal_and_incompatible(self):
        hex_literal = self._load("hex_string_literal")
        char_concat = self._load("char_concat")
        unhex_concat = self._load("unhex_concat")
        randomcase = self._load("randomcase")
        decimal = self._load("decimal_entities")

        self.assertFalse(
            tamper_engine._valid_chain((hex_literal, char_concat))
        )
        self.assertFalse(
            tamper_engine._valid_chain((unhex_concat, hex_literal))
        )
        self.assertFalse(
            tamper_engine._valid_chain((randomcase, decimal, randomcase))
        )
        self.assertTrue(
            tamper_engine._valid_chain((hex_literal, randomcase))
        )


if __name__ == "__main__":
    unittest.main()
