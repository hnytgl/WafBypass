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
        self.assertGreaterEqual(len(modules), 64)
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


if __name__ == "__main__":
    unittest.main()
