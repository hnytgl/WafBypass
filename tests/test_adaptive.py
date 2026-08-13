import importlib
import types
import unittest
from unittest import mock

import content
import lib.adaptive
import lib.tamper_engine


def _module(name):
    return importlib.import_module("content.tampers.{}".format(name))


class BlockSignatureTests(unittest.TestCase):
    def _sig(self, text="normal html content here"):
        return lib.adaptive.BlockSignature(("GET /", 200, text, {}))

    def test_static_block_status_is_blocked(self):
        sig = self._sig()
        self.assertEqual("blocked", sig.observe(("", 403, "blocked page", {})))

    def test_normal_response_is_normal(self):
        sig = self._sig()
        self.assertEqual(
            "normal", sig.observe(("", 200, "normal html content here", {}))
        )

    def test_error_and_redirect_are_neutral(self):
        sig = self._sig()
        self.assertEqual("error", sig.observe(("", 0, "", {})))
        self.assertEqual("redirect", sig.observe(("", 302, "", {})))

    def test_marker_words_learn_the_signature(self):
        sig = self._sig()
        # learns the target's block vocabulary from the first marker hit
        self.assertEqual(
            "blocked", sig.observe(("", 200, "Access denied by security policy XYZ-123", {}))
        )
        self.assertTrue(sig._learned)

    def test_learned_signature_classifies_similar_block_page(self):
        sig = self._sig()
        sig.observe(("", 403, "Access denied by security policy XYZ-123", {}))
        # a sibling block page sharing the vocabulary but no marker words
        verdict = sig.observe(
            ("", 418, "security policy XYZ-123 violation detected", {})
        )
        self.assertEqual("blocked", verdict)

    def test_clearly_normal_page_stays_normal_after_learning(self):
        sig = self._sig()
        sig.observe(("", 403, "Access denied by security policy XYZ-123", {}))
        verdict = sig.observe(("", 200, "normal html content here", {}))
        self.assertIn(verdict, ("normal", "ambiguous"))

    def test_likely_blocked_convenience(self):
        sig = self._sig()
        self.assertTrue(sig.likely_blocked(("", 406, "blocked", {})))
        self.assertFalse(sig.likely_blocked(("", 200, "normal html content here", {})))

    def test_unicode_tokens_are_preserved_and_casefolded(self):
        text = "\u8bf7\u6c42\u5df2\u88ab\u62e6\u622a STRASSE \u7248\u672c2"
        tokens = lib.adaptive.BlockSignature._tokenize(text)
        self.assertIn("\u8bf7\u6c42\u5df2\u88ab\u62e6\u622a", tokens)
        self.assertIn("strasse", tokens)
        self.assertIn("\u7248\u672c2", tokens)


class FamilyResolutionTests(unittest.TestCase):
    def test_family_for_resolves_known_and_unknown(self):
        self.assertEqual("case", lib.adaptive.family_for(_module("randomcase")))
        self.assertEqual("encoding", lib.adaptive.family_for(_module("urlencode")))
        fake = types.SimpleNamespace(__name__="content.tampers.no_such_tamper")
        self.assertEqual("generic", lib.adaptive.family_for(fake))

    def test_families_for_chain_resolves_components(self):
        chain = lib.tamper_engine.TamperChain(
            (_module("randomcase"), _module("urlencode"))
        )
        self.assertEqual({"case", "encoding"}, lib.adaptive.families_for(chain))

    def test_family_hints_for_cloudflare(self):
        hints = lib.adaptive.family_hints_for(
            "CloudFlare Web Application Firewall (CloudFlare)"
        )
        self.assertIn("encoding", hints)
        self.assertIn("whitespace", hints)

    def test_family_hints_accepts_a_list(self):
        hints = lib.adaptive.family_hints_for(["ModSecurity", "SafeDog"])
        self.assertIn("comment", hints)
        self.assertIn("unicode", hints)

    def test_family_hints_none_is_empty(self):
        self.assertEqual({}, lib.adaptive.family_hints_for(None))
        self.assertEqual({}, lib.adaptive.family_hints_for([]))


class AdaptiveRankerTests(unittest.TestCase):
    def test_success_marks_family_as_confirmed(self):
        ranker = lib.adaptive.AdaptiveRanker(
            [_module("randomcase"), _module("lowercase")], seed=1
        )
        ranker.record(_module("randomcase"), "bypass", requests=1)
        self.assertIn("case", ranker.confirmed_families())

    def test_block_penalty_is_recorded_not_confirmed(self):
        ranker = lib.adaptive.AdaptiveRanker([_module("randomcase")], seed=1)
        ranker.record(_module("randomcase"), "blocked", requests=1)
        self.assertEqual(1, ranker.family_stats["case"]["blocked"])
        self.assertEqual(set(), ranker.confirmed_families())

    def test_order_excludes_tried_candidates(self):
        ranker = lib.adaptive.AdaptiveRanker(
            [_module("randomcase"), _module("urlencode")], seed=1
        )
        ranker.record(_module("randomcase"), "bypass", requests=1)
        names = [lib.tamper_engine.tamper_name(m) for m in ranker.order()]
        self.assertNotIn("randomcase", names)
        self.assertIn("urlencode", names)

    def test_seeded_order_is_reproducible(self):
        mods = [_module("urlencode"), _module("randomcase"), _module("space2comment")]
        first = lib.adaptive.AdaptiveRanker(mods, seed=42).order()
        second = lib.adaptive.AdaptiveRanker(mods, seed=42).order()
        self.assertEqual(
            [lib.tamper_engine.tamper_name(m) for m in first],
            [lib.tamper_engine.tamper_name(m) for m in second],
        )

    def test_seeded_order_is_stable_on_repeated_calls(self):
        mods = [_module("urlencode"), _module("randomcase"), _module("space2comment")]
        ranker = lib.adaptive.AdaptiveRanker(mods, seed=42)
        first = [lib.tamper_engine.tamper_name(m) for m in ranker.order()]
        second = [lib.tamper_engine.tamper_name(m) for m in ranker.order()]
        self.assertEqual(first, second)

    def test_chain_inherits_component_family_priority(self):
        chain = lib.tamper_engine.TamperChain(
            (_module("randomcase"), _module("urlencode"))
        )
        plain = _module("space2comment")
        ranker = lib.adaptive.AdaptiveRanker(
            [plain, chain], seed=1, family_priorities={"encoding": 3}
        )
        self.assertIs(chain, ranker.order()[0])

    def test_diversity_bonus_prefers_untried_families(self):
        ranker = lib.adaptive.AdaptiveRanker(
            [_module("randomcase"), _module("lowercase"), _module("urlencode")],
            seed=None,
        )
        # blocking randomcase penalizes its family; urlencode stays untouched
        ranker.record(_module("randomcase"), "blocked", requests=1)
        ordered = [lib.tamper_engine.tamper_name(m) for m in ranker.order()]
        # lowercase shares the penalized 'case' family, urlencode does not
        self.assertLess(ordered.index("urlencode"), ordered.index("lowercase"))


class ConfidenceTests(unittest.TestCase):
    def test_single_consistent_product_is_full_confidence(self):
        self.assertEqual(1.0, lib.adaptive.waf_confidence({"Cloudflare": 4}, 4))

    def test_competing_products_reduce_confidence(self):
        single = lib.adaptive.waf_confidence({"A": 2}, 2)
        competing = lib.adaptive.waf_confidence({"A": 1, "B": 1}, 2)
        self.assertGreater(single, competing)

    def test_no_matches_zero_confidence(self):
        self.assertEqual(0.0, lib.adaptive.waf_confidence({}, 4))
        self.assertEqual(0.0, lib.adaptive.waf_confidence({"A": 1}, 0))


class AdaptiveIntegrationTests(unittest.TestCase):
    def test_early_stop_after_target_families_confirmed(self):
        # four candidates across four distinct families; only three are
        # required, so the sweep stops before exhausting the candidate set.
        candidates = [
            _module("randomcase"),        # case
            _module("urlencode"),         # encoding
            _module("space2comment"),     # whitespace
            _module("keyword_avoidance"), # keyword (left untried)
        ]
        normal = ("GET /", 200, "normal", {})
        stats = lib.adaptive.AdaptiveStats()
        with mock.patch.object(content.ScriptQueue, "load_scripts", return_value=candidates):
            with mock.patch("lib.settings.get_page", return_value=("GET /", 200, "ok", {})):
                found = content.get_working_tampers(
                    "https://example.test/?q=",
                    normal,
                    ["select value"],
                    tamper_int=10,
                    adaptive_bypass=True,
                    bypass_families=3,
                    adaptive_stats=stats,
                )
        self.assertEqual(3, len(found))
        self.assertEqual(3, len(stats.families_bypassed))
        self.assertEqual(3, stats.candidates_tried)
        self.assertTrue(stats.early_stopped)

    def test_blocked_candidates_are_not_recorded(self):
        candidates = [_module("urlencode")]
        normal = ("GET /", 200, "normal", {})
        with mock.patch.object(content.ScriptQueue, "load_scripts", return_value=candidates):
            with mock.patch("lib.settings.get_page", return_value=("GET /", 403, "blocked", {})):
                found = content.get_working_tampers(
                    "https://example.test/?q=",
                    normal,
                    ["select value"],
                    tamper_int=5,
                    adaptive_bypass=True,
                )
        self.assertEqual(set(), found)

    def test_non_adaptive_mode_preserves_old_behavior(self):
        candidates = [_module("urlencode")]
        normal = ("GET /", 200, "normal", {})
        with mock.patch.object(content.ScriptQueue, "load_scripts", return_value=candidates):
            with mock.patch("lib.settings.get_page", return_value=("GET /", 200, "ok", {})):
                found = content.get_working_tampers(
                    "https://example.test/?q=",
                    normal,
                    ["select value"],
                    tamper_int=5,
                    adaptive_bypass=False,
                )
        self.assertEqual(1, len(found))


if __name__ == "__main__":
    unittest.main()
