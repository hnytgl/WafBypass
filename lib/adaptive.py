"""
lib.adaptive -- adaptive intelligence for the WAFBypass engine.

This module turns the static bypass loop into a feedback-driven one:

* ``BlockSignature`` learns what the *target's* block page looks like (status
  codes, text tokens, relative length) and classifies later probe responses
  as blocked / normal / ambiguous / error / redirect.
* ``AdaptiveRanker`` orders tamper candidates by a live score that combines
  per-WAF family hints, tamper stage weights, observed success, observed
  block signals and family diversity, and re-ranks candidates after every
  batch of requests.
* ``AdaptiveStats`` records coverage so the caller can emit JSON / HTML
  intelligence sections.

The module is pure stdlib and keeps all randomness on its own
``random.Random`` instance so seeded runs stay reproducible without touching
the global RNG used by ``lib.tamper_engine.apply_candidate``.
"""

import hashlib
import random
import re

import lib.tamper_engine


# Status codes that are strong static signals of a block page.
BLOCK_STATUS_SEED = (400, 403, 406, 429, 502, 503)

# 3xx responses are redirects -- neither a block signal nor a bypass.
REDIRECT_STATUS = range(300, 400)

# Word-boundary markers seeded from the historic static failure list. These
# are intentionally word-boundary anchored so plain "404" text in a normal
# page is not treated as a block.
WORD_BLOCK_MARKERS = (
    re.compile(r"\bblocked\b", re.I),
    re.compile(r"\bforbidden\b", re.I),
    re.compile(r"\bdenied\b", re.I),
    re.compile(r"access\s+denied", re.I),
    re.compile(r"\bcaptcha\b", re.I),
    re.compile(r"\billegal\b", re.I),
    re.compile(r"not\s+acceptable", re.I),
    re.compile(r"request\s+was\s+rejected", re.I),
    re.compile(r"ip\s+address\s+logged", re.I),
)

# Technique family per tamper script. ``__category__`` on tampers is the
# *payload* category (sqli/xss/...); this dict is the *technique* family used
# by the adaptive ranker for diversity and per-WAF targeting.
FAMILY_BY_TAMPER = {
    # encoding -- encoders, escape and entity transforms
    "base64encode": "encoding",
    "urlencode": "encoding",
    "urlencodeall": "encoding",
    "doubleurlencode": "encoding",
    "tripleurlencode": "encoding",
    "selective_urlencode": "encoding",
    "nested_encoding": "encoding",
    "encoding_chain": "encoding",
    "reverse_encoding": "encoding",
    "json_encoding": "encoding",
    "hex_encoding": "encoding",
    "decimal_entities": "encoding",
    "html_hex_entities": "encoding",
    "obfuscatebyhtmlentity": "encoding",
    "obfuscatebyordinal": "encoding",
    "unicode_escape": "encoding",
    "randomhexcase": "encoding",
    # whitespace -- blank / separator variation
    "space2comment": "whitespace",
    "space2randomblank": "whitespace",
    "space2urlencode": "whitespace",
    "space2doubledash": "whitespace",
    "space2hash": "whitespace",
    "space2multicomment": "whitespace",
    "space2null": "whitespace",
    "space2plus": "whitespace",
    "randomtabify": "whitespace",
    "tabifyspacecommon": "whitespace",
    "tabifyspaceuncommon": "whitespace",
    "whitespace_variation": "whitespace",
    "space2newline": "whitespace",
    # case -- character case transforms
    "randomcase": "case",
    "lowercase": "case",
    "uppercase": "case",
    # comment -- comment-block injection
    "sql_versioned_keywords": "comment",
    "double_sql_comment": "comment",
    "obfuscatebyhtmlcomment": "comment",
    "randomcomments": "comment",
    "modsec": "comment",
    "modsecspace2comment": "comment",
    "nested_comment_fragment": "comment",
    # keyword -- keyword rewriting / avoidance
    "keyword_avoidance": "keyword",
    "booleanmask": "keyword",
    "enclosebrackets": "keyword",
    "maskenclosebrackets": "keyword",
    "randomwildcard": "keyword",
    # operator -- SQL operator substitution
    "operator_swap": "operator",
    # literal -- string literal / quote handling
    "char_concat": "literal",
    "hex_string_literal": "literal",
    "unhex_concat": "literal",
    "escapequotes": "literal",
    "apostrephemask": "literal",
    "apostrephenullify": "literal",
    "appendnull": "literal",
    "prependnull": "literal",
    # numeric -- numeric literal rewriting
    "scientific_notation": "numeric",
    "sql_numeric_bypass": "numeric",
    # cmdpath -- command / path traversal obfuscation
    "cmd_obfuscation": "cmdpath",
    "path_traversal_obfuscation": "cmdpath",
    # ssti / xss -- template and script injection specific
    "ssti_obfuscation": "ssti",
    "xss_vector_variation": "xss",
    "xss_attribute_injection": "xss",
    "xss_javascript_obfuscation": "xss",
    # unicode -- unicode normalization / confusables / overlong encodings
    "unicode_normalize": "unicode",
    "randomunicode": "unicode",
    "overlong_utf8": "unicode",
    "unicode_fullwidth": "unicode",
    # fragment -- payload / request fragmentation (mostly non-chainable)
    "sql_comment_fragment": "fragment",
    "crlf_injection": "fragment",
    "hpp": "fragment",
    "hpp_split": "fragment",
    "multipart_fragment": "fragment",
    "param_fragment": "fragment",
    "pipeline_fragment": "fragment",
    "null_byte_fragment": "fragment",
    # generic -- transport / junk / misc
    "buffer_overflow": "generic",
    "chunked_transfer": "generic",
    "content_type_bypass": "generic",
    "method_tamper": "generic",
    "xml_encoding": "generic",
    "randomdecoys": "generic",
    "randomjunkcharacters": "generic",
}

# Detected WAF products (matched case-insensitively as substrings of the
# plugin ``__product__``) mapped to the technique families most likely to
# defeat their signature matching. Seeded into the ranker as base priorities.
WAF_TAMPER_HINTS = {
    "cloudflare": ("encoding", "keyword", "whitespace"),
    "modsecurity": ("comment", "case", "keyword"),
    "safedog": ("unicode", "keyword", "whitespace"),
    "aliyun": ("encoding", "literal", "whitespace"),
    "yundun": ("encoding", "literal"),
    "360": ("keyword", "whitespace"),
    "bigip": ("case", "comment"),
    "f5": ("case", "comment"),
    "barracuda": ("whitespace", "encoding"),
    "incapsula": ("encoding", "keyword"),
    "imperva": ("encoding", "keyword"),
    "akamai": ("whitespace", "encoding"),
    "siteguard": ("keyword", "case"),
    "dotdefender": ("encoding", "literal"),
    "sucuri": ("encoding", "case"),
    "tencentwaf": ("encoding", "whitespace"),
    "yunsuo": ("keyword", "case"),
    "wordfence": ("case", "keyword"),
    "naxsi": ("case", "comment"),
    "huawei": ("encoding", "whitespace"),
}


class BlockSignature(object):
    """Learn the target's block-page signature and classify responses."""

    MIN_BLOCK_SIM = 0.35
    MAX_LEN_DELTA = 0.5

    def __init__(self, normal_response):
        _, status, html, _ = normal_response
        self.normal_status = status
        self.normal_text = str(html)
        self.normal_len = len(self.normal_text)
        self.normal_tokens = self._tokenize(self.normal_text)
        self.block_statuses = set()
        self.block_tokens = None
        self.block_len = None
        self._learned = False

    @staticmethod
    def _tokenize(text):
        # Unicode-aware alphanumeric tokens; avoids encoding-corrupted ranges.
        return set(re.findall(r"[^\W_]+", str(text).casefold(), re.UNICODE))

    @staticmethod
    def _sim(a, b):
        if not a or not b:
            return 0.0
        union = len(a | b)
        return len(a & b) / union if union else 0.0

    def _learn(self, status, text):
        self.block_statuses.add(status)
        self.block_tokens = self._tokenize(text)
        self.block_len = len(text)
        self._learned = True

    def observe(self, response):
        """Classify one probe response.

        Returns one of: ``blocked``, ``normal``, ``ambiguous``, ``error``
        (status 0, transient network issue) or ``redirect`` (3xx).
        """
        _, status, html, _ = response
        text = str(html)
        if not status:
            return "error"
        if status in REDIRECT_STATUS:
            return "redirect"
        if status in BLOCK_STATUS_SEED:
            if not self._learned:
                self._learn(status, text)
            return "blocked"
        if any(marker.search(text) for marker in WORD_BLOCK_MARKERS):
            if not self._learned:
                self._learn(status, text)
            return "blocked"
        if self._learned:
            tokens = self._tokenize(text)
            block_sim = self._sim(tokens, self.block_tokens)
            normal_sim = self._sim(tokens, self.normal_tokens)
            length_delta = abs(len(text) - self.block_len) / max(self.block_len, 1)
            if block_sim >= self.MIN_BLOCK_SIM and block_sim > normal_sim and length_delta < self.MAX_LEN_DELTA:
                return "blocked"
            if normal_sim >= self.MIN_BLOCK_SIM and normal_sim > block_sim:
                return "normal"
            return "ambiguous"
        return "normal"

    def likely_blocked(self, response):
        return self.observe(response) == "blocked"


def family_for(candidate):
    """Resolve one tamper module / chain to its technique family."""
    if isinstance(candidate, lib.tamper_engine.TamperChain):
        return "chain"
    return FAMILY_BY_TAMPER.get(
        lib.tamper_engine.tamper_name(candidate), "generic"
    )


def families_for(candidate):
    """Resolve a candidate to the set of technique families it exercises."""
    if isinstance(candidate, lib.tamper_engine.TamperChain):
        return {
            FAMILY_BY_TAMPER.get(lib.tamper_engine.tamper_name(t), "generic")
            for t in candidate.tampers
        }
    return {family_for(candidate)}


def family_hints_for(detected_protections):
    """Return ``{family: hits}`` for the given detected WAF product(s).

    Accepts a string or an iterable of product names and matches the
    ``WAF_TAMPER_HINTS`` keys as case-insensitive substrings.
    """
    if not detected_protections:
        return {}
    if isinstance(detected_protections, str):
        detected_protections = [detected_protections]
    hints = {}
    for product in detected_protections:
        lowered = str(product).lower()
        for key, families in WAF_TAMPER_HINTS.items():
            if key in lowered:
                for fam in families:
                    hints[fam] = hints.get(fam, 0) + 1
    return hints


class AdaptiveRanker(object):
    """Feedback-driven ordering of tamper candidates."""

    SUCCESS_BOOST = 30.0
    CONFIRMED_BOOST = 60.0
    BLOCK_PENALTY = 40.0
    DIVERSITY_BONUS = 25.0
    HINT_WEIGHT = 25.0

    def __init__(self, candidates, seed=None, family_priorities=None):
        self.seed = seed
        self.candidates = list(candidates)
        # Track tried candidates by identity: tamper modules and chains are
        # hashable in production, but tests sometimes pass unhashable stand-ins.
        self.tried = set()
        self.family_priorities = dict(family_priorities or {})
        self.family_stats = {}
        self.requests_made = 0

    def _jitter(self, candidate):
        """Return a stable tie-break for seeded runs."""
        if self.seed is None:
            return random.random() * 0.01
        material = "{}\0{}".format(
            self.seed, lib.tamper_engine.tamper_path(candidate)
        ).encode("utf-8", errors="replace")
        value = int(hashlib.sha256(material).hexdigest()[:16], 16)
        return (value / float(0xFFFFFFFFFFFFFFFF)) * 0.01

    def _stats(self, family):
        return self.family_stats.setdefault(family, {
            "tried": 0, "bypass": 0, "blocked": 0, "normal": 0, "error": 0,
        })

    def _base_score(self, candidate):
        families = families_for(candidate)
        hint = sum(self.family_priorities.get(family, 0) for family in families)
        hint = (hint / max(len(families), 1)) * self.HINT_WEIGHT
        components = (
            candidate.tampers
            if isinstance(candidate, lib.tamper_engine.TamperChain)
            else (candidate,)
        )
        stages = [
            lib.tamper_engine.STAGE_WEIGHTS.get(
                lib.tamper_engine.tamper_name(component), 60
            )
            for component in components
        ]
        stage = sum(stages) / len(stages)
        return hint + (100 - min(stage, 100)) / 4.0

    def score(self, candidate):
        families = families_for(candidate)
        family_stats = [self._stats(family) for family in families]
        bypasses = sum(stats["bypass"] for stats in family_stats) / len(family_stats)
        blocked = sum(stats["blocked"] for stats in family_stats) / len(family_stats)
        tried = sum(stats["tried"] for stats in family_stats) / len(family_stats)
        total = self.SUCCESS_BOOST * bypasses
        total += self.CONFIRMED_BOOST if bypasses else 0.0
        total -= self.BLOCK_PENALTY * blocked
        if tried == 0:
            total += self.DIVERSITY_BONUS
        else:
            total += max(0.0, self.DIVERSITY_BONUS - tried)
        # deterministic tie-break so seeded runs are fully reproducible
        total += self._jitter(candidate)
        return self._base_score(candidate) + total

    def order(self, batch_size=None):
        remaining = [c for c in self.candidates if id(c) not in self.tried]
        remaining.sort(key=self.score, reverse=True)
        return remaining[:batch_size] if batch_size else remaining

    def record(self, candidate, outcome, requests=0):
        self.tried.add(id(candidate))
        self.requests_made += requests
        for family in families_for(candidate):
            stats = self._stats(family)
            stats["tried"] += 1
            stats[outcome] = stats.get(outcome, 0) + 1

    def confirmed_families(self):
        return {
            family for family, stats in self.family_stats.items()
            if stats["bypass"] > 0
        }


class AdaptiveStats(object):
    """Coverage statistics emitted into JSON / HTML intelligence sections."""

    def __init__(self):
        self.families_tried = set()
        self.families_bypassed = set()
        self.total_families = 0
        self.requests_made = 0
        self.candidates_tried = 0
        self.early_stopped = False

    def to_dict(self):
        return {
            "families_tried": sorted(self.families_tried),
            "families_bypassed": sorted(self.families_bypassed),
            "total_families": self.total_families,
            "requests_made": self.requests_made,
            "candidates_tried": self.candidates_tried,
            "early_stopped": self.early_stopped,
        }


def build_strategy(stats, confidence):
    """Human readable summary of the adaptive run for reports / JSON."""
    if stats is None:
        return ""
    parts = [
        "adaptive bypass ranking: {} candidates across {} families".format(
            stats.candidates_tried, stats.total_families
        )
    ]
    parts.append("requests made: {}".format(stats.requests_made))
    parts.append("confirmed bypass families: {}".format(
        ", ".join(sorted(stats.families_bypassed)) or "none"
    ))
    if stats.early_stopped:
        parts.append("early stop after {} families".format(
            len(stats.families_bypassed)
        ))
    parts.append("waf identification confidence: {:.0%}".format(confidence))
    return "; ".join(parts)


def waf_confidence(match_counts, probe_count, statuses_by_product=None):
    """0..1 confidence in the WAF identification.

    ``match_counts`` maps product -> number of probes that matched it,
    ``probe_count`` is the total number of probes made, and
    ``statuses_by_product`` (optional) maps product -> set of observed status
    codes. Rewards probe consistency, few competing products and stable
    status codes.
    """
    statuses_by_product = statuses_by_product or {}
    if not match_counts or not probe_count:
        return 0.0
    top_product = max(match_counts, key=match_counts.get)
    coverage = match_counts[top_product] / float(probe_count)
    unanimity = 1.0 / len(match_counts)
    statuses = statuses_by_product.get(top_product, set())
    status_agreement = 1.0 if len(statuses) <= 1 else 0.5
    confidence = 0.55 * coverage + 0.25 * unanimity + 0.2 * status_agreement
    return round(min(1.0, confidence), 3)
