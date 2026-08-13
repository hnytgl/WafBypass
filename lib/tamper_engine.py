import hashlib
import itertools
import random


TAMPER_PROFILES = {
    "balanced": [
        "keyword_avoidance",
        "whitespace_variation",
        "space2comment",
        "randomcase",
        "unicode_normalize",
        "unicode_fullwidth",
        "randomhexcase",
        "space2newline",
        "urlencode",
        "doubleurlencode",
    ],
    "sqli": [
        "keyword_avoidance",
        "sql_versioned_keywords",
        "operator_swap",
        "booleanmask",
        "sql_numeric_bypass",
        "scientific_notation",
        "sql_comment_fragment",
        "nested_comment_fragment",
        "hex_string_literal",
        "char_concat",
        "unhex_concat",
        "space2comment",
        "space2randomblank",
        "space2urlencode",
        "space2newline",
        "randomcase",
        "randomhexcase",
        "urlencode",
        "doubleurlencode",
    ],
    "xss": [
        "xss_vector_variation",
        "xss_javascript_obfuscation",
        "xss_attribute_injection",
        "obfuscatebyhtmlcomment",
        "randomcase",
        "unicode_normalize",
        "unicode_fullwidth",
        "obfuscatebyhtmlentity",
        "html_hex_entities",
        "decimal_entities",
        "space2newline",
        "urlencode",
        "doubleurlencode",
    ],
    "encoding": [
        "randomcase",
        "unicode_normalize",
        "unicode_fullwidth",
        "obfuscatebyhtmlentity",
        "html_hex_entities",
        "decimal_entities",
        "unicode_escape",
        "selective_urlencode",
        "randomhexcase",
        "space2urlencode",
        "urlencode",
        "urlencodeall",
        "doubleurlencode",
        "tripleurlencode",
    ],
    "cmdi": [
        "cmd_obfuscation",
        "randomcase",
        "uppercase",
        "lowercase",
        "space2plus",
        "space2urlencode",
        "space2newline",
        "randomwildcard",
        "randomjunkcharacters",
        "randomdecoys",
    ],
    "lfi": [
        "path_traversal_obfuscation",
        "overlong_utf8",
        "appendnull",
        "prependnull",
        "urlencode",
        "doubleurlencode",
    ],
    "ssti": [
        "ssti_obfuscation",
        "randomcase",
        "unicode_normalize",
        "obfuscatebyhtmlentity",
        "space2comment",
        "urlencode",
        "doubleurlencode",
    ],
}

PAYLOAD_PROFILE_MAP = {
    "sqli": "sqli",
    "xss": "xss",
    "xxe": "encoding",
    "ssti": "ssti",
    "lfi": "lfi",
    "cmdi": "cmdi",
}

# These scripts change the transport or full request shape rather than only the
# payload text. They remain available as standalone tampers but are deliberately
# excluded from automatic chains.
NON_CHAINABLE_TAMPERS = {
    "buffer_overflow",
    "chunked_transfer",
    "content_type_bypass",
    "crlf_injection",
    "hpp",
    "hpp_split",
    "json_encoding",
    "method_tamper",
    "multipart_fragment",
    "param_fragment",
    "pipeline_fragment",
    "reverse_encoding",
    "xml_encoding",
}

# Full encoders should terminate a chain; applying lexical transforms after
# them generally mutates encoded data instead of the intended payload.
TERMINAL_TAMPERS = {
    "base64encode",
    "decimal_entities",
    "doubleurlencode",
    "nested_encoding",
    "tripleurlencode",
    "unicode_escape",
    "urlencode",
    "urlencodeall",
    "selective_urlencode",
}

INCOMPATIBLE_GROUPS = (
    {"keyword_avoidance", "sql_versioned_keywords"},
    {"space2comment", "space2randomblank", "whitespace_variation", "space2newline"},
    {"obfuscatebyhtmlentity", "html_hex_entities", "decimal_entities"},
    {"hex_string_literal", "char_concat", "unhex_concat"},
    {"lowercase", "randomcase", "uppercase"},
)

STAGE_WEIGHTS = {
    "keyword_avoidance": 10,
    "sql_versioned_keywords": 10,
    "operator_swap": 15,
    "sql_numeric_bypass": 15,
    "booleanmask": 15,
    "scientific_notation": 25,
    "sql_comment_fragment": 20,
    "hex_string_literal": 20,
    "char_concat": 20,
    "unhex_concat": 20,
    "xss_vector_variation": 10,
    "xss_javascript_obfuscation": 30,
    "xss_attribute_injection": 35,
    "cmd_obfuscation": 35,
    "ssti_obfuscation": 30,
    "path_traversal_obfuscation": 30,
    "obfuscatebyhtmlcomment": 20,
    "nested_comment_fragment": 20,
    "randomcase": 30,
    "lowercase": 30,
    "uppercase": 30,
    "unicode_normalize": 40,
    "unicode_fullwidth": 40,
    "randomhexcase": 45,
    "space2newline": 50,
    "whitespace_variation": 50,
    "space2comment": 50,
    "space2randomblank": 50,
    "space2urlencode": 40,
    "obfuscatebyhtmlentity": 70,
    "html_hex_entities": 70,
    "decimal_entities": 70,
    "unicode_escape": 80,
    "selective_urlencode": 90,
    "urlencode": 100,
    "urlencodeall": 100,
    "doubleurlencode": 110,
    "tripleurlencode": 120,
    "nested_encoding": 120,
    "base64encode": 130,
}


def tamper_name(tamper):
    name = getattr(tamper, "__name__", tamper.__class__.__name__)
    return str(name).split(".")[-1]


def tamper_path(tamper):
    return getattr(tamper, "__name__", str(tamper))


def resolve_profile(profile, payload_type="all"):
    if profile in (None, "auto"):
        return PAYLOAD_PROFILE_MAP.get(payload_type, "balanced")
    return profile


def available_profiles():
    return {
        name: tuple("content.tampers.{}".format(item) for item in tampers)
        for name, tampers in sorted(TAMPER_PROFILES.items())
    }


def _stable_seed(seed, candidate, payload, variant):
    material = "{}\0{}\0{}\0{}".format(
        seed, tamper_path(candidate), payload, variant
    ).encode("utf-8", errors="replace")
    return int(hashlib.sha256(material).hexdigest()[:16], 16)


def apply_candidate(candidate, payload, seed=None, variant=0):
    if isinstance(candidate, TamperChain):
        return candidate.tamper(payload, seed=seed, variant=variant)
    if seed is None:
        return candidate.tamper(payload)

    previous_state = random.getstate()
    random.seed(_stable_seed(seed, candidate, payload, variant))
    try:
        return candidate.tamper(payload)
    finally:
        random.setstate(previous_state)


class TamperChain(object):
    def __init__(self, tampers, seed=None):
        self.tampers = tuple(tampers)
        self.seed = seed
        short_names = [tamper_name(tamper) for tamper in self.tampers]
        self.__name__ = "content.tampers.chain[{}]".format("+".join(short_names))
        self.__type__ = "tamper chain: {}".format(" -> ".join(short_names))
        example = getattr(self.tampers[0], "__example_payload__", "test")
        self.__example_payload__ = self.tamper(example)

    def tamper(self, payload, **kwargs):
        transformed = payload
        chain_seed = kwargs.get("seed", self.seed)
        base_variant = int(kwargs.get("variant", 0))
        for index, tamper in enumerate(self.tampers):
            transformed = apply_candidate(
                tamper,
                transformed,
                seed=chain_seed,
                variant=(base_variant * len(self.tampers)) + index,
            )
        return transformed

    def __repr__(self):
        return self.__name__

    __str__ = __repr__


def _valid_chain(tampers):
    names = [tamper_name(tamper) for tamper in tampers]
    if len(set(names)) != len(names):
        return False
    if any(name in NON_CHAINABLE_TAMPERS for name in names):
        return False
    if any(len(set(names).intersection(group)) > 1 for group in INCOMPATIBLE_GROUPS):
        return False
    return not any(name in TERMINAL_TAMPERS for name in names[:-1])


def _chain_score(tampers, profile_names):
    names = [tamper_name(tamper) for tamper in tampers]
    profile_index = {
        name: index
        for index, name in enumerate(profile_names)
    }
    stage_score = sum(
        abs(STAGE_WEIGHTS.get(names[index], 60) - (index * 40))
        for index in range(len(names))
    )
    profile_score = sum(profile_index.get(name, 99) for name in names)
    terminal_bonus = -20 if names[-1] in TERMINAL_TAMPERS else 0
    return (stage_score + profile_score + terminal_bonus, len(names), "+".join(names))


def build_chain_candidates(
    loaded_tampers,
    profile="auto",
    payload_type="all",
    max_depth=1,
    budget=24,
    seed=None,
):
    if max_depth <= 1 or budget <= 0:
        return []

    selected_profile = resolve_profile(profile, payload_type)
    profile_names = TAMPER_PROFILES.get(selected_profile)
    if profile_names is None:
        raise ValueError("unknown tamper profile '{}'".format(selected_profile))

    loaded_by_name = {tamper_name(tamper): tamper for tamper in loaded_tampers}
    ordered = [
        loaded_by_name[name]
        for name in profile_names
        if name in loaded_by_name and name not in NON_CHAINABLE_TAMPERS
    ]

    candidates = []
    seen = set()
    max_depth = min(max(int(max_depth), 2), 3)
    for depth in range(2, max_depth + 1):
        for combination in itertools.permutations(ordered, depth):
            names = tuple(tamper_name(tamper) for tamper in combination)
            if names in seen:
                continue
            seen.add(names)
            if _valid_chain(combination):
                candidates.append(combination)

    ranked = sorted(
        candidates,
        key=lambda candidate: _chain_score(candidate, profile_names),
    )
    return [
        TamperChain(candidate, seed=seed)
        for candidate in ranked[:budget]
    ]
