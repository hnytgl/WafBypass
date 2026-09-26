"""
lib.signature_loader -- Declarative YAML signature engine for WAF detection.

Replaces dynamic Python plugin imports with auditable, hot-updatable YAML rules.
Zero code execution: signatures are pure data (regex patterns + field mappings).

Usage:
    from lib.signature_loader import SignatureEngine
    engine = SignatureEngine()
    engine.load_builtin()
    engine.load_user()
    results = engine.detect(content, headers, status)
"""

import os
import re

import lib.formatter

try:
    import yaml
except ImportError:
    yaml = None

# Project root
_CUR_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BUILTIN_SIGNATURES_DIR = os.path.join(_CUR_DIR, "signatures")
_HOME = os.path.join(os.path.expanduser("~"), ".wafbypass")
_USER_SIGNATURES_DIR = os.path.join(_HOME, "signatures")

# Well-known header field aliases (lowercase YAML field -> actual header name)
FIELD_ALIASES = {
    "body": None,  # special: matches against response body
    "server": "Server",
    "set-cookie": "Set-Cookie",
    "cookie": "Cookie",
    "x-powered-by": "X-Powered-By",
    "via": "Via",
    "x-cache": "X-Cache",
    "location": "Location",
    "expect-ct": "Expect-CT",
    "cf-ray": "CF-RAY",
    "x-server": "X-Server",
    "x-backside-transport": "X-Backside-Transport",
    "gw-server": "GW-Server",
    "all_headers": None,  # special: iterate all headers
}

# Regex flag string -> re flags
_FLAG_MAP = {
    "i": re.IGNORECASE,
    "m": re.MULTILINE,
    "s": re.DOTALL,
}


class DetectionResult:
    """Result of a successful WAF detection."""

    __slots__ = ("product", "signature_file", "confidence", "tamper_hints", "tags")

    def __init__(self, product, signature_file="", confidence="medium",
                 tamper_hints=None, tags=None):
        self.product = product
        self.signature_file = signature_file
        self.confidence = confidence
        self.tamper_hints = tamper_hints or []
        self.tags = tags or []

    def __repr__(self):
        return "DetectionResult(product={!r}, confidence={!r})".format(
            self.product, self.confidence
        )


class CompiledSignature:
    """A single YAML signature with pre-compiled regex patterns."""

    def __init__(self, data, filepath=""):
        self.product = data["product"]
        self.filepath = filepath
        self.confidence = data.get("confidence", "medium")
        self.tamper_hints = data.get("tamper_hints", [])
        self.tags = data.get("tags", [])
        self.vendor = data.get("vendor", "")
        self.version = data.get("version", "")

        detection = data.get("detection", {})
        self.header_presence = detection.get("header_presence", [])
        self.match_all_headers = detection.get("match_all_headers", False)

        # Compile patterns
        self.patterns = [
            self._compile_pattern(p) for p in detection.get("patterns", [])
        ]
        self.contains = detection.get("contains", [])
        self.status_rules = [
            self._compile_status_rule(r) for r in detection.get("status_rules", [])
        ]
        self.conditional = [
            self._compile_conditional(c) for c in detection.get("conditional", [])
        ]

    @staticmethod
    def _parse_flags(flags_str):
        """Parse flag string like 'i', 'im', 'is' into re flags."""
        if not flags_str:
            return re.IGNORECASE  # default
        result = 0
        for ch in str(flags_str).lower():
            result |= _FLAG_MAP.get(ch, 0)
        return result

    def _compile_pattern(self, pattern_def):
        """Compile a single pattern definition."""
        regex = re.compile(pattern_def["regex"], self._parse_flags(pattern_def.get("flags", "i")))
        return {
            "regex": regex,
            "fields": pattern_def.get("fields", ["body"]),
            "negate": pattern_def.get("negate", False),
        }

    def _compile_status_rule(self, rule_def):
        """Compile a status-conditional rule."""
        return {
            "status": set(rule_def.get("status", [])),
            "patterns": [self._compile_pattern(p) for p in rule_def.get("patterns", [])],
            "contains": rule_def.get("contains", []),
        }

    def _compile_conditional(self, cond_def):
        """Compile a conditional (if_header) rule."""
        return {
            "if_header": cond_def["if_header"],
            "patterns": [self._compile_pattern(p) for p in cond_def.get("patterns", [])],
        }

    def match(self, content, headers, status):
        """
        Execute detection logic against a response.

        Args:
            content: response body as string
            headers: dict of response headers (case-insensitive lookup)
            status: HTTP status code (int)

        Returns:
            True if this signature matches the response.
        """
        content_str = str(content) if content else ""
        headers_lower = {k.lower(): v for k, v in (headers or {}).items()}

        # 1. Header presence check (fastest, O(1) per header)
        for hdr in self.header_presence:
            value = headers_lower.get(hdr.lower(), "")
            if value:
                return True

        # 2. Main patterns
        for pat in self.patterns:
            if self._match_pattern(pat, content_str, headers_lower):
                return True

        # 3. Contains checks
        for cont in self.contains:
            if self._match_contains(cont, content_str, headers_lower):
                return True

        # 4. Status-conditional rules
        if status:
            for rule in self.status_rules:
                if status in rule["status"]:
                    for pat in rule["patterns"]:
                        if self._match_pattern(pat, content_str, headers_lower):
                            return True
                    for cont in rule["contains"]:
                        if self._match_contains(cont, content_str, headers_lower):
                            return True

        # 5. Conditional rules (if_header present → check patterns)
        for cond in self.conditional:
            hdr_value = headers_lower.get(cond["if_header"].lower(), "")
            if hdr_value:
                for pat in cond["patterns"]:
                    if self._match_pattern(pat, content_str, headers_lower):
                        return True

        return False

    def _match_pattern(self, pat, content_str, headers_lower):
        """Check a compiled pattern against its specified fields."""
        regex = pat["regex"]
        negate = pat["negate"]
        found = False

        for field in pat["fields"]:
            if field == "body":
                if regex.search(content_str):
                    found = True
                    break
            elif field == "all_headers":
                # Match against all header keys and values
                for key, value in headers_lower.items():
                    if regex.search(str(key)) or regex.search(str(value)):
                        found = True
                        break
                if found:
                    break
            else:
                # Specific header field
                header_name = FIELD_ALIASES.get(field, field)
                if header_name is None:
                    header_name = field
                value = headers_lower.get(header_name.lower(), "")
                if not value:
                    # Try original field name as-is
                    value = headers_lower.get(field.lower(), "")
                if value and regex.search(str(value)):
                    found = True
                    break

        if negate:
            return not found
        return found

    def _match_contains(self, cont, content_str, headers_lower):
        """Check a contains rule."""
        value = cont["value"]
        field = cont["field"]
        case_sensitive = cont.get("case_sensitive", False)

        if field == "body":
            target = content_str
        elif field == "all_headers":
            target = " ".join(str(v) for v in headers_lower.values())
        else:
            header_name = FIELD_ALIASES.get(field, field)
            if header_name is None:
                header_name = field
            target = headers_lower.get(header_name.lower(), "")
            if not target:
                target = headers_lower.get(field.lower(), "")

        if not target:
            return False

        if case_sensitive:
            return value in str(target)
        return value.lower() in str(target).lower()


class SignatureEngine:
    """
    Loads, compiles and executes YAML-based WAF detection signatures.

    Load order (later overrides earlier for same product name):
      1. Built-in signatures (signatures/ directory)
      2. User signatures (~/.wafbypass/signatures/)
    """

    def __init__(self, verbose=False):
        self.signatures = []  # list of CompiledSignature
        self._by_product = {}  # product name -> CompiledSignature
        self.verbose = verbose
        self._load_errors = []

    @property
    def count(self):
        return len(self.signatures)

    @property
    def products(self):
        return list(self._by_product.keys())

    def load_builtin(self):
        """Load signatures from the built-in signatures/ directory."""
        if os.path.isdir(_BUILTIN_SIGNATURES_DIR):
            self._load_directory(_BUILTIN_SIGNATURES_DIR)

    def load_user(self):
        """Load user signatures from ~/.wafbypass/signatures/ (overrides built-in)."""
        if os.path.isdir(_USER_SIGNATURES_DIR):
            self._load_directory(_USER_SIGNATURES_DIR)

    def load_directory(self, path):
        """Load signatures from an arbitrary directory."""
        if os.path.isdir(path):
            self._load_directory(path)

    def _load_directory(self, path):
        """Load all .yaml/.yml files from a directory."""
        if yaml is None:
            lib.formatter.warn(
                "PyYAML not installed, cannot load YAML signatures. "
                "Install with: pip install pyyaml"
            )
            return

        loaded = 0
        for filename in sorted(os.listdir(path)):
            if not filename.endswith((".yaml", ".yml")):
                continue
            if filename.startswith("_"):
                continue  # skip _schema.json, _index.json etc.
            filepath = os.path.join(path, filename)
            sig = self._load_file(filepath)
            if sig is not None:
                # Override existing signature with same product name
                if sig.product in self._by_product:
                    old = self._by_product[sig.product]
                    self.signatures.remove(old)
                self._by_product[sig.product] = sig
                self.signatures.append(sig)
                loaded += 1

        if self.verbose and loaded:
            lib.formatter.debug("loaded {} signatures from '{}'".format(loaded, path))

    def _load_file(self, filepath):
        """Load and compile a single YAML signature file."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                self._load_errors.append((filepath, "not a YAML mapping"))
                return None
            if data.get("schema_version") != 1:
                self._load_errors.append((filepath, "unsupported schema_version"))
                return None
            if "product" not in data or "detection" not in data:
                self._load_errors.append((filepath, "missing required fields"))
                return None
            return CompiledSignature(data, filepath=filepath)
        except Exception as e:
            self._load_errors.append((filepath, str(e)))
            return None

    def detect(self, content, headers=None, status=0):
        """
        Run all signatures against a response.

        Args:
            content: response body (string or BeautifulSoup)
            headers: dict of response headers
            status: HTTP status code

        Returns:
            List of DetectionResult for all matching signatures.

        Performance: body is truncated to first 64KB for regex matching.
        WAF block pages are typically <10KB; checking 335KB+ of normal HTML
        against 111 signatures is wasteful and causes false positives from
        incidental keyword matches in large pages.
        """
        results = []
        content_str = str(content) if content else ""
        # Truncate body for matching: WAF block/error pages are small.
        # Large normal pages (news sites, apps) don't need full-body regex.
        if len(content_str) > 65536:
            content_str = content_str[:65536]

        for sig in self.signatures:
            if sig.match(content_str, headers, status):
                results.append(DetectionResult(
                    product=sig.product,
                    signature_file=sig.filepath,
                    confidence=sig.confidence,
                    tamper_hints=sig.tamper_hints,
                    tags=sig.tags,
                ))
        return results

    def detect_first(self, content, headers=None, status=0):
        """
        Run signatures with short-circuit: return first match.
        Ordered by confidence (high → medium → low).
        """
        content_str = str(content) if content else ""

        # Sort by confidence for priority matching
        priority = {"high": 0, "medium": 1, "low": 2}
        ordered = sorted(self.signatures, key=lambda s: priority.get(s.confidence, 1))

        for sig in ordered:
            if sig.match(content_str, headers, status):
                return DetectionResult(
                    product=sig.product,
                    signature_file=sig.filepath,
                    confidence=sig.confidence,
                    tamper_hints=sig.tamper_hints,
                    tags=sig.tags,
                )
        return None

    def get_tamper_hints(self, product_name):
        """Get tamper_hints for a detected product (for AdaptiveRanker)."""
        sig = self._by_product.get(product_name)
        if sig:
            return sig.tamper_hints
        return []

    def get_load_errors(self):
        """Return list of (filepath, error_message) for failed signature loads."""
        return list(self._load_errors)
