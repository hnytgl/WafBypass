#!/usr/bin/env python
"""
tools/migrate_plugins.py -- Auto-convert Python WAF plugins to YAML signatures.

Uses AST parsing to extract detection logic from content/plugins/*.py and
generates equivalent signatures/*.yaml files.

Usage:
    python tools/migrate_plugins.py content/plugins/ -o signatures/
    python tools/migrate_plugins.py content/plugins/cloudflare.py -o signatures/  # single file
    python tools/migrate_plugins.py content/plugins/ -o signatures/ --dry-run     # preview only

Complexity tiers:
  - SIMPLE: only regex patterns against body/headers → fully automatic
  - MEDIUM: status code conditionals → automatic with status_rules
  - COMPLEX: multi-step conditionals, all-header iteration → skeleton + TODO comments
"""

import argparse
import ast
import os
import re
import sys

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML required. Install with: pip install pyyaml")
    sys.exit(1)


# Mapping from HTTP_HEADER.XXX constants to YAML field names
HEADER_CONST_MAP = {
    "SERVER": "server",
    "SET_COOKIE": "set-cookie",
    "COOKIE": "cookie",
    "X_POWERED_BY": "x-powered-by",
    "VIA": "via",
    "X_CACHE": "x-cache",
    "LOCATION": "location",
    "EXPECT_CT": "expect-ct",
    "CF_RAY": "cf-ray",
    "X_SERVER": "x-server",
    "X_BACKSIDE_TRANS": "x-backside-transport",
    "GW_SERVER": "gw-server",
    "CONTENT_TYPE": "content-type",
    "X_FRAME_OPT": "x-frame-options",
    "X_FORWARDED_FOR": "x-forwarded-for",
    "X_DATA_ORIGIN": "x-data-origin",
    "STRICT_TRANSPORT": "strict-transport-security",
    "CONTENT_SECURITY": "content-security-policy",
}

# Known WAF tag heuristics
TAG_HEURISTICS = {
    "cloudflare": ["cdn", "cloud", "challenge"],
    "akamai": ["cdn", "cloud"],
    "aws": ["cloud"],
    "azure": ["cloud"],
    "gcp": ["cloud"],
    "incapsula": ["cdn", "cloud"],
    "imperva": ["cdn", "cloud"],
    "sucuri": ["cdn", "cloud"],
    "fastly": ["cdn"],
    "cloudfront": ["cdn"],
    "modsecurity": ["opensource"],
    "naxsi": ["opensource"],
    "openresty": ["opensource"],
    "safedog": ["chinese"],
    "aliyun": ["chinese", "cloud"],
    "baidu": ["chinese", "cdn"],
    "360": ["chinese"],
    "qianxin": ["chinese"],
    "huawei": ["chinese", "cloud"],
    "tencent": ["chinese", "cloud"],
    "yundun": ["chinese"],
    "jiasule": ["chinese", "cdn"],
    "knownsec": ["chinese"],
    "nsfocus": ["chinese"],
    "hillstone": ["chinese"],
    "dbsapp": ["chinese"],
    "chuangyu": ["chinese"],
    "anquanbao": ["chinese"],
    "wordfence": ["wordpress"],
    "malcare": ["wordpress"],
    "rsfirewall": ["joomla"],
}


def extract_product(tree):
    """Extract __product__ string from AST."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__product__":
                    if isinstance(node.value, ast.Constant):
                        return node.value.value
                    elif isinstance(node.value, ast.Str):  # Python 3.7 compat
                        return node.value.s
    return None


def extract_regex_patterns(tree):
    """Extract all re.compile() calls and their arguments."""
    patterns = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            # re.compile(...)
            if isinstance(func, ast.Attribute) and func.attr == "compile":
                if isinstance(func.value, ast.Name) and func.value.id == "re":
                    if node.args:
                        arg = node.args[0]
                        regex_str = _get_string_value(arg)
                        if regex_str:
                            flags = _get_flags(node)
                            patterns.append({"regex": regex_str, "flags": flags})
            # re.compile("...", re.I) as standalone
    return patterns


def _get_string_value(node):
    """Extract string value from an AST node."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    elif isinstance(node, ast.Str):  # Python 3.7
        return node.s
    elif isinstance(node, ast.JoinedStr):
        # f-string: try to reconstruct
        parts = []
        for val in node.values:
            if isinstance(val, ast.Constant):
                parts.append(str(val.value))
            else:
                parts.append(".*")
        return "".join(parts)
    return None


def _get_flags(call_node):
    """Extract regex flags from re.compile() call."""
    flags = "i"  # default
    if len(call_node.args) > 1:
        flag_node = call_node.args[1]
        flag_str = _resolve_flag(flag_node)
        if flag_str:
            flags = flag_str
    for kw in call_node.keywords:
        if kw.arg == "flags":
            flag_str = _resolve_flag(kw.value)
            if flag_str:
                flags = flag_str
    return flags


def _resolve_flag(node):
    """Resolve a flag AST node to string like 'i', 'im', etc."""
    flags = ""
    if isinstance(node, ast.Attribute):
        if node.attr == "IGNORECASE":
            flags += "i"
        elif node.attr == "MULTILINE":
            flags += "m"
        elif node.attr == "DOTALL":
            flags += "s"
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = _resolve_flag(node.left)
        right = _resolve_flag(node.right)
        flags = (left or "") + (right or "")
    elif isinstance(node, ast.Name):
        if node.id == "I":
            flags += "i"
    return flags or "i"


def extract_header_fields(source):
    """Extract which headers are checked via headers.get(HTTP_HEADER.XXX, ...)."""
    fields = set()
    # Pattern: headers.get(HTTP_HEADER.SERVER, "")
    for match in re.finditer(r"headers\.get\(HTTP_HEADER\.(\w+)", source):
        const_name = match.group(1)
        yaml_field = HEADER_CONST_MAP.get(const_name)
        if yaml_field:
            fields.add(yaml_field)
    # Pattern: headers.get("X-Custom-Header", "")
    for match in re.finditer(r'headers\.get\(["\']([^"\']+)["\']', source):
        header_name = match.group(1)
        fields.add(header_name.lower())
    return fields


def extract_status_codes(source):
    """Extract status code checks from source."""
    codes = set()
    # status == 403
    for match in re.finditer(r"status\s*==\s*(\d+)", source):
        codes.add(int(match.group(1)))
    # status in (403, 405, 501)
    for match in re.finditer(r"status\s+in\s+\(([^)]+)\)", source):
        for num in re.findall(r"\d+", match.group(1)):
            codes.add(int(num))
    # status in [403, 405]
    for match in re.finditer(r"status\s+in\s+\[([^\]]+)\]", source):
        for num in re.findall(r"\d+", match.group(1)):
            codes.add(int(num))
    return codes


def detect_header_presence(source):
    """Detect TRUE header presence checks (non-empty → immediately return True).

    Only flags headers where the pattern is:
        var = headers.get(...)
        if var != "": return True   (or: if var: return True)

    Does NOT flag conditional gates like:
        if gw_server != "":
            if detection.search(server): return True
    (those are multi-step conditionals, not presence checks)
    """
    presence = []
    var_to_header = {}
    for match in re.finditer(
        r'(\w+)\s*=\s*headers\.get\((?:HTTP_HEADER\.(\w+)|["\']([^"\']+)["\'])',
        source
    ):
        var_name = match.group(1)
        if match.group(2):
            header = HEADER_CONST_MAP.get(match.group(2), match.group(2).lower())
        else:
            header = match.group(3).lower()
        var_to_header[var_name] = header

    for var_name, header in var_to_header.items():
        # True presence: "if var != "":\n        return True" or "if var:\n        return True"
        # The return True must be the DIRECT next statement (not inside a nested if/for)
        pattern_direct = r"if\s+{}\s*(!=\s*[\"']{{2}}|is\s+not\s+None)?\s*:\s*\n\s+return\s+True".format(
            re.escape(var_name)
        )
        if re.search(pattern_direct, source):
            presence.append(header)

    return presence


def detect_all_headers_iteration(source):
    """Check if plugin iterates over all headers."""
    return bool(re.search(r"for\s+\w+\s*,\s*\w+\s+in\s+headers\.items\(\)", source))


def detect_contains_checks(source):
    """Detect simple string-in-variable checks."""
    contains = []
    # Pattern: if "__cfuid" in set_cookie
    for match in re.finditer(r'if\s+["\']([^"\']+)["\']\s+in\s+(\w+)', source):
        value = match.group(1)
        var_name = match.group(2)
        # Map variable to field
        field = _var_to_field(var_name)
        if field:
            contains.append({"value": value, "field": field})
    return contains


def _var_to_field(var_name):
    """Map common variable names to YAML field names."""
    mapping = {
        "server": "server",
        "set_cookie": "set-cookie",
        "cookie": "cookie",
        "expect_ct": "expect-ct",
        "cf_ray": "cf-ray",
        "x_cache": "x-cache",
        "content": "body",
    }
    return mapping.get(var_name)


def classify_complexity(source, patterns, status_codes, all_headers, conditionals):
    """Classify plugin complexity: simple, medium, complex."""
    if all_headers or conditionals:
        return "complex"
    if status_codes:
        return "medium"
    return "simple"


def detect_conditionals(source):
    """Detect multi-step conditionals (if header X: then check patterns)."""
    conditionals = []
    # Pattern: if x_amzn:\n    for detection in ...:\n        if detection.search(content)
    # This is hard to detect via regex alone; use a heuristic
    if re.search(r"if\s+\w+\s*:\s*\n\s+for\s+detection", source):
        # Find which variable gates the loop
        for match in re.finditer(r"if\s+(\w+)\s*:\s*\n\s+for\s+detection", source):
            var_name = match.group(1)
            # Try to find what header this variable came from
            hdr_match = re.search(
                r"{}\s*=\s*headers\.get\((?:HTTP_HEADER\.(\w+)|[\"']([^\"']+)[\"'])".format(re.escape(var_name)),
                source
            )
            if hdr_match:
                if hdr_match.group(1):
                    header = HEADER_CONST_MAP.get(hdr_match.group(1), hdr_match.group(1).lower())
                else:
                    header = hdr_match.group(2).lower()
                conditionals.append(header)
    return conditionals


def generate_yaml(plugin_path, product, patterns, fields, status_codes,
                  header_presence, all_headers, contains_checks, conditionals,
                  complexity):
    """Generate YAML signature dict from extracted data."""
    # Determine filename for tags
    basename = os.path.splitext(os.path.basename(plugin_path))[0].lower()
    tags = []
    for key, key_tags in TAG_HEURISTICS.items():
        if key in basename:
            tags.extend(key_tags)
            break

    sig = {
        "schema_version": 1,
        "product": product,
        "version": "2026.09",
    }
    if tags:
        sig["tags"] = sorted(set(tags))

    detection = {}

    if header_presence:
        detection["header_presence"] = sorted(set(header_presence))

    if all_headers:
        detection["match_all_headers"] = True

    if patterns:
        # Always include "body" in fields (all plugins check content),
        # plus any specific headers found in the source.
        default_fields = sorted(set(list(fields) + ["body"])) if fields else ["body"]
        yaml_patterns = []
        for pat in patterns:
            entry = {"regex": pat["regex"], "fields": default_fields}
            if pat.get("flags", "i") != "i":
                entry["flags"] = pat["flags"]
            yaml_patterns.append(entry)
        detection["patterns"] = yaml_patterns

    if contains_checks:
        detection["contains"] = contains_checks

    if status_codes and complexity in ("medium", "complex"):
        detection["status_rules"] = [{
            "status": sorted(status_codes),
            "patterns": [{"regex": p["regex"], "fields": sorted(fields) if fields else ["body"]}
                         for p in patterns[:3]],  # limit to first 3 for status rules
        }]

    if conditionals and complexity == "complex":
        detection["conditional"] = [{
            "if_header": cond,
            "patterns": [{"regex": p["regex"], "fields": ["body", "server"]}
                         for p in patterns[:3]],
        } for cond in conditionals]

    sig["detection"] = detection

    # Add tamper hints based on product name
    hints = _guess_tamper_hints(product, basename)
    if hints:
        sig["tamper_hints"] = hints

    sig["confidence"] = "high" if complexity == "simple" else "medium"

    return sig


def _guess_tamper_hints(product, basename):
    """Guess tamper hints from product name (mirrors WAF_TAMPER_HINTS in adaptive.py)."""
    hints_map = {
        "cloudflare": ["encoding", "keyword", "whitespace"],
        "modsecurity": ["comment", "case", "keyword"],
        "safedog": ["unicode", "keyword", "whitespace"],
        "aliyun": ["encoding", "literal", "whitespace"],
        "360": ["keyword", "whitespace"],
        "akamai": ["whitespace", "encoding"],
        "incapsula": ["encoding", "keyword"],
        "imperva": ["encoding", "keyword"],
        "barracuda": ["whitespace", "encoding"],
        "sucuri": ["encoding", "case"],
        "wordfence": ["case", "keyword"],
        "naxsi": ["case", "comment"],
        "huawei": ["encoding", "whitespace"],
        "tencent": ["encoding", "whitespace"],
        "bigip": ["case", "comment"],
        "f5": ["case", "comment"],
    }
    for key, hints in hints_map.items():
        if key in basename or key in product.lower():
            return hints
    return []


def migrate_plugin(plugin_path, output_dir, dry_run=False):
    """Migrate a single Python plugin to YAML signature."""
    with open(plugin_path, "r", encoding="utf-8") as f:
        source = f.read()

    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return None, "syntax error: {}".format(e)

    product = extract_product(tree)
    if not product:
        return None, "no __product__ found"

    patterns = extract_regex_patterns(tree)
    fields = extract_header_fields(source)
    status_codes = extract_status_codes(source)
    header_presence = detect_header_presence(source)
    all_headers = detect_all_headers_iteration(source)
    contains_checks = detect_contains_checks(source)
    conditionals = detect_conditionals(source)

    complexity = classify_complexity(source, patterns, status_codes, all_headers, conditionals)

    if not patterns and not header_presence and not contains_checks:
        return None, "no detection logic found"

    sig = generate_yaml(
        plugin_path, product, patterns, fields, status_codes,
        header_presence, all_headers, contains_checks, conditionals, complexity
    )

    # Generate output filename
    basename = os.path.splitext(os.path.basename(plugin_path))[0]
    out_path = os.path.join(output_dir, "{}.yaml".format(basename))

    if dry_run:
        return sig, complexity

    # Custom YAML representer for clean output
    class CleanDumper(yaml.SafeDumper):
        pass

    def str_representer(dumper, data):
        if "\n" in data:
            return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
        return dumper.represent_scalar("tag:yaml.org,2002:str", data)

    CleanDumper.add_representer(str, str_representer)

    os.makedirs(output_dir, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        yaml.dump(sig, f, Dumper=CleanDumper, default_flow_style=False,
                  allow_unicode=True, sort_keys=False, width=120)

    return sig, complexity


def main():
    parser = argparse.ArgumentParser(description="Migrate Python WAF plugins to YAML signatures")
    parser.add_argument("input", help="Plugin file or directory to migrate")
    parser.add_argument("-o", "--output", default="signatures/", help="Output directory for YAML files")
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing files")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed output")
    args = parser.parse_args()

    if os.path.isfile(args.input):
        files = [args.input]
    elif os.path.isdir(args.input):
        files = sorted([
            os.path.join(args.input, f)
            for f in os.listdir(args.input)
            if f.endswith(".py") and not f.startswith("__")
        ])
    else:
        print("ERROR: '{}' not found".format(args.input))
        sys.exit(1)

    stats = {"simple": 0, "medium": 0, "complex": 0, "failed": 0}
    results = []

    for filepath in files:
        sig, complexity = migrate_plugin(filepath, args.output, dry_run=args.dry_run)
        basename = os.path.basename(filepath)

        if sig is None:
            stats["failed"] += 1
            if args.verbose:
                print("  FAIL {}: {}".format(basename, complexity))
            continue

        stats[complexity] = stats.get(complexity, 0) + 1
        results.append((basename, sig.get("product", "?"), complexity))

        if args.verbose or args.dry_run:
            print("  {} [{}] -> {}".format(basename, complexity, sig.get("product", "?")))

    print("\n--- Migration Summary ---")
    print("  Total plugins:  {}".format(len(files)))
    print("  Simple (auto):  {}".format(stats["simple"]))
    print("  Medium (auto):  {}".format(stats["medium"]))
    print("  Complex (review): {}".format(stats["complex"]))
    print("  Failed:         {}".format(stats["failed"]))
    if not args.dry_run:
        print("  Output:         {}".format(os.path.abspath(args.output)))
    print()

    if stats["complex"] > 0:
        print("NOTE: {} complex plugins need manual review.".format(stats["complex"]))
        print("      Check generated YAML for '# TODO' comments and verify logic.")


if __name__ == "__main__":
    main()
