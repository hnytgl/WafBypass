import re

__example_payload__ = "' OR 1=1--"
__type__ = "encode metacharacters as \\uXXXX unicode escapes"
__category__ = "encoding"
__chain_stage__ = "encoding"
__contexts__ = ("json", "html", "attribute")

_SPECIAL = re.compile(r"[\'\"<>=/()\\\\\s]")


def _escape(match):
    return "\\u{:04x}".format(ord(match.group(0)))


def tamper(payload, **kwargs):
    if not payload:
        return payload
    return _SPECIAL.sub(_escape, payload)
