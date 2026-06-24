import re


__example_payload__ = "' UNION SELECT NULL FROM users--"
__type__ = "wrap SQL keywords in MySQL versioned comments"
__category__ = "sqli"
__chain_stage__ = "lexical"
__contexts__ = ("query", "form")


KEYWORDS = (
    "UNION",
    "SELECT",
    "FROM",
    "WHERE",
    "AND",
    "OR",
    "ORDER",
    "GROUP",
    "HAVING",
    "INSERT",
    "UPDATE",
    "DELETE",
)
KEYWORD_PATTERN = re.compile(
    r"\b({})\b".format("|".join(KEYWORDS)),
    re.IGNORECASE,
)


def tamper(payload, **kwargs):
    if not payload:
        return payload
    return KEYWORD_PATTERN.sub(
        lambda match: "/*!50000{}*/".format(match.group(0).upper()),
        payload,
    )
