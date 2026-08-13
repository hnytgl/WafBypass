import re

__example_payload__ = "SELECT 1 FROM users"
__type__ = "convert ASCII letters and digits to full-width unicode confusables (skips %XX/\\x/0x/\\u encodings)"
__category__ = "encoding"
__chain_stage__ = "normalization"
__contexts__ = ("query", "form", "json")

# Already-encoded fragments must not be touched: their hex digits are part of
# the encoding, not plain text. Split on them and only transform the rest.
_PROTECTED = re.compile(
    r"(%[0-9A-Fa-f]{2}|\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|0x[0-9A-Fa-f]+)"
)
# Full-width confusables: U+FF01..U+FF5E map 1:1 onto U+0021..U+007E.
_FULLWIDTH = {chr(c): chr(c + 0xFEE0) for c in range(0x21, 0x7E)}


def tamper(payload, **kwargs):
    if not payload:
        return payload
    parts = _PROTECTED.split(str(payload))
    out = []
    for index, part in enumerate(parts):
        if index % 2 == 1:
            # matched protected encoding, keep as-is
            out.append(part)
        else:
            out.append("".join(_FULLWIDTH.get(ch, ch) for ch in part))
    return "".join(out)
