__example_payload__ = '<script>alert(1)</script>'
__type__ = "encode HTML metacharacters as decimal character references"
__category__ = "encoding"
__chain_stage__ = "encoding"
__contexts__ = ("html", "attribute")

ENTITY_MAP = {
    "<": "&#60;",
    ">": "&#62;",
    '"': "&#34;",
    "'": "&#39;",
    "(": "&#40;",
    ")": "&#41;",
    "/": "&#47;",
    "=": "&#61;",
}


def tamper(payload, **kwargs):
    if not payload:
        return payload
    return "".join(ENTITY_MAP.get(char, char) for char in payload)
