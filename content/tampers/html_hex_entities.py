__example_payload__ = '<img src=x onerror="alert(1)">'
__type__ = "encode HTML metacharacters as hexadecimal character references"
__category__ = "xss"
__chain_stage__ = "encoding"
__contexts__ = ("html", "attribute")


ENTITY_MAP = {
    "<": "&#x3c;",
    ">": "&#x3e;",
    '"': "&#x22;",
    "'": "&#x27;",
    "(": "&#x28;",
    ")": "&#x29;",
    "/": "&#x2f;",
    "=": "&#x3d;",
}


def tamper(payload, **kwargs):
    if not payload:
        return payload
    return "".join(ENTITY_MAP.get(char, char) for char in payload)
