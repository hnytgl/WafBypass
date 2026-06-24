from urllib.parse import quote


__example_payload__ = "' AND 1=1 UNION SELECT NULL--"
__type__ = "selectively URL encode payload metacharacters while preserving parameter delimiters"
__category__ = "encoding"
__chain_stage__ = "terminal"
__contexts__ = ("query", "form")


def tamper(payload, **kwargs):
    if not payload:
        return payload
    return quote(payload, safe="=&")
