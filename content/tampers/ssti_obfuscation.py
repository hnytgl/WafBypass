import random

__example_payload__ = "{{7*7}}"
__type__ = "obfuscate SSTI templates with whitespace, operator spacing, and newline-split delimiters"
__category__ = "ssti"
__chain_stage__ = "lexical"
__contexts__ = ("form", "query")


def tamper(payload, **kwargs):
    if not payload:
        return payload

    strategy = kwargs.get("strategy", -1)
    if strategy == -1:
        strategy = random.randrange(3)

    if strategy == 0:
        # {{7*7}} -> {{ 7*7 }} (most template engines ignore whitespace inside delimiters)
        return (
            payload.replace("{{", "{{ ").replace("}}", " }}")
            .replace("{%", "{% ").replace("%}", " %}")
        )
    if strategy == 1:
        # {{7*7}} -> {{ 7 * 7 }} (spread the arithmetic expression)
        return (
            payload.replace("*", " * ").replace("+", " + ")
            .replace("-", " - ").replace("=", " = ")
        )
    # strategy 2: newline inside the delimiters breaks naive {{\s*.*\s*}} regexes
    return (
        payload.replace("{{", "{{\n").replace("}}", "\n}}")
        .replace("{%", "{%\n").replace("%}", "\n%}")
    )
