from __future__ import annotations

import re

_DOT_TOKENS = ("[.]", "(.)", "{.}")
_HTTP_REPLACEMENTS = (
    ("hxxps://", "https://"),
    ("hxxp://", "http://"),
    ("HXXPS://", "https://"),
    ("HXXP://", "http://"),
)


def refang(value: str) -> str:
    result = value.strip()
    result = re.sub(r"^hxxps://", "https://", result, flags=re.IGNORECASE)
    result = re.sub(r"^hxxp://", "http://", result, flags=re.IGNORECASE)
    for token in _DOT_TOKENS:
        result = result.replace(token, ".")
    result = re.sub(r"\[:\]", ":", result)
    return result


def defang(value: str) -> str:
    result = value.strip()
    if result.startswith("https://"):
        result = "hxxps://" + result[len("https://") :]
    elif result.startswith("http://"):
        result = "hxxp://" + result[len("http://") :]
    return result.replace(".", "[.]")
