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
    if result[:8].lower() == "https://":
        result = "hxxps://" + result[8:]
    elif result[:7].lower() == "http://":
        result = "hxxp://" + result[7:]
    return result.replace(".", "[.]")
