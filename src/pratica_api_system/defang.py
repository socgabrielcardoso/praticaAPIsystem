from __future__ import annotations

import re

_DOT_TOKENS = ("[.]", "(.)")
_DEFANGED_SCHEME = re.compile(r"^hxxps?://", re.IGNORECASE)
_ACTIVE_SCHEME = re.compile(r"^https?://", re.IGNORECASE)


def refang(value: str) -> str:
    result = value.strip()
    # Only restore a leading URL scheme. Embedded strings in paths and queries
    # are data and must not be silently rewritten.
    result = _DEFANGED_SCHEME.sub(
        lambda match: "https://" if match.group().lower().startswith("hxxps") else "http://",
        result,
        count=1,
    )
    for token in _DOT_TOKENS:
        result = result.replace(token, ".")
    result = re.sub(r"\[:\]", ":", result)
    return result


def defang(value: str) -> str:
    result = value.strip()
    # URL schemes are case-insensitive; never leave an uppercase active scheme.
    result = _ACTIVE_SCHEME.sub(
        lambda match: "hxxps://" if match.group().lower().startswith("https") else "hxxp://",
        result,
        count=1,
    )
    return result.replace(".", "[.]")
