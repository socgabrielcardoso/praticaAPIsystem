from __future__ import annotations

import ipaddress
import re
from urllib.parse import SplitResult, urlsplit, urlunsplit

from .models import Indicator, IndicatorType

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_HASH_RE = re.compile(r"^[A-Fa-f0-9]+$")
_DOMAIN_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


class IndicatorValidationError(ValueError):
    pass


def _normalize_domain(value: str) -> str:
    candidate = value.rstrip(".").lower()
    try:
        ascii_domain = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise IndicatorValidationError("invalid domain name") from exc

    if len(ascii_domain) > 253 or "." not in ascii_domain:
        raise IndicatorValidationError("invalid domain name")
    if any(not _DOMAIN_LABEL_RE.fullmatch(label) for label in ascii_domain.split(".")):
        raise IndicatorValidationError("invalid domain name")
    return ascii_domain


def _ip_is_public(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    return ip.is_global


def _normalize_url(value: str) -> tuple[str, bool]:
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise IndicatorValidationError("URL scheme must be http or https")
    if not parsed.hostname:
        raise IndicatorValidationError("URL must include a hostname")
    if parsed.username or parsed.password:
        raise IndicatorValidationError("URLs with embedded credentials are not accepted")

    host = parsed.hostname
    public_routable = True
    try:
        ip = ipaddress.ip_address(host)
        normalized_host = ip.compressed
        public_routable = ip.is_global
    except ValueError:
        normalized_host = _normalize_domain(host)

    netloc = normalized_host
    if ":" in normalized_host and not normalized_host.startswith("["):
        netloc = f"[{normalized_host}]"
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"

    normalized = urlunsplit(
        SplitResult(
            scheme=parsed.scheme.lower(),
            netloc=netloc,
            path=parsed.path or "/",
            query=parsed.query,
            fragment="",
        )
    )
    return normalized, public_routable


def parse_indicator(raw: str) -> Indicator:
    value = raw.strip()
    if not value:
        raise IndicatorValidationError("indicator cannot be empty")
    if len(value) > 2048:
        raise IndicatorValidationError("indicator is too long")

    if _CVE_RE.fullmatch(value):
        normalized = value.upper()
        return Indicator(original=raw, normalized=normalized, type=IndicatorType.CVE)

    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        normalized = ip.compressed
        return Indicator(
            original=raw,
            normalized=normalized,
            type=IndicatorType.IP,
            public_routable=ip.is_global,
        )

    if "://" in value:
        normalized, public_routable = _normalize_url(value)
        return Indicator(
            original=raw,
            normalized=normalized,
            type=IndicatorType.URL,
            public_routable=public_routable,
        )

    if len(value) in {32, 40, 64} and _HASH_RE.fullmatch(value):
        return Indicator(
            original=raw,
            normalized=value.lower(),
            type=IndicatorType.HASH,
        )

    try:
        normalized = _normalize_domain(value)
    except IndicatorValidationError as exc:
        raise IndicatorValidationError(
            "unsupported indicator. Use an IP, domain, HTTP(S) URL, MD5, SHA1, SHA256 or CVE"
        ) from exc

    return Indicator(original=raw, normalized=normalized, type=IndicatorType.DOMAIN)
