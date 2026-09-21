import pytest

from pratica_api_system.indicators import IndicatorValidationError, parse_indicator
from pratica_api_system.models import IndicatorType


@pytest.mark.parametrize(
    ("raw", "expected_type", "normalized"),
    [
        ("8.8.8.8", IndicatorType.IP, "8.8.8.8"),
        ("EXAMPLE.COM.", IndicatorType.DOMAIN, "example.com"),
        (
            "https://Example.com/a?x=1#frag",
            IndicatorType.URL,
            "https://example.com/a?x=1",
        ),
        (
            "d41d8cd98f00b204e9800998ecf8427e",
            IndicatorType.HASH,
            "d41d8cd98f00b204e9800998ecf8427e",
        ),
        ("cve-2026-12345", IndicatorType.CVE, "CVE-2026-12345"),
    ],
)
def test_parse_indicator(raw, expected_type, normalized):
    result = parse_indicator(raw)
    assert result.type == expected_type
    assert result.normalized == normalized


def test_private_ip_is_marked_non_public():
    result = parse_indicator("192.168.1.10")
    assert result.public_routable is False


def test_url_with_credentials_is_rejected():
    with pytest.raises(IndicatorValidationError):
        parse_indicator("https://user:pass@example.com/path")


def test_invalid_indicator_is_rejected():
    with pytest.raises(IndicatorValidationError):
        parse_indicator("not an indicator")
