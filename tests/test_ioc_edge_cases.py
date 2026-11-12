import pytest

from pratica_api_system.defang import defang, refang
from pratica_api_system.indicators import IndicatorValidationError, parse_indicator


def test_mixed_case_hxxps_scheme_is_refanged():
    assert refang("HxxPs://example[.]org/a") == "https://example.org/a"


def test_brace_delimited_dot_is_refanged():
    assert refang("example{.}org") == "example.org"


def test_uppercase_http_scheme_is_defanged():
    assert defang("HTTPS://example.org") == "hxxps://example[.]org"


def test_empty_url_username_is_rejected():
    with pytest.raises(IndicatorValidationError):
        parse_indicator("https://@example.org/")


def test_out_of_range_url_port_is_rejected():
    with pytest.raises(IndicatorValidationError):
        parse_indicator("https://example.org:99999/a")


def test_fake_numeric_ipv4_is_not_accepted_as_domain():
    with pytest.raises(IndicatorValidationError):
        parse_indicator("999.999.999.999")


def test_empty_url_port_is_rejected():
    with pytest.raises(IndicatorValidationError):
        parse_indicator("https://example.org:/a")

