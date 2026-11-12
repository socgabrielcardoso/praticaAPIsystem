import pytest

from pratica_api_system.defang import defang, refang
from pratica_api_system.indicators import IndicatorValidationError, parse_indicator


def test_mixed_case_hxxps_scheme_is_refanged():
    assert refang("HxxPs://example[.]org/a") == "https://example.org/a"


def test_brace_delimited_dot_is_refanged():
    assert refang("example{.}org") == "example.org"

