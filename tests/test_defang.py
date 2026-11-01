from pratica_api_system.defang import defang, refang
from pratica_api_system.indicators import parse_indicator
from pratica_api_system.models import IndicatorType


def test_refang_url():
    assert refang("hxxps://example[.]com/path") == "https://example.com/path"


def test_defang_url():
    assert defang("https://example.com/path") == "hxxps://example[.]com/path"


def test_parser_accepts_defanged_domain():
    indicator = parse_indicator("example[.]com")
    assert indicator.type == IndicatorType.DOMAIN
    assert indicator.normalized == "example.com"


def test_parser_accepts_defanged_url():
    indicator = parse_indicator("hxxps://example[.]com/login")
    assert indicator.type == IndicatorType.URL
    assert indicator.normalized == "https://example.com/login"


def test_refang_mixed_case_scheme_and_embedded_text():
    assert refang("HxXpS://example[.]com/a/hxxp://keep") == "https://example.com/a/hxxp://keep"
    assert refang("hXxP://example[.]com") == "http://example.com"
    assert refang("https://example[.]com/?next=hxxps://other[.]test") == (
        "https://example.com/?next=hxxps://other.test"
    )


def test_defang_mixed_case_scheme_and_round_trip():
    assert defang("HTTPS://Example.com/path") == "hxxps://Example[.]com/path"
    assert defang("HtTp://example.com") == "hxxp://example[.]com"
    assert refang(defang("HTTPS://Example.com/path")) == "https://Example.com/path"


def test_indicator_parser_accepts_mixed_case_defanged_scheme():
    indicator = parse_indicator("HxXpS://Example[.]com/login")
    assert indicator.type == IndicatorType.URL
    assert indicator.normalized == "https://example.com/login"
