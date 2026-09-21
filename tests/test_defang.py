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
