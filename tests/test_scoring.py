from pratica_api_system.models import Finding, Verdict
from pratica_api_system.scoring import aggregate_score


def finding(provider: str, verdict: Verdict, score: int) -> Finding:
    return Finding(provider=provider, verdict=verdict, score=score, summary="test")


def test_no_findings_is_unknown():
    score, verdict, tags = aggregate_score([])
    assert score == 0
    assert verdict == Verdict.UNKNOWN
    assert "no_intelligence" in tags


def test_two_malicious_sources_receive_corroboration_bonus():
    score, verdict, tags = aggregate_score(
        [
            finding("one", Verdict.MALICIOUS, 88),
            finding("two", Verdict.MALICIOUS, 90),
        ]
    )
    assert score == 100
    assert verdict == Verdict.MALICIOUS
    assert "corroborated" in tags
    assert "multi_source_malicious" in tags


def test_clean_sources_remain_clean():
    score, verdict, tags = aggregate_score(
        [
            finding("one", Verdict.CLEAN, 0),
            finding("two", Verdict.CLEAN, 0),
        ]
    )
    assert score == 0
    assert verdict == Verdict.CLEAN
    assert "no_adverse_signal" in tags
