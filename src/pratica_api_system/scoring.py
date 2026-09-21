from __future__ import annotations

from .models import Finding, Verdict


def aggregate_score(findings: list[Finding]) -> tuple[int, Verdict, list[str]]:
    if not findings:
        return 0, Verdict.UNKNOWN, ["no_intelligence"]

    scored = [finding for finding in findings if finding.verdict != Verdict.UNKNOWN]
    if not scored:
        return 0, Verdict.UNKNOWN, ["no_decisive_signal"]

    highest = max(finding.score for finding in scored)
    corroborating = sum(1 for finding in scored if finding.score >= 50)
    malicious_sources = sum(1 for finding in scored if finding.verdict == Verdict.MALICIOUS)

    score = highest
    if corroborating >= 2:
        score = min(100, score + 8)
    if malicious_sources >= 2:
        score = min(100, score + 7)

    if malicious_sources >= 1 and score >= 80:
        verdict = Verdict.MALICIOUS
    elif score >= 40:
        verdict = Verdict.SUSPICIOUS
    elif all(finding.verdict == Verdict.CLEAN for finding in scored):
        verdict = Verdict.CLEAN
    else:
        verdict = Verdict.UNKNOWN

    tags: list[str] = []
    if corroborating >= 2:
        tags.append("corroborated")
    if malicious_sources >= 2:
        tags.append("multi_source_malicious")
    if verdict == Verdict.CLEAN:
        tags.append("no_adverse_signal")
    return score, verdict, tags
