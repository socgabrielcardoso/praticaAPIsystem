from __future__ import annotations

from ..models import Finding, Indicator, IndicatorType, Verdict
from .base import Provider


class EPSSProvider(Provider):
    name = "FIRST EPSS"
    supported_types = frozenset({IndicatorType.CVE})
    _endpoint = "https://api.first.org/data/v1/epss"

    @property
    def configured(self) -> bool:
        return True

    async def enrich(self, indicator: Indicator) -> Finding | None:
        payload = await self.request_json(
            "GET",
            self._endpoint,
            params={"cve": indicator.normalized},
        )
        records = payload.get("data") or []
        if not records:
            return Finding(
                provider=self.name,
                verdict=Verdict.UNKNOWN,
                score=0,
                confidence=70,
                summary="EPSS has no probability record for this CVE.",
                reference="https://www.first.org/epss/",
            )

        record = records[0]
        probability = float(record.get("epss", 0) or 0)
        percentile = float(record.get("percentile", 0) or 0)
        score = min(100, round(probability * 100))

        if probability >= 0.1:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.UNKNOWN

        return Finding(
            provider=self.name,
            verdict=verdict,
            score=score,
            confidence=90,
            summary=(
                f"EPSS exploitation probability is {probability:.2%} "
                f"at percentile {percentile:.2%}."
            ),
            evidence={
                "epss": probability,
                "percentile": percentile,
                "date": record.get("date"),
            },
            reference="https://www.first.org/epss/",
        )
