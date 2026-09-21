from __future__ import annotations

from typing import Any
from urllib.parse import quote

from pydantic import SecretStr

from ..models import Finding, Indicator, IndicatorType, Verdict
from .base import Provider


class OTXProvider(Provider):
    name = "AlienVault OTX"
    supported_types = frozenset(
        {IndicatorType.IP, IndicatorType.DOMAIN, IndicatorType.URL, IndicatorType.HASH}
    )
    _base_url = "https://otx.alienvault.com/api/v1/indicators"

    def __init__(self, *args: Any, api_key: SecretStr | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._api_key = api_key

    @property
    def configured(self) -> bool:
        return bool(self._api_key and self._api_key.get_secret_value().strip())

    async def enrich(self, indicator: Indicator) -> Finding | None:
        if not self.configured:
            return None

        indicator_kind = self._indicator_kind(indicator.type)
        encoded = quote(indicator.normalized, safe="")
        payload = await self.request_json(
            "GET",
            f"{self._base_url}/{indicator_kind}/{encoded}/general",
            headers={"X-OTX-API-KEY": self._api_key.get_secret_value()},
        )

        if payload.get("_not_found"):
            return Finding(
                provider=self.name,
                verdict=Verdict.UNKNOWN,
                score=0,
                confidence=55,
                summary="OTX has no record for this indicator.",
            )

        pulse_info = payload.get("pulse_info") or {}
        pulse_count = int(pulse_info.get("count", 0) or 0)
        pulses = pulse_info.get("pulses") or []
        references = payload.get("references") or []

        if pulse_count >= 5:
            verdict = Verdict.MALICIOUS
            score = min(98, 72 + pulse_count * 3)
        elif pulse_count > 0:
            verdict = Verdict.SUSPICIOUS
            score = min(79, 38 + pulse_count * 8)
        else:
            verdict = Verdict.UNKNOWN
            score = 0

        evidence = {
            "pulse_count": pulse_count,
            "pulse_names": [
                pulse.get("name")
                for pulse in pulses[:5]
                if isinstance(pulse, dict) and pulse.get("name")
            ],
            "validation": payload.get("validation"),
            "references": references[:5] if isinstance(references, list) else [],
        }
        return Finding(
            provider=self.name,
            verdict=verdict,
            score=score,
            confidence=80,
            summary=f"OTX reports {pulse_count} threat intelligence pulse matches.",
            evidence=evidence,
            reference=f"https://otx.alienvault.com/indicator/{indicator_kind}/{encoded}",
        )

    @staticmethod
    def _indicator_kind(indicator_type: IndicatorType) -> str:
        mapping = {
            IndicatorType.IP: "IPv4",
            IndicatorType.DOMAIN: "domain",
            IndicatorType.URL: "url",
            IndicatorType.HASH: "file",
        }
        return mapping[indicator_type]
