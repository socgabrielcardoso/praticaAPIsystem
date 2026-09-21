from __future__ import annotations

from typing import Any
from urllib.parse import quote

from pydantic import SecretStr

from ..models import Finding, Indicator, IndicatorType, Verdict
from .base import Provider


class GreyNoiseProvider(Provider):
    name = "GreyNoise"
    supported_types = frozenset({IndicatorType.IP})
    _base_url = "https://api.greynoise.io/v3/community"

    def __init__(self, *args: Any, api_key: SecretStr | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._api_key = api_key

    @property
    def configured(self) -> bool:
        return bool(self._api_key and self._api_key.get_secret_value().strip())

    async def enrich(self, indicator: Indicator) -> Finding | None:
        if not self.configured:
            return None

        encoded = quote(indicator.normalized, safe="")
        payload = await self.request_json(
            "GET",
            f"{self._base_url}/{encoded}",
            headers={"key": self._api_key.get_secret_value()},
        )

        if payload.get("_not_found"):
            return Finding(
                provider=self.name,
                verdict=Verdict.UNKNOWN,
                score=0,
                confidence=55,
                summary="GreyNoise has no community record for this IP.",
            )

        classification = str(payload.get("classification", "unknown")).lower()
        noise = bool(payload.get("noise", False))
        riot = bool(payload.get("riot", False))

        if classification == "malicious":
            verdict = Verdict.MALICIOUS
            score = 88
        elif classification == "benign" or riot:
            verdict = Verdict.CLEAN
            score = 0
        elif noise:
            verdict = Verdict.SUSPICIOUS
            score = 45
        else:
            verdict = Verdict.UNKNOWN
            score = 0

        evidence = {
            "classification": classification,
            "noise": noise,
            "riot": riot,
            "name": payload.get("name"),
            "last_seen": payload.get("last_seen"),
            "message": payload.get("message"),
        }
        return Finding(
            provider=self.name,
            verdict=verdict,
            score=score,
            confidence=85,
            summary=(
                f"GreyNoise classification is {classification}; "
                f"noise={noise}, riot={riot}."
            ),
            evidence=evidence,
            reference=f"https://viz.greynoise.io/ip/{encoded}",
        )
