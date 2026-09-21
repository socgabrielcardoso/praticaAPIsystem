from __future__ import annotations

import base64
from typing import Any
from urllib.parse import quote

from pydantic import SecretStr

from ..models import Finding, Indicator, IndicatorType, Verdict
from .base import Provider


class VirusTotalProvider(Provider):
    name = "VirusTotal"
    supported_types = frozenset(
        {IndicatorType.IP, IndicatorType.DOMAIN, IndicatorType.URL, IndicatorType.HASH}
    )
    _base_url = "https://www.virustotal.com/api/v3"

    def __init__(self, *args: Any, api_key: SecretStr | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._api_key = api_key

    @property
    def configured(self) -> bool:
        return bool(self._api_key and self._api_key.get_secret_value().strip())

    async def enrich(self, indicator: Indicator) -> Finding | None:
        if not self.configured:
            return None

        resource, reference = self._resource(indicator)
        payload = await self.request_json(
            "GET",
            f"{self._base_url}/{resource}",
            headers={"x-apikey": self._api_key.get_secret_value()},
        )
        if payload.get("_not_found"):
            return Finding(
                provider=self.name,
                verdict=Verdict.UNKNOWN,
                score=0,
                confidence=50,
                summary="No VirusTotal object was found for this indicator.",
                reference=reference,
            )

        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)

        if malicious >= 5:
            verdict = Verdict.MALICIOUS
            score = min(100, 70 + (malicious - 5) * 3 + suspicious * 2)
        elif malicious > 0 or suspicious > 0:
            verdict = Verdict.SUSPICIOUS
            score = min(79, 30 + malicious * 12 + suspicious * 6)
        elif harmless > 0 or undetected > 0:
            verdict = Verdict.CLEAN
            score = 0
        else:
            verdict = Verdict.UNKNOWN
            score = 0

        evidence = {
            "analysis_stats": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
            },
            "reputation": attributes.get("reputation"),
            "categories": attributes.get("categories"),
            "last_analysis_date": attributes.get("last_analysis_date"),
        }
        return Finding(
            provider=self.name,
            verdict=verdict,
            score=score,
            confidence=85,
            summary=(
                f"VirusTotal engines reported {malicious} malicious and "
                f"{suspicious} suspicious detections."
            ),
            evidence=evidence,
            reference=reference,
        )

    def _resource(self, indicator: Indicator) -> tuple[str, str]:
        encoded = quote(indicator.normalized, safe="")
        if indicator.type == IndicatorType.IP:
            return (
                f"ip_addresses/{encoded}",
                f"https://www.virustotal.com/gui/ip-address/{encoded}",
            )
        if indicator.type == IndicatorType.DOMAIN:
            return f"domains/{encoded}", f"https://www.virustotal.com/gui/domain/{encoded}"
        if indicator.type == IndicatorType.HASH:
            return f"files/{encoded}", f"https://www.virustotal.com/gui/file/{encoded}"

        url_id = base64.urlsafe_b64encode(indicator.normalized.encode()).decode().rstrip("=")
        return f"urls/{url_id}", f"https://www.virustotal.com/gui/url/{url_id}"
