from __future__ import annotations

from typing import Any

from pydantic import SecretStr

from ..models import Finding, Indicator, IndicatorType, Verdict
from .base import Provider


class AbuseIPDBProvider(Provider):
    name = "AbuseIPDB"
    supported_types = frozenset({IndicatorType.IP})
    _endpoint = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, *args: Any, api_key: SecretStr | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._api_key = api_key

    @property
    def configured(self) -> bool:
        return bool(self._api_key and self._api_key.get_secret_value().strip())

    async def enrich(self, indicator: Indicator) -> Finding | None:
        if not self.configured:
            return None

        payload = await self.request_json(
            "GET",
            self._endpoint,
            headers={
                "Accept": "application/json",
                "Key": self._api_key.get_secret_value(),
            },
            params={"ipAddress": indicator.normalized, "maxAgeInDays": 90},
        )
        data = payload.get("data", {})
        confidence = int(data.get("abuseConfidenceScore", 0) or 0)
        reports = int(data.get("totalReports", 0) or 0)

        if confidence >= 80:
            verdict = Verdict.MALICIOUS
        elif confidence >= 20 or reports > 0:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.CLEAN

        evidence = {
            "abuse_confidence_score": confidence,
            "total_reports": reports,
            "last_reported_at": data.get("lastReportedAt"),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "is_whitelisted": data.get("isWhitelisted"),
        }
        return Finding(
            provider=self.name,
            verdict=verdict,
            score=confidence,
            confidence=85,
            summary=f"AbuseIPDB confidence is {confidence}% across {reports} recent reports.",
            evidence=evidence,
            reference=f"https://www.abuseipdb.com/check/{indicator.normalized}",
        )
