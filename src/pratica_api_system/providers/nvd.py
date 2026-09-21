from __future__ import annotations

from typing import Any

from pydantic import SecretStr

from ..models import Finding, Indicator, IndicatorType, Verdict
from .base import Provider


class NVDProvider(Provider):
    name = "NVD"
    supported_types = frozenset({IndicatorType.CVE})
    _endpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, *args: Any, api_key: SecretStr | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._api_key = api_key

    @property
    def configured(self) -> bool:
        return True

    async def enrich(self, indicator: Indicator) -> Finding | None:
        headers: dict[str, str] = {}
        if self._api_key and self._api_key.get_secret_value().strip():
            headers["apiKey"] = self._api_key.get_secret_value()

        payload = await self.request_json(
            "GET",
            self._endpoint,
            headers=headers or None,
            params={"cveId": indicator.normalized},
        )
        vulnerabilities = payload.get("vulnerabilities") or []
        if not vulnerabilities:
            return Finding(
                provider=self.name,
                verdict=Verdict.UNKNOWN,
                score=0,
                confidence=70,
                summary="NVD has no published record for this CVE.",
                reference=f"https://nvd.nist.gov/vuln/detail/{indicator.normalized}",
            )

        cve = vulnerabilities[0].get("cve", {})
        metrics = cve.get("metrics", {})
        score, severity, vector = self._best_cvss(metrics)
        descriptions = cve.get("descriptions") or []
        description = next(
            (item.get("value") for item in descriptions if item.get("lang") == "en"),
            None,
        )

        if score >= 9.0:
            verdict = Verdict.MALICIOUS
            risk_score = 90
        elif score >= 7.0:
            verdict = Verdict.SUSPICIOUS
            risk_score = 72
        elif score > 0:
            verdict = Verdict.SUSPICIOUS
            risk_score = max(40, round(score * 8))
        else:
            verdict = Verdict.UNKNOWN
            risk_score = 0

        evidence = {
            "cvss_base_score": score,
            "severity": severity,
            "vector": vector,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "vuln_status": cve.get("vulnStatus"),
            "description": description,
            "weaknesses": cve.get("weaknesses"),
        }
        return Finding(
            provider=self.name,
            verdict=verdict,
            score=risk_score,
            confidence=90,
            summary=f"NVD rates {indicator.normalized} at CVSS {score or 'N/A'} {severity or ''}.".strip(),
            evidence=evidence,
            reference=f"https://nvd.nist.gov/vuln/detail/{indicator.normalized}",
        )

    @staticmethod
    def _best_cvss(metrics: dict[str, Any]) -> tuple[float, str | None, str | None]:
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if not entries:
                continue
            primary = next((entry for entry in entries if entry.get("type") == "Primary"), entries[0])
            data = primary.get("cvssData", {})
            score = float(data.get("baseScore", 0) or 0)
            severity = data.get("baseSeverity") or primary.get("baseSeverity")
            vector = data.get("vectorString")
            return score, severity, vector
        return 0.0, None, None
