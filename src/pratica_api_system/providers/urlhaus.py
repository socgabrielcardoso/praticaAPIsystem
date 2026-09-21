from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from pydantic import SecretStr

from ..models import Finding, Indicator, IndicatorType, Verdict
from .base import Provider


class URLhausProvider(Provider):
    name = "URLhaus"
    supported_types = frozenset({IndicatorType.IP, IndicatorType.DOMAIN, IndicatorType.URL})
    _url_endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    _host_endpoint = "https://urlhaus-api.abuse.ch/v1/host/"

    def __init__(self, *args: Any, auth_key: SecretStr | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._auth_key = auth_key

    @property
    def configured(self) -> bool:
        return bool(self._auth_key and self._auth_key.get_secret_value().strip())

    async def enrich(self, indicator: Indicator) -> Finding | None:
        if not self.configured:
            return None

        if indicator.type == IndicatorType.URL:
            endpoint = self._url_endpoint
            form = {"url": indicator.normalized}
        else:
            endpoint = self._host_endpoint
            form = {"host": indicator.normalized}

        payload = await self.request_json(
            "POST",
            endpoint,
            headers={"Auth-Key": self._auth_key.get_secret_value()},
            data=form,
        )
        status = str(payload.get("query_status", "")).lower()
        if status == "no_results":
            return Finding(
                provider=self.name,
                verdict=Verdict.UNKNOWN,
                score=0,
                confidence=65,
                summary=(
                    "URLhaus has no matching record. "
                    "Absence of a record is not a benign verdict."
                ),
            )
        if status != "ok":
            return Finding(
                provider=self.name,
                verdict=Verdict.UNKNOWN,
                score=0,
                confidence=40,
                summary=f"URLhaus returned query status: {status or 'unknown'}.",
            )

        online = str(payload.get("url_status", "")).lower() == "online"
        url_count = int(payload.get("url_count", 0) or 0)
        threat = payload.get("threat")
        score = 95 if online else 88
        if indicator.type != IndicatorType.URL and url_count > 0:
            score = min(100, 80 + min(url_count, 20))

        reference = payload.get("urlhaus_reference")
        evidence = {
            "query_status": status,
            "url_status": payload.get("url_status"),
            "threat": threat,
            "url_count": url_count,
            "first_seen": payload.get("firstseen") or payload.get("date_added"),
            "last_online": payload.get("last_online"),
            "tags": payload.get("tags"),
            "blacklists": payload.get("blacklists"),
        }
        host = (
            urlsplit(indicator.normalized).hostname
            if indicator.type == IndicatorType.URL
            else indicator.normalized
        )
        return Finding(
            provider=self.name,
            verdict=Verdict.MALICIOUS,
            score=score,
            confidence=95,
            summary=f"URLhaus has a malware distribution record associated with {host}.",
            evidence=evidence,
            reference=reference,
        )
