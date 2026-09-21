from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable

import httpx

from .cache import TTLCache
from .config import Settings
from .indicators import parse_indicator
from .models import (
    AnalysisResult,
    Finding,
    Indicator,
    IndicatorType,
    ProviderErrorRecord,
    ProviderState,
)
from .providers.abuseipdb import AbuseIPDBProvider
from .providers.base import Provider
from .providers.greynoise import GreyNoiseProvider
from .providers.nvd import NVDProvider
from .providers.urlhaus import URLhausProvider
from .providers.virustotal import VirusTotalProvider
from .scoring import aggregate_score


class ThreatIntelService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(settings.request_timeout_seconds),
            headers={"User-Agent": settings.user_agent, "Accept": "application/json"},
            follow_redirects=False,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )
        self.providers: list[Provider] = [
            VirusTotalProvider(
                self.client,
                retry_attempts=settings.retry_attempts,
                api_key=settings.virustotal_api_key,
            ),
            AbuseIPDBProvider(
                self.client,
                retry_attempts=settings.retry_attempts,
                api_key=settings.abuseipdb_api_key,
            ),
            URLhausProvider(
                self.client,
                retry_attempts=settings.retry_attempts,
                auth_key=settings.urlhaus_auth_key,
            ),
            GreyNoiseProvider(
                self.client,
                retry_attempts=settings.retry_attempts,
                api_key=settings.greynoise_api_key,
            ),
            NVDProvider(
                self.client,
                retry_attempts=settings.retry_attempts,
                api_key=settings.nvd_api_key,
            ),
        ]
        self.cache: TTLCache[AnalysisResult] = TTLCache(settings.cache_ttl_seconds)

    async def __aenter__(self) -> ThreatIntelService:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self.client.aclose()

    def provider_states(self) -> list[ProviderState]:
        states: list[ProviderState] = []
        for provider in self.providers:
            reason = None
            if not provider.configured:
                reason = "credential not configured"
            states.append(
                ProviderState(
                    name=provider.name,
                    configured=provider.configured,
                    supported_types=sorted(provider.supported_types, key=lambda item: item.value),
                    reason=reason,
                )
            )
        return states

    async def analyze(self, raw_indicator: str) -> AnalysisResult:
        started = time.perf_counter()
        indicator = parse_indicator(raw_indicator)
        cache_key = f"{indicator.type.value}:{indicator.normalized}"
        cached = await self.cache.get(cache_key)
        if cached is not None:
            result = cached.model_copy(deep=True)
            result.tags = sorted(set(result.tags + ["cache_hit"]))
            result.duration_ms = max(0, round((time.perf_counter() - started) * 1000))
            return result

        eligible, skipped = self._eligible_providers(indicator)
        queried: list[str] = []
        findings: list[Finding] = []
        errors: list[ProviderErrorRecord] = []

        if eligible:
            tasks = [self._query_provider(provider, indicator) for provider in eligible]
            outputs = await asyncio.gather(*tasks)
            for provider, finding, error in outputs:
                queried.append(provider.name)
                if finding is not None:
                    findings.append(finding)
                if error is not None:
                    errors.append(ProviderErrorRecord(provider=provider.name, message=error))

        score, verdict, tags = aggregate_score(findings)
        if not indicator.public_routable:
            tags.append("non_public_indicator")

        result = AnalysisResult(
            indicator=indicator,
            verdict=verdict,
            score=score,
            findings=sorted(findings, key=lambda item: item.score, reverse=True),
            queried_providers=queried,
            skipped_providers=skipped,
            errors=errors,
            tags=sorted(set(tags)),
            duration_ms=max(0, round((time.perf_counter() - started) * 1000)),
        )
        await self.cache.set(cache_key, result)
        return result

    async def analyze_batch(self, raw_indicators: Iterable[str]) -> list[AnalysisResult]:
        values = list(raw_indicators)
        if len(values) > self.settings.max_batch_size:
            raise ValueError(f"batch exceeds limit of {self.settings.max_batch_size} indicators")
        semaphore = asyncio.Semaphore(min(8, self.settings.max_batch_size))

        async def run(value: str) -> AnalysisResult:
            async with semaphore:
                return await self.analyze(value)

        return await asyncio.gather(*(run(value) for value in values))

    def _eligible_providers(self, indicator: Indicator) -> tuple[list[Provider], list[str]]:
        eligible: list[Provider] = []
        skipped: list[str] = []
        for provider in self.providers:
            if not provider.supports(indicator):
                continue
            if not provider.configured:
                skipped.append(f"{provider.name}:credential_missing")
                continue
            if not indicator.public_routable and indicator.type in {
                IndicatorType.IP,
                IndicatorType.URL,
            }:
                skipped.append(f"{provider.name}:non_public_indicator")
                continue
            eligible.append(provider)
        return eligible, skipped

    @staticmethod
    async def _query_provider(
        provider: Provider,
        indicator: Indicator,
    ) -> tuple[Provider, Finding | None, str | None]:
        try:
            finding = await provider.enrich(indicator)
            return provider, finding, None
        except Exception as exc:
            return provider, None, str(exc)
