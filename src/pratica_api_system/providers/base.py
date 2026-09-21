from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from ..models import Finding, Indicator, IndicatorType


class ProviderError(RuntimeError):
    pass


class ProviderAuthError(ProviderError):
    pass


class ProviderRateLimitError(ProviderError):
    pass


class Provider(ABC):
    name: str
    supported_types: frozenset[IndicatorType]

    def __init__(self, client: httpx.AsyncClient, retry_attempts: int = 2) -> None:
        self.client = client
        self.retry_attempts = retry_attempts

    @property
    @abstractmethod
    def configured(self) -> bool:
        raise NotImplementedError

    def supports(self, indicator: Indicator) -> bool:
        return indicator.type in self.supported_types

    @abstractmethod
    async def enrich(self, indicator: Indicator) -> Finding | None:
        raise NotImplementedError

    async def request_json(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        last_error: Exception | None = None
        retryable = {429, 500, 502, 503, 504}

        for attempt in range(self.retry_attempts + 1):
            try:
                response = await self.client.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    data=data,
                )
            except httpx.HTTPError as exc:
                last_error = exc
                if attempt >= self.retry_attempts:
                    break
                await asyncio.sleep(min(0.5 * (2**attempt), 4.0))
                continue

            if response.status_code in {401, 403}:
                raise ProviderAuthError(f"{self.name} rejected the configured credential")
            if response.status_code == 404:
                return {"_not_found": True}
            if response.status_code in retryable:
                if attempt >= self.retry_attempts:
                    if response.status_code == 429:
                        raise ProviderRateLimitError(f"{self.name} rate limit reached")
                    raise ProviderError(f"{self.name} returned HTTP {response.status_code}")
                await asyncio.sleep(self._retry_delay(response, attempt))
                continue

            try:
                response.raise_for_status()
                payload = response.json()
            except (httpx.HTTPError, ValueError) as exc:
                raise ProviderError(f"invalid response from {self.name}") from exc
            if not isinstance(payload, dict):
                raise ProviderError(f"unexpected response shape from {self.name}")
            return payload

        raise ProviderError(f"{self.name} request failed") from last_error

    @staticmethod
    def _retry_delay(response: httpx.Response, attempt: int) -> float:
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                return min(float(retry_after), 10.0)
            except ValueError:
                try:
                    target = parsedate_to_datetime(retry_after)
                    seconds = max(0.0, target.timestamp() - __import__("time").time())
                    return min(seconds, 10.0)
                except (TypeError, ValueError, OverflowError):
                    pass
        return min(0.5 * (2**attempt), 4.0)
