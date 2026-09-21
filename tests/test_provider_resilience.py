import httpx
import pytest

from pratica_api_system.models import Indicator, IndicatorType
from pratica_api_system.providers.base import Provider, ProviderAuthError


class DummyProvider(Provider):
    name = "Dummy"
    supported_types = frozenset({IndicatorType.IP})

    @property
    def configured(self) -> bool:
        return True

    async def enrich(self, indicator: Indicator):
        return None


@pytest.mark.asyncio
async def test_retry_recovers_from_transient_failure():
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(503, request=request)
        return httpx.Response(200, json={"ok": True}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = DummyProvider(client, retry_attempts=1)
        payload = await provider.request_json("GET", "https://example.test/intel")

    assert payload == {"ok": True}
    assert calls == 2


@pytest.mark.asyncio
async def test_authentication_failure_is_not_hidden():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = DummyProvider(client, retry_attempts=0)
        with pytest.raises(ProviderAuthError):
            await provider.request_json("GET", "https://example.test/intel")


@pytest.mark.asyncio
async def test_not_found_becomes_explicit_signal():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = DummyProvider(client, retry_attempts=0)
        payload = await provider.request_json("GET", "https://example.test/intel")

    assert payload == {"_not_found": True}
