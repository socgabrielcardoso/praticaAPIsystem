import pytest

from pratica_api_system.config import Settings
from pratica_api_system.models import IndicatorType
from pratica_api_system.service import ThreatIntelService


@pytest.mark.asyncio
async def test_private_ip_never_leaves_host():
    settings = Settings(
        virustotal_api_key="test-key",
        abuseipdb_api_key="test-key",
        urlhaus_auth_key="test-key",
        cache_ttl_seconds=0,
    )
    service = ThreatIntelService(settings)
    try:
        result = await service.analyze("10.0.0.1")
    finally:
        await service.close()

    assert result.indicator.type == IndicatorType.IP
    assert result.queried_providers == []
    assert "non_public_indicator" in result.tags
    assert any("non_public_indicator" in item for item in result.skipped_providers)


@pytest.mark.asyncio
async def test_provider_states_do_not_expose_secrets():
    settings = Settings(virustotal_api_key="super-secret-value")
    service = ThreatIntelService(settings)
    try:
        payload = [item.model_dump() for item in service.provider_states()]
    finally:
        await service.close()

    assert "super-secret-value" not in str(payload)
