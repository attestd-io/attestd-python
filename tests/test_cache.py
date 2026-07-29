"""Tests for client-side ResultCache, SessionStats, and AsyncClient batch coalescing."""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

import attestd
from attestd._cache import ResultCache
from attestd.testing import NGINX_SAFE, NGINX_VULNERABLE, SequentialMockAsyncTransport

from tests.conftest import make_client


def test_cache_hit_skips_api_call():
    transport = attestd.testing.SequentialMockTransport(
        [(200, NGINX_VULNERABLE), (200, NGINX_SAFE)]
    )
    client = attestd.Client(
        api_key="atst_test",
        transport=transport,
        max_retries=0,
        cache_policy="runtime",
    )
    first = client.check("nginx", "1.20.0")
    second = client.check("nginx", "1.20.0")
    assert first.risk_state == "high"
    assert second.risk_state == "high"
    assert transport.call_count == 1
    stats = client.stats()
    assert stats.api_calls_made == 1
    assert stats.cache_hits == 1
    assert stats.calls_saved == 1


def test_none_policy_always_hits_api():
    transport = attestd.testing.SequentialMockTransport(
        [(200, NGINX_VULNERABLE), (200, NGINX_SAFE)]
    )
    client = attestd.Client(
        api_key="atst_test",
        transport=transport,
        max_retries=0,
        cache_policy="none",
    )
    client.check("nginx", "1.20.0")
    second = client.check("nginx", "1.20.0")
    assert transport.call_count == 2
    assert second.risk_state == "none"
    assert client.stats().cache_hits == 0


def test_ci_policy_never_expires():
    cache = ResultCache("ci")
    client = make_client([(200, NGINX_VULNERABLE)], cache_policy="ci")
    result = client.check("nginx", "1.20.0")
    # Force time far into the future; ci TTL is infinite.
    with patch("attestd._cache.time.monotonic", return_value=1e12):
        cached = client._cache.get("nginx", "1.20.0")
    assert cached is not None
    assert cached.risk_state == result.risk_state


def test_runtime_ttl_expiry():
    from datetime import datetime, timezone

    from attestd.models import RiskResult

    cache = ResultCache("runtime")
    result = RiskResult(
        product="nginx",
        version="1.20.0",
        risk_state="high",
        risk_factors=[],
        actively_exploited=False,
        remote_exploitable=True,
        authentication_required=False,
        patch_available=True,
        fixed_version="1.27.4",
        confidence=0.85,
        cve_ids=["CVE-2021-23017"],
        last_updated=datetime(2024, 6, 1, 12, tzinfo=timezone.utc),
    )
    with patch("attestd._cache.time.monotonic", return_value=100.0):
        cache.put("nginx", "1.20.0", result)
    with patch("attestd._cache.time.monotonic", return_value=400.0):
        assert cache.get("nginx", "1.20.0") is None  # expired (300s TTL)
    with patch("attestd._cache.time.monotonic", return_value=100.0):
        cache.put("nginx", "1.20.0", result)
    with patch("attestd._cache.time.monotonic", return_value=399.0):
        assert cache.get("nginx", "1.20.0") is not None  # still valid


def test_development_ttl_is_24h():
    from attestd.models import RiskResult
    from datetime import datetime, timezone

    cache = ResultCache("development")
    result = RiskResult(
        product="nginx",
        version="1.20.0",
        risk_state="high",
        risk_factors=[],
        actively_exploited=False,
        remote_exploitable=True,
        authentication_required=False,
        patch_available=True,
        fixed_version="1.27.4",
        confidence=0.85,
        cve_ids=[],
        last_updated=datetime(2024, 6, 1, 12, tzinfo=timezone.utc),
    )
    with patch("attestd._cache.time.monotonic", return_value=0.0):
        cache.put("nginx", "1.20.0", result)
    with patch("attestd._cache.time.monotonic", return_value=86_399.0):
        assert cache.get("nginx", "1.20.0") is not None
    with patch("attestd._cache.time.monotonic", return_value=86_400.0):
        assert cache.get("nginx", "1.20.0") is None


def test_invalidate_cache_forces_refetch():
    transport = attestd.testing.SequentialMockTransport(
        [(200, NGINX_VULNERABLE), (200, NGINX_SAFE)]
    )
    client = attestd.Client(
        api_key="atst_test",
        transport=transport,
        max_retries=0,
        cache_policy="runtime",
    )
    client.check("nginx", "1.20.0")
    client.invalidate_cache("nginx", "1.20.0")
    second = client.check("nginx", "1.20.0")
    assert transport.call_count == 2
    assert second.risk_state == "none"
    assert client.stats().api_calls_made == 2
    assert client.stats().cache_hits == 0


def test_stats_calls_saved():
    client = make_client(
        [(200, NGINX_VULNERABLE)],
        cache_policy="runtime",
    )
    client.check("nginx", "1.20.0")
    client.check("nginx", "1.20.0")
    client.check("nginx", "1.20.0")
    stats = client.stats()
    assert stats.api_calls_made == 1
    assert stats.cache_hits == 2
    assert stats.batch_saves == 0
    assert stats.calls_saved == 2


def test_batch_check_uses_cache():
    client = make_client(
        [(200, {"results": [{"product": "nginx", "version": "1.20.0", "result": NGINX_VULNERABLE}]})],
        cache_policy="runtime",
    )
    first = client.batch_check([("nginx", "1.20.0")])
    second = client.batch_check([("nginx", "1.20.0")])
    assert first[0] is not None
    assert second[0] is not None
    assert first[0].risk_state == second[0].risk_state
    assert client.stats().api_calls_made == 1
    assert client.stats().cache_hits == 1


def test_exports():
    assert hasattr(attestd, "SessionStats")
    assert hasattr(attestd, "CachePolicy")
    assert attestd.__version__ == "0.7.0"


@pytest.mark.asyncio
async def test_async_batch_coalescing():
    """Three concurrent check() calls coalesce into one batch request."""
    batch_body = {
        "results": [
            {"product": "nginx", "version": "1.20.0", "result": NGINX_VULNERABLE},
            {"product": "nginx", "version": "1.27.4", "result": NGINX_SAFE},
            {
                "product": "log4j",
                "version": "2.14.1",
                "result": {
                    **NGINX_VULNERABLE,
                    "product": "log4j",
                    "version": "2.14.1",
                    "risk_state": "critical",
                },
            },
        ]
    }
    transport = SequentialMockAsyncTransport([(200, batch_body)])
    client = attestd.AsyncClient(
        api_key="atst_test",
        transport=transport,
        max_retries=0,
        cache_policy="none",
        batch_window_ms=5,
    )
    r1, r2, r3 = await asyncio.gather(
        client.check("nginx", "1.20.0"),
        client.check("nginx", "1.27.4"),
        client.check("log4j", "2.14.1"),
    )
    assert r1.risk_state == "high"
    assert r2.risk_state == "none"
    assert r3.risk_state == "critical"
    assert transport.call_count == 1
    stats = client.stats()
    assert stats.api_calls_made == 3
    assert stats.batch_saves == 2
    assert stats.calls_saved == 2
    await client.aclose()


@pytest.mark.asyncio
async def test_async_cache_hit_skips_batch():
    # Single pending key uses GET /v1/check, so the mock returns a check body.
    transport = SequentialMockAsyncTransport([(200, NGINX_VULNERABLE)])
    client = attestd.AsyncClient(
        api_key="atst_test",
        transport=transport,
        max_retries=0,
        cache_policy="runtime",
        batch_window_ms=5,
    )
    first = await client.check("nginx", "1.20.0")
    second = await client.check("nginx", "1.20.0")
    assert first.risk_state == second.risk_state == "high"
    assert transport.call_count == 1
    assert client.stats().cache_hits == 1
    await client.aclose()
