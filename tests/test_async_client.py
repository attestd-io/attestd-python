"""
Tests for the asynchronous AsyncClient.

Mirrors test_client.py but exercises the async code paths and retry logic
with asyncio.sleep (sleep is not actually called because max_retries=0 in
most tests, or the success case terminates the retry loop early).
"""

from __future__ import annotations

import pytest

from attestd import AsyncClient
from attestd.errors import (
    AttestdAPIError,
    AttestdAuthError,
    AttestdRateLimitError,
    AttestdUnsupportedProductError,
)

from tests.conftest import (
    LOG4J_CRITICAL_BODY,
    SUPPORTED_NGINX_BODY,
    UNSUPPORTED_BODY,
    make_async_client,
)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

async def test_check_returns_risk_result():
    async with make_async_client([(200, SUPPORTED_NGINX_BODY)]) as client:
        result = await client.check("nginx", "1.20.0")
    assert result.product == "nginx"
    assert result.risk_state == "high"
    assert result.actively_exploited is False
    assert result.remote_exploitable is True
    assert "CVE-2021-23017" in result.cve_ids


async def test_check_critical_state():
    async with make_async_client([(200, LOG4J_CRITICAL_BODY)]) as client:
        result = await client.check("log4j", "2.14.1")
    assert result.risk_state == "critical"
    assert result.actively_exploited is True
    assert "CVE-2021-44228" in result.cve_ids


async def test_supply_chain_signal_parsed():
    from attestd.testing import LITELLM_COMPROMISED, MockAsyncTransport

    transport = MockAsyncTransport(200, LITELLM_COMPROMISED)
    async with AsyncClient(api_key="atst_test", transport=transport) as client:
        result = await client.check("litellm", "1.82.7")
    assert result.supply_chain is not None
    assert result.supply_chain.compromised is True
    assert "registry" in result.supply_chain.sources


# ---------------------------------------------------------------------------
# Unsupported product
# ---------------------------------------------------------------------------

async def test_unsupported_raises():
    async with make_async_client([(200, UNSUPPORTED_BODY)]) as client:
        with pytest.raises(AttestdUnsupportedProductError) as exc_info:
            await client.check("unknown", "1.0.0")
    assert exc_info.value.product == "unknown"
    assert exc_info.value.version == "1.0.0"


# ---------------------------------------------------------------------------
# Auth error
# ---------------------------------------------------------------------------

async def test_401_raises_auth_error():
    async with make_async_client([(401, {})]) as client:
        with pytest.raises(AttestdAuthError):
            await client.check("nginx", "1.20.0")


# ---------------------------------------------------------------------------
# Rate limit
# ---------------------------------------------------------------------------

async def test_429_raises_rate_limit_error_with_retry_after():
    async with make_async_client([(429, {}, {"Retry-After": "30"})]) as client:
        with pytest.raises(AttestdRateLimitError) as exc_info:
            await client.check("nginx", "1.20.0")
    assert exc_info.value.retry_after == 30


async def test_429_without_retry_after_header():
    async with make_async_client([(429, {})]) as client:
        with pytest.raises(AttestdRateLimitError) as exc_info:
            await client.check("nginx", "1.20.0")
    assert exc_info.value.retry_after is None


# ---------------------------------------------------------------------------
# Retry
# ---------------------------------------------------------------------------

async def test_retry_succeeds_on_second_attempt():
    """First 503, second 200 — succeeds after one retry."""
    client = make_async_client(
        [(503, {}), (200, SUPPORTED_NGINX_BODY)],
        max_retries=1,
    )
    async with client:
        result = await client.check("nginx", "1.20.0")
    assert result.risk_state == "high"


async def test_retry_exhausted_raises_api_error():
    """Two 500s with max_retries=1 — raises AttestdAPIError."""
    client = make_async_client(
        [(500, {}), (500, {})],
        max_retries=1,
    )
    async with client:
        with pytest.raises(AttestdAPIError):
            await client.check("nginx", "1.20.0")


async def test_401_does_not_retry():
    """401 is raised immediately — only one request made."""
    from attestd.testing import SequentialMockAsyncTransport as _AsyncSequentialTransport
    transport = _AsyncSequentialTransport([(401, {})])
    client = AsyncClient(
        api_key="bad_key",
        transport=transport,
        max_retries=3,
    )
    async with client:
        with pytest.raises(AttestdAuthError):
            await client.check("nginx", "1.20.0")
    assert transport._idx == 1


async def test_429_does_not_retry():
    """429 is raised immediately — only one request made."""
    from attestd.testing import SequentialMockAsyncTransport as _AsyncSequentialTransport
    transport = _AsyncSequentialTransport([(429, {}, {"Retry-After": "60"})])
    client = AsyncClient(
        api_key="atst_test",
        transport=transport,
        max_retries=3,
    )
    async with client:
        with pytest.raises(AttestdRateLimitError):
            await client.check("nginx", "1.20.0")
    assert transport._idx == 1


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------

async def test_async_context_manager():
    async with make_async_client([(200, SUPPORTED_NGINX_BODY)]) as client:
        result = await client.check("nginx", "1.20.0")
    assert result.risk_state == "high"


async def test_aclose_is_idempotent():
    """aclose() can be called explicitly without double-closing on __aexit__."""
    client = make_async_client([(200, SUPPORTED_NGINX_BODY)])
    result = await client.check("nginx", "1.20.0")
    await client.aclose()
    # No exception raised
    assert result.product == "nginx"
