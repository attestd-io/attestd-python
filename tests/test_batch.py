"""
Tests for batch_check / AsyncClient.batch_check.

Uses SequentialMockTransport via conftest helpers — no real network calls.
"""

from __future__ import annotations

import pytest

import attestd
from attestd.errors import AttestdError, AttestdRateLimitError

from tests.conftest import (
    LOG4J_CRITICAL_BODY,
    SUPPORTED_NGINX_BODY,
    UNSUPPORTED_BODY,
    make_async_client,
    make_client,
)

BATCH_HAPPY = {
    "results": [
        {"product": "nginx", "version": "1.25.3", "result": SUPPORTED_NGINX_BODY},
        {"product": "log4j", "version": "2.14.1", "result": LOG4J_CRITICAL_BODY},
    ]
}

BATCH_MIXED = {
    "results": [
        {"product": "nginx", "version": "1.25.3", "result": SUPPORTED_NGINX_BODY},
        {"product": "fake", "version": "9.9.9", "result": UNSUPPORTED_BODY},
    ]
}


# ---------------------------------------------------------------------------
# Sync batch_check
# ---------------------------------------------------------------------------


def test_batch_happy_path():
    client = make_client([(200, BATCH_HAPPY)])
    results = client.batch_check([("nginx", "1.25.3"), ("log4j", "2.14.1")])
    assert len(results) == 2
    assert results[0] is not None
    assert results[0].product == "nginx"
    assert results[0].risk_state == "high"
    assert results[1] is not None
    assert results[1].product == "log4j"
    assert results[1].risk_state == "critical"


def test_batch_mixed_supported_unsupported():
    client = make_client([(200, BATCH_MIXED)])
    results = client.batch_check([("nginx", "1.25.3"), ("fake", "9.9.9")])
    assert len(results) == 2
    assert results[0] is not None
    assert results[0].product == "nginx"
    assert results[1] is None


def test_batch_empty_list():
    client = make_client([])
    assert client.batch_check([]) == []


def test_batch_over_limit_raises():
    client = make_client([])
    items = [(f"product-{i}", "1.0.0") for i in range(101)]
    with pytest.raises(AttestdError, match="at most 100"):
        client.batch_check(items)


def test_batch_429_raises_rate_limit_error():
    client = make_client([(429, {}, {"Retry-After": "60"})])
    with pytest.raises(AttestdRateLimitError) as exc_info:
        client.batch_check([("nginx", "1.25.3")])
    assert exc_info.value.retry_after == 60


# ---------------------------------------------------------------------------
# Async batch_check
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_batch_happy_path():
    client = make_async_client([(200, BATCH_HAPPY)])
    results = await client.batch_check([("nginx", "1.25.3"), ("log4j", "2.14.1")])
    assert len(results) == 2
    assert results[0] is not None
    assert results[0].product == "nginx"
    assert results[1] is not None
    assert results[1].risk_state == "critical"


@pytest.mark.asyncio
async def test_async_batch_mixed_supported_unsupported():
    client = make_async_client([(200, BATCH_MIXED)])
    results = await client.batch_check([("nginx", "1.25.3"), ("fake", "9.9.9")])
    assert results[0] is not None
    assert results[1] is None


@pytest.mark.asyncio
async def test_async_batch_empty_list():
    client = make_async_client([])
    assert await client.batch_check([]) == []


@pytest.mark.asyncio
async def test_async_batch_over_limit_raises():
    client = make_async_client([])
    items = [(f"product-{i}", "1.0.0") for i in range(101)]
    with pytest.raises(AttestdError, match="at most 100"):
        await client.batch_check(items)


@pytest.mark.asyncio
async def test_async_batch_429_raises_rate_limit_error():
    client = make_async_client([(429, {}, {"Retry-After": "60"})])
    with pytest.raises(AttestdRateLimitError) as exc_info:
        await client.batch_check([("nginx", "1.25.3")])
    assert exc_info.value.retry_after == 60
