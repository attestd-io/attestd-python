"""
Tests for batch_check / AsyncClient.batch_check.

Uses SequentialMockTransport via conftest helpers — no real network calls.
"""

from __future__ import annotations

import json

import pytest

import attestd
from attestd.errors import AttestdAPIError, AttestdError, AttestdRateLimitError

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


def test_batch_short_results_raises():
    client = make_client(
        [
            (
                200,
                {
                    "results": [
                        {
                            "product": "nginx",
                            "version": "1.25.3",
                            "result": SUPPORTED_NGINX_BODY,
                        }
                    ]
                },
            )
        ]
    )
    with pytest.raises(AttestdAPIError, match="expected 2 results, got 1"):
        client.batch_check([("nginx", "1.25.3"), ("log4j", "2.14.1")])


def test_batch_extra_results_raises():
    client = make_client(
        [
            (
                200,
                {
                    "results": [
                        {
                            "product": "nginx",
                            "version": "1.25.3",
                            "result": SUPPORTED_NGINX_BODY,
                        },
                        {
                            "product": "log4j",
                            "version": "2.14.1",
                            "result": LOG4J_CRITICAL_BODY,
                        },
                        {
                            "product": "redis",
                            "version": "7.0.0",
                            "result": SUPPORTED_NGINX_BODY,
                        },
                    ]
                },
            )
        ]
    )
    with pytest.raises(AttestdAPIError, match="expected 2 results, got 3"):
        client.batch_check([("nginx", "1.25.3"), ("log4j", "2.14.1")])


def test_batch_empty_list():
    client = make_client([])
    assert client.batch_check([]) == []


def test_batch_over_limit_raises():
    client = make_client([])
    items = [(f"product-{i}", "1.0.0") for i in range(101)]
    with pytest.raises(AttestdError, match="at most 100"):
        client.batch_check(items)


def test_batch_trims_product_and_version():
    from attestd.testing import SequentialMockTransport

    class Recording(SequentialMockTransport):
        def __init__(self, responses):
            super().__init__(responses)
            self.bodies = []

        def handle_request(self, request):
            self.bodies.append(request.content)
            return super().handle_request(request)

    transport = Recording([(200, BATCH_HAPPY)])
    client = attestd.Client(
        api_key="atst_test",
        transport=transport,
        max_retries=0,
        cache_policy="none",
    )
    client.batch_check([(" nginx ", " 1.25.3 "), (" log4j ", " 2.14.1 ")])
    payload = json.loads(transport.bodies[0])
    assert payload["items"] == [
        {"product": "nginx", "version": "1.25.3"},
        {"product": "log4j", "version": "2.14.1"},
    ]


def test_batch_whitespace_only_item_raises_without_request():
    client = make_client([])
    with pytest.raises(AttestdError, match="product and version are required"):
        client.batch_check([("nginx", "1.25.3"), ("  ", "1.0.0")])


def test_batch_429_raises_rate_limit_error():
    client = make_client([(429, {}, {"Retry-After": "60"})])
    with pytest.raises(AttestdRateLimitError) as exc_info:
        client.batch_check([("nginx", "1.25.3")])
    assert exc_info.value.retry_after == 60


def test_batch_omits_include_by_default():
    from attestd.testing import SequentialMockTransport

    class Recording(SequentialMockTransport):
        def __init__(self, responses):
            super().__init__(responses)
            self.urls = []

        def handle_request(self, request):
            self.urls.append(str(request.url))
            return super().handle_request(request)

    transport = Recording([(200, BATCH_HAPPY)])
    client = attestd.Client(
        api_key="atst_test",
        transport=transport,
        max_retries=0,
        cache_policy="none",
    )
    client.batch_check([("nginx", "1.25.3"), ("log4j", "2.14.1")])
    assert transport.urls[0].endswith("/v1/check/batch")
    assert "include=" not in transport.urls[0]


def test_batch_sends_include_cves():
    from attestd.testing import SequentialMockTransport

    class Recording(SequentialMockTransport):
        def __init__(self, responses):
            super().__init__(responses)
            self.urls = []

        def handle_request(self, request):
            self.urls.append(str(request.url))
            return super().handle_request(request)

    transport = Recording([(200, BATCH_HAPPY)])
    client = attestd.Client(
        api_key="atst_test",
        transport=transport,
        max_retries=0,
        cache_policy="none",
    )
    client.batch_check(
        [("nginx", "1.25.3"), ("log4j", "2.14.1")],
        include=["cves"],
    )
    assert "include=cves" in transport.urls[0]


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
async def test_async_batch_whitespace_only_item_raises_without_request():
    client = make_async_client([])
    with pytest.raises(AttestdError, match="product and version are required"):
        await client.batch_check([("nginx", "1.25.3"), ("  ", "1.0.0")])


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
