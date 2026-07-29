"""
Shared test fixtures for the Attestd SDK tests.

Uses attestd.testing transports — the same ones documented for end-user
integration testing. This verifies the testing module works correctly and
avoids duplicating transport logic.
"""

from __future__ import annotations

from typing import Any

import pytest

import attestd
from attestd import AsyncClient, Client
from attestd.testing import (
    LOG4J_CRITICAL,
    NGINX_SAFE,
    NGINX_VULNERABLE,
    UNSUPPORTED,
    SequentialMockAsyncTransport,
    SequentialMockTransport,
)

# Re-export response bodies used in test files under the names tests expect
SUPPORTED_NGINX_BODY = NGINX_VULNERABLE
LOG4J_CRITICAL_BODY = LOG4J_CRITICAL
UNSUPPORTED_BODY = UNSUPPORTED

# Re-export transport classes under the names tests expect
_SequentialTransport = SequentialMockTransport
_AsyncSequentialTransport = SequentialMockAsyncTransport


def make_client(
    responses: list[tuple],
    max_retries: int = 0,
    **kwargs: Any,
) -> Client:
    """Return a Client backed by a SequentialMockTransport.

    Defaults to cache_policy=\"none\" so each call exercises the transport.
    Pass cache_policy explicitly when testing the cache layer.
    """
    kwargs.setdefault("cache_policy", "none")
    return Client(
        api_key="atst_test_key",
        transport=SequentialMockTransport(responses),
        max_retries=max_retries,
        **kwargs,
    )


def make_async_client(
    responses: list[tuple],
    max_retries: int = 0,
    **kwargs: Any,
) -> AsyncClient:
    """Return an AsyncClient backed by a SequentialMockAsyncTransport.

    Defaults to cache_policy=\"none\" so each call exercises the transport.
    Pass cache_policy explicitly when testing the cache layer.
    """
    kwargs.setdefault("cache_policy", "none")
    kwargs.setdefault("batch_window_ms", 0)
    return AsyncClient(
        api_key="atst_test_key",
        transport=SequentialMockAsyncTransport(responses),
        max_retries=max_retries,
        **kwargs,
    )
