"""
Tests for the synchronous Client.

All tests use _SequentialTransport to avoid real network calls.
"""

from __future__ import annotations

import pytest

import attestd
from attestd import Client
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
    make_client,
)


# ---------------------------------------------------------------------------
# Happy path — supported product
# ---------------------------------------------------------------------------

def test_check_returns_risk_result():
    client = make_client([(200, SUPPORTED_NGINX_BODY)])
    result = client.check("nginx", "1.20.0")
    assert result.product == "nginx"
    assert result.version == "1.20.0"
    assert result.risk_state == "high"
    assert result.actively_exploited is False
    assert result.remote_exploitable is True
    assert result.authentication_required is False
    assert result.patch_available is True
    assert result.fixed_version == "1.27.4"
    assert result.confidence == pytest.approx(0.85)
    assert "CVE-2021-23017" in result.cve_ids
    assert result.last_updated is not None


def test_check_critical_state():
    client = make_client([(200, LOG4J_CRITICAL_BODY)])
    result = client.check("log4j", "2.14.1")
    assert result.risk_state == "critical"
    assert result.actively_exploited is True
    assert "active_exploitation" in result.risk_factors
    assert "CVE-2021-44228" in result.cve_ids


def test_check_fixed_version_none():
    body = {**SUPPORTED_NGINX_BODY, "fixed_version": None, "patch_available": False}
    client = make_client([(200, body)])
    result = client.check("nginx", "1.20.0")
    assert result.fixed_version is None
    assert result.patch_available is False


def test_check_risk_factors_empty_for_none_state():
    body = {
        **SUPPORTED_NGINX_BODY,
        "risk_state": "none",
        "risk_factors": [],
        "actively_exploited": False,
        "remote_exploitable": False,
        "authentication_required": False,
        "patch_available": False,
        "fixed_version": None,
    }
    client = make_client([(200, body)])
    result = client.check("nginx", "1.27.4")
    assert result.risk_state == "none"
    assert result.risk_factors == []


def test_supply_chain_signal_parsed():
    from attestd.testing import LITELLM_COMPROMISED, MockTransport

    client = Client(
        api_key="atst_test",
        transport=MockTransport(200, LITELLM_COMPROMISED),
    )
    result = client.check("litellm", "1.82.7")
    assert result.supply_chain is not None
    assert result.supply_chain.compromised is True
    assert "registry" in result.supply_chain.sources
    assert result.supply_chain.malware_type == "backdoor"


# ---------------------------------------------------------------------------
# Unsupported product
# ---------------------------------------------------------------------------

def test_check_unsupported_raises():
    client = make_client([(200, UNSUPPORTED_BODY)])
    with pytest.raises(AttestdUnsupportedProductError) as exc_info:
        client.check("someunknownproduct", "1.0.0")
    assert exc_info.value.product == "someunknownproduct"
    assert exc_info.value.version == "1.0.0"


def test_unsupported_error_message_contains_docs_link():
    client = make_client([(200, UNSUPPORTED_BODY)])
    with pytest.raises(AttestdUnsupportedProductError) as exc_info:
        client.check("unknown", "1.0.0")
    assert "attestd.io/docs" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Auth error
# ---------------------------------------------------------------------------

def test_401_raises_auth_error():
    client = make_client([(401, {"detail": "Unauthorized"})])
    with pytest.raises(AttestdAuthError):
        client.check("nginx", "1.20.0")


def test_auth_error_is_attestd_error():
    client = make_client([(401, {})])
    with pytest.raises(attestd.AttestdError):
        client.check("nginx", "1.20.0")


# ---------------------------------------------------------------------------
# Rate limit
# ---------------------------------------------------------------------------

def test_429_raises_rate_limit_error():
    client = make_client([(429, {}, {"Retry-After": "60"})])
    with pytest.raises(AttestdRateLimitError) as exc_info:
        client.check("nginx", "1.20.0")
    assert exc_info.value.retry_after == 60


def test_429_without_retry_after_header():
    client = make_client([(429, {})])
    with pytest.raises(AttestdRateLimitError) as exc_info:
        client.check("nginx", "1.20.0")
    assert exc_info.value.retry_after is None


def test_429_parses_retry_after_http_date():
    from datetime import datetime, timedelta, timezone
    from email.utils import format_datetime

    retry_at = datetime.now(tz=timezone.utc) + timedelta(seconds=120)
    header = format_datetime(retry_at, usegmt=True)
    client = make_client([(429, {}, {"Retry-After": header})])
    with pytest.raises(AttestdRateLimitError) as exc_info:
        client.check("nginx", "1.20.0")
    assert exc_info.value.retry_after is not None
    assert 110 <= exc_info.value.retry_after <= 130


def test_unsupported_with_typosquat_attaches_signal():
    body = {
        "supported": False,
        "typosquat": {
            "detected": True,
            "resembles": "langchain",
            "confidence": 0.92,
            "ecosystem": "pypi",
        },
    }
    client = make_client([(200, body)])
    with pytest.raises(AttestdUnsupportedProductError) as exc_info:
        client.check("langchian", "1.0.0")
    assert exc_info.value.typosquat is not None
    assert exc_info.value.typosquat.detected is True
    assert exc_info.value.typosquat.resembles == "langchain"


def test_missing_last_updated_raises_api_error():
    body = {**SUPPORTED_NGINX_BODY}
    del body["last_updated"]
    client = make_client([(200, body)])
    with pytest.raises(AttestdAPIError) as exc_info:
        client.check("nginx", "1.20.0")
    assert "last_updated" in str(exc_info.value)


def test_missing_supported_raises_api_error():
    body = {**SUPPORTED_NGINX_BODY}
    del body["supported"]
    client = make_client([(200, body)])
    with pytest.raises(AttestdAPIError) as exc_info:
        client.check("nginx", "1.20.0")
    assert "supported" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Server errors and retry
# ---------------------------------------------------------------------------

def test_500_raises_api_error_with_no_retries():
    client = make_client([(500, {})], max_retries=0)
    with pytest.raises(AttestdAPIError) as exc_info:
        client.check("nginx", "1.20.0")
    assert exc_info.value.status_code == 500


def test_retry_succeeds_on_second_attempt():
    """First response is 503, second is 200 — should succeed after one retry."""
    client = make_client(
        [(503, {}), (200, SUPPORTED_NGINX_BODY)],
        max_retries=1,
    )
    result = client.check("nginx", "1.20.0")
    assert result.risk_state == "high"


def test_retry_exhausted_raises_api_error():
    """Three 500s with max_retries=2 — should raise after three total attempts."""
    client = make_client(
        [(500, {}), (500, {}), (500, {})],
        max_retries=2,
    )
    with pytest.raises(AttestdAPIError):
        client.check("nginx", "1.20.0")


def test_401_does_not_retry():
    """
    401 is surfaced immediately — only one request should be made even if
    max_retries > 0.
    """
    from attestd.testing import SequentialMockTransport as _SequentialTransport
    transport = _SequentialTransport([(401, {})])
    client = Client(
        api_key="bad_key",
        transport=transport,
        max_retries=3,
    )
    with pytest.raises(AttestdAuthError):
        client.check("nginx", "1.20.0")
    # Only one request was made — transport index is 1
    assert transport._idx == 1


def test_429_does_not_retry():
    """429 is surfaced immediately without retry."""
    from attestd.testing import SequentialMockTransport as _SequentialTransport
    transport = _SequentialTransport([(429, {}, {"Retry-After": "60"})])
    client = Client(
        api_key="atst_test",
        transport=transport,
        max_retries=3,
    )
    with pytest.raises(AttestdRateLimitError):
        client.check("nginx", "1.20.0")
    assert transport._idx == 1


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------

def test_context_manager():
    """Client can be used as a context manager."""
    with make_client([(200, SUPPORTED_NGINX_BODY)]) as client:
        result = client.check("nginx", "1.20.0")
    assert result.risk_state == "high"


# ---------------------------------------------------------------------------
# Module-level exports
# ---------------------------------------------------------------------------

def test_top_level_exports():
    assert hasattr(attestd, "Client")
    assert hasattr(attestd, "AsyncClient")
    assert hasattr(attestd, "RiskResult")
    assert hasattr(attestd, "SupplyChainSignal")
    assert hasattr(attestd, "TyposquatSignal")
    assert hasattr(attestd, "AttestdError")
    assert hasattr(attestd, "AttestdAuthError")
    assert hasattr(attestd, "AttestdRateLimitError")
    assert hasattr(attestd, "AttestdUnsupportedProductError")
    assert hasattr(attestd, "AttestdAPIError")
    assert hasattr(attestd, "__version__")
