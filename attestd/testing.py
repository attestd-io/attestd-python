"""
Testing utilities for the Attestd SDK.

Provides httpx transports that return pre-defined responses without making
real network calls. Inject them via the ``transport`` parameter on
:class:`~attestd.Client` or :class:`~attestd.AsyncClient`.

The primary use case is testing the security branching logic in your own
code. Test the paths that handle ``critical`` vs ``high`` risk states, the
``AttestdUnsupportedProductError`` policy, retry behaviour, etc. against
controlled, reproducible API responses.

Example: testing a deployment gate.

    from attestd.testing import MockTransport, NGINX_VULNERABLE

    def test_deployment_blocked_on_critical():
        transport = MockTransport(200, NGINX_VULNERABLE | {"risk_state": "critical"})
        client = attestd.Client(api_key="test", transport=transport)

        with pytest.raises(SystemExit):
            run_deployment_gate(client, "nginx", "1.20.0")

Example: testing retry handling in an async agent tool.

    from attestd.testing import SequentialMockAsyncTransport

    async def test_tool_retries_on_503():
        transport = SequentialMockAsyncTransport([
            (503, {}),            # first attempt fails
            (200, NGINX_SAFE),    # second attempt succeeds
        ])
        client = attestd.AsyncClient(api_key="test", transport=transport, max_retries=1)
        result = await my_agent_tool(client, "nginx", "1.27.4")
        assert result["risk_state"] == "none"

Example: testing the "outside coverage" policy branch.

    from attestd.testing import MockTransport, UNSUPPORTED

    def test_outside_coverage_blocks_by_default():
        transport = MockTransport(200, UNSUPPORTED)
        client = attestd.Client(api_key="test", transport=transport)

        with pytest.raises(attestd.AttestdUnsupportedProductError):
            # verify your code raises, not silently allows
            run_check(client, "unknownproduct", "1.0.0")
"""

from __future__ import annotations

from typing import Any

import httpx


# ---------------------------------------------------------------------------
# Ready-made response bodies for common test scenarios
# ---------------------------------------------------------------------------

#: A supported product response with risk_state="none" (safe version).
NGINX_SAFE: dict[str, Any] = {
    "product": "nginx",
    "version": "1.27.4",
    "supported": True,
    "risk_state": "none",
    "risk_factors": [],
    "actively_exploited": False,
    "remote_exploitable": False,
    "authentication_required": False,
    "patch_available": False,
    "fixed_version": None,
    "confidence": 0.9,
    "cve_ids": [],
    "last_updated": "2024-06-01T12:00:00+00:00",
}

#: A supported product response with risk_state="high".
NGINX_VULNERABLE: dict[str, Any] = {
    "product": "nginx",
    "version": "1.20.0",
    "supported": True,
    "risk_state": "high",
    "risk_factors": ["remote_code_execution", "no_authentication_required"],
    "actively_exploited": False,
    "remote_exploitable": True,
    "authentication_required": False,
    "patch_available": True,
    "fixed_version": "1.27.4",
    "confidence": 0.85,
    "cve_ids": ["CVE-2021-23017"],
    "last_updated": "2024-06-01T12:00:00+00:00",
}

#: A supported product response with risk_state="critical" (actively exploited).
LOG4J_CRITICAL: dict[str, Any] = {
    "product": "log4j",
    "version": "2.14.1",
    "supported": True,
    "risk_state": "critical",
    "risk_factors": [
        "active_exploitation",
        "remote_code_execution",
        "no_authentication_required",
        "internet_exposed_service",
    ],
    "actively_exploited": True,
    "remote_exploitable": True,
    "authentication_required": False,
    "patch_available": True,
    "fixed_version": "2.17.1",
    "confidence": 0.95,
    "cve_ids": ["CVE-2021-44228", "CVE-2021-45046"],
    "last_updated": "2024-06-01T12:00:00+00:00",
}

#: Response body for a product outside Attestd's coverage (supported=False).
UNSUPPORTED: dict[str, Any] = {"supported": False}

#: Monitored PyPI package. Supply chain clean (compromised=false).
LITELLM_SAFE: dict[str, Any] = {
    "product": "litellm",
    "version": "1.82.6",
    "supported": True,
    "risk_state": "none",
    "risk_factors": [],
    "actively_exploited": False,
    "remote_exploitable": False,
    "authentication_required": False,
    "patch_available": False,
    "fixed_version": None,
    "confidence": 0.9,
    "cve_ids": [],
    "last_updated": "2026-03-24T12:00:00+00:00",
    "supply_chain": {"compromised": False, "sources": []},
}

#: Monitored PyPI package. Compromised version flagged by multiple sources.
LITELLM_COMPROMISED: dict[str, Any] = {
    "product": "litellm",
    "version": "1.82.7",
    "supported": True,
    "risk_state": "none",
    "risk_factors": [],
    "actively_exploited": False,
    "remote_exploitable": False,
    "authentication_required": False,
    "patch_available": False,
    "fixed_version": None,
    "confidence": 1.0,
    "cve_ids": [],
    "last_updated": "2026-03-24T12:00:00+00:00",
    "supply_chain": {
        "compromised": True,
        "sources": ["osv", "registry"],
        "malware_type": "backdoor",
        "description": "TeamPCP supply chain attack",
        "advisory_url": "https://docs.litellm.ai/blog/security-update-march-2026",
        "compromised_at": "2026-03-24T10:39:00+00:00",
        "removed_at": "2026-03-24T16:00:00+00:00",
        "provenance": None,
    },
}


#: GET /v1/products response sample.
PRODUCTS_RESPONSE: dict[str, Any] = {
    "cve_products": [
        {"slug": "nginx", "display_name": "NGINX"},
        {"slug": "postgresql", "display_name": "PostgreSQL"},
    ],
    "supply_chain_packages": [
        {"package": "litellm", "ecosystem": "pypi", "display_name": None},
    ],
    "total": 3,
}

#: GET /v1/cve/CVE-2021-44228 response sample.
CVE_LOG4SHELL: dict[str, Any] = {
    "cve_id": "CVE-2021-44228",
    "description": "Apache Log4j2 JNDI injection allows remote code execution.",
    "cvss_score": 10.0,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "actively_exploited": True,
    "remote_exploitable": True,
    "authentication_required": False,
    "affected_products": ["log4j"],
    "epss_score": 0.97568,
    "epss_percentile": 0.99976,
    "source_published_at": "2021-12-10T00:00:00+00:00",
    "last_checked_at": "2026-07-08T04:00:00+00:00",
}

#: GET /v1/usage response sample.
USAGE_SOLO: dict[str, Any] = {
    "tier": "solo",
    "key_calls_this_month": 1200,
    "account_calls_this_month": 1200,
    "included_calls": 10000,
    "billing_period_start": "2026-07-01T00:00:00+00:00",
    "billing_period_end": "2026-08-01T00:00:00+00:00",
    "overage_calls": 0,
    "estimated_overage_usd": 0.0,
}

#: Empty SessionStats snapshot for assertions against a fresh client.
STATS_EMPTY: dict[str, int] = {
    "api_calls_made": 0,
    "cache_hits": 0,
    "batch_saves": 0,
    "calls_saved": 0,
}


# ---------------------------------------------------------------------------
# Transport implementations
# ---------------------------------------------------------------------------

class MockTransport(httpx.BaseTransport):
    """
    Synchronous transport that returns a single fixed response for every request.

    Use when all requests in a test should return the same response.

    Args:
        status_code: HTTP status code to return.
        body:        JSON body to return as a dict.
        headers:     Optional response headers (e.g. ``{"Retry-After": "60"}``).
    """

    def __init__(
        self,
        status_code: int,
        body: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> None:
        self._response = httpx.Response(
            status_code, json=body, headers=headers or {}
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return self._response


class MockAsyncTransport(httpx.AsyncBaseTransport):
    """
    Asynchronous transport that returns a single fixed response for every request.

    Args:
        status_code: HTTP status code to return.
        body:        JSON body to return as a dict.
        headers:     Optional response headers.
    """

    def __init__(
        self,
        status_code: int,
        body: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> None:
        self._response = httpx.Response(
            status_code, json=body, headers=headers or {}
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return self._response


class SequentialMockTransport(httpx.BaseTransport):
    """
    Synchronous transport that returns responses from a pre-defined sequence.

    Each entry in ``responses`` is consumed in order. Useful for testing retry
    logic where the first one or two requests fail before a success.

    Args:
        responses: List of ``(status_code, body)`` or
                   ``(status_code, body, headers)`` tuples.

    Raises:
        AssertionError: If more requests are made than entries in ``responses``.
    """

    def __init__(self, responses: list[tuple]) -> None:
        self._responses = list(responses)
        self._idx = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if self._idx >= len(self._responses):
            raise AssertionError(
                f"SequentialMockTransport exhausted after {len(self._responses)} "
                f"responses. Got an unexpected extra request to {request.url}"
            )
        entry = self._responses[self._idx]
        self._idx += 1
        status, body = entry[0], entry[1]
        headers = entry[2] if len(entry) > 2 else {}
        return httpx.Response(status, json=body, headers=headers)

    @property
    def call_count(self) -> int:
        """Number of requests handled so far."""
        return self._idx


class SequentialMockAsyncTransport(httpx.AsyncBaseTransport):
    """
    Asynchronous transport that returns responses from a pre-defined sequence.

    Drop-in async equivalent of :class:`SequentialMockTransport`.

    Args:
        responses: List of ``(status_code, body)`` or
                   ``(status_code, body, headers)`` tuples.
    """

    def __init__(self, responses: list[tuple]) -> None:
        self._responses = list(responses)
        self._idx = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self._idx >= len(self._responses):
            raise AssertionError(
                f"SequentialMockAsyncTransport exhausted after {len(self._responses)} responses"
            )
        entry = self._responses[self._idx]
        self._idx += 1
        status, body = entry[0], entry[1]
        headers = entry[2] if len(entry) > 2 else {}
        return httpx.Response(status, json=body, headers=headers)

    @property
    def call_count(self) -> int:
        """Number of requests handled so far."""
        return self._idx
