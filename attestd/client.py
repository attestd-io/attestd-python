"""
Attestd sync and async API clients.

Both clients share the same retry strategy: up to max_retries additional
attempts on transient 5xx responses or connection failures, with exponential
backoff (1s, 2s, 4s between attempts). 401 and 429 are surfaced immediately
without retry. These require deliberate action from the caller.

Usage (sync)::

    import attestd

    with attestd.Client(api_key="atst_...") as client:
        result = client.check("nginx", "1.20.0")
        if result.risk_state in ("critical", "high"):
            block_deployment(reason=result.risk_factors)

Usage (async)::

    import attestd

    async with attestd.AsyncClient(api_key="atst_...") as client:
        result = await client.check("nginx", "1.20.0")
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any

import httpx

from attestd._internal import (
    BATCH_PATH,
    CHECK_PATH,
    CVE_PATH_PREFIX,
    DEFAULT_BASE_URL,
    PRODUCTS_PATH,
    USAGE_PATH,
    _RETRYABLE_EXCEPTIONS,
    _RETRY_STATUS_CODES,
    make_headers,
    parse_batch_check_response,
    parse_check_response,
    parse_cve_response,
    parse_products_response,
    parse_usage_response,
)
from attestd.errors import AttestdAPIError, AttestdError
from attestd.models import CveDetail, ProductsResult, RiskResult, UsageResult


def _resolve_api_key(api_key: str | None) -> str:
    key = (api_key or os.environ.get("ATTESTD_API_KEY") or "").strip()
    if not key:
        raise AttestdError(
            "api_key is required. Pass it to Client() or set the ATTESTD_API_KEY "
            "environment variable. Obtain a key at https://api.attestd.io/portal/login."
        )
    return key


class Client:
    """
    Synchronous Attestd API client.

    Thread-safe: the underlying httpx.Client connection pool is shared
    across calls. Create one Client per application and reuse it.

    Args:
        api_key:     Your Attestd API key (starts with "atst_"). Falls back to
                     the ATTESTD_API_KEY environment variable when omitted.
        base_url:    API base URL. Defaults to https://api.attestd.io.
                     Override to point at a local instance during testing.
        timeout:     Per-request timeout in seconds. Default: 10.
        max_retries: Maximum number of retries on transient errors. Default: 3.
                     Retry 0 means one attempt total with no retries.
        retry_delay: Base delay in seconds for exponential backoff between
                     retries. Default: 1.0 (1s, 2s, 4s with max_retries=3).
        transport:   Custom httpx transport. Inject a mock for unit testing.
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 10.0,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        resolved_key = _resolve_api_key(api_key)
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._http = httpx.Client(
            base_url=base_url,
            headers=make_headers(resolved_key),
            timeout=timeout,
            transport=transport,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, product: str, version: str) -> RiskResult:
        """
        Query Attestd for the risk state of a product version.

        Args:
            product: Product slug, e.g. "nginx", "log4j", "openssh".
                     See https://attestd.io/docs/products for the full list.
            version: Version string, e.g. "1.20.0", "2.14.1", "9.2p1".

        Returns:
            RiskResult with the aggregated risk assessment.

        Raises:
            AttestdUnsupportedProductError: Product not in the supported list.
            AttestdAuthError:               API key is invalid or revoked.
            AttestdRateLimitError:          Monthly call quota exceeded.
                Check e.retry_after for seconds to wait before retrying.
            AttestdAPIError:                Server error after all retries.
        """
        response = self._send_with_retry(product, version)
        return parse_check_response(response, product, version)

    def batch_check(self, items: list[tuple[str, str]]) -> list[RiskResult | None]:
        """
        Check up to 100 product versions in one API call.

        Each tuple is (product, version). Results are returned in the same
        order as the input. None means the product is not in Attestd's
        coverage (supported=false). Each item counts as one API call against
        your quota.

        If the batch would exceed your quota, AttestdRateLimitError is raised
        before any results are delivered and no items are billed.

        Raises:
            AttestdError:          items exceeds 100.
            AttestdAuthError:      API key is invalid or revoked.
            AttestdRateLimitError: Quota exceeded (no items are billed).
            AttestdAPIError:       Server error after all retries.
        """
        if not items:
            return []
        if len(items) > 100:
            raise AttestdError(
                f"batch_check accepts at most 100 items; got {len(items)}."
            )
        body = {"items": [{"product": p, "version": v} for p, v in items]}
        response = self._post_with_retry(body)
        return parse_batch_check_response(response, items)

    def products(self) -> ProductsResult:
        """Return the full Attestd product catalog (CVE + supply chain)."""
        response = self._get_with_retry(PRODUCTS_PATH)
        return parse_products_response(response)

    def cve(self, cve_id: str) -> CveDetail:
        """Return details for a single CVE id. Raises AttestdAPIError on 404."""
        path = f"{CVE_PATH_PREFIX}{cve_id.strip()}"
        response = self._get_with_retry(path)
        return parse_cve_response(response, cve_id.strip())

    def usage(self) -> UsageResult:
        """Return API key quota usage for the current billing period."""
        response = self._get_with_retry(USAGE_PATH)
        return parse_usage_response(response)

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._http.close()

    # ------------------------------------------------------------------
    # Context manager support
    # ------------------------------------------------------------------

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _send_with_retry(self, product: str, version: str) -> httpx.Response:
        params = {"product": product, "version": version}
        last_exc: Exception | None = None

        for attempt in range(self._max_retries + 1):
            if attempt > 0:
                time.sleep(self._retry_delay * (2 ** (attempt - 1)))
            try:
                response = self._http.get(CHECK_PATH, params=params)
                if response.status_code not in _RETRY_STATUS_CODES:
                    return response
                response.read()
                last_exc = AttestdAPIError(
                    f"Attestd API error (HTTP {response.status_code}).",
                    status_code=response.status_code,
                )
            except httpx.TimeoutException as exc:
                raise AttestdAPIError(
                    f"Request timed out after {self._http.timeout} seconds.",
                    status_code=0,
                ) from exc
            except _RETRYABLE_EXCEPTIONS as exc:
                last_exc = AttestdAPIError(
                    f"Connection to Attestd API failed: {exc}",
                    status_code=0,
                )

        raise last_exc  # type: ignore[misc]

    def _post_with_retry(self, body: dict) -> httpx.Response:
        last_exc: Exception | None = None

        for attempt in range(self._max_retries + 1):
            if attempt > 0:
                time.sleep(self._retry_delay * (2 ** (attempt - 1)))
            try:
                response = self._http.post(BATCH_PATH, json=body)
                if response.status_code not in _RETRY_STATUS_CODES:
                    return response
                response.read()
                last_exc = AttestdAPIError(
                    f"Attestd API error (HTTP {response.status_code}).",
                    status_code=response.status_code,
                )
            except httpx.TimeoutException as exc:
                raise AttestdAPIError(
                    f"Request timed out after {self._http.timeout} seconds.",
                    status_code=0,
                ) from exc
            except _RETRYABLE_EXCEPTIONS as exc:
                last_exc = AttestdAPIError(
                    f"Connection to Attestd API failed: {exc}",
                    status_code=0,
                )

        raise last_exc  # type: ignore[misc]

    def _get_with_retry(self, path: str) -> httpx.Response:
        last_exc: Exception | None = None

        for attempt in range(self._max_retries + 1):
            if attempt > 0:
                time.sleep(self._retry_delay * (2 ** (attempt - 1)))
            try:
                response = self._http.get(path)
                if response.status_code not in _RETRY_STATUS_CODES:
                    return response
                response.read()
                last_exc = AttestdAPIError(
                    f"Attestd API error (HTTP {response.status_code}).",
                    status_code=response.status_code,
                )
            except httpx.TimeoutException as exc:
                raise AttestdAPIError(
                    f"Request timed out after {self._http.timeout} seconds.",
                    status_code=0,
                ) from exc
            except _RETRYABLE_EXCEPTIONS as exc:
                last_exc = AttestdAPIError(
                    f"Connection to Attestd API failed: {exc}",
                    status_code=0,
                )

        raise last_exc  # type: ignore[misc]


class AsyncClient:
    """
    Asynchronous Attestd API client for use in async/await code.

    Args:
        api_key:     Your Attestd API key (starts with "atst_"). Falls back to
                     the ATTESTD_API_KEY environment variable when omitted.
        base_url:    API base URL. Defaults to https://api.attestd.io.
        timeout:     Per-request timeout in seconds. Default: 10.
        max_retries: Maximum number of retries on transient errors. Default: 3.
        retry_delay: Base delay in seconds for exponential backoff between
                     retries. Default: 1.0.
        transport:   Custom async httpx transport. Inject a mock for unit testing.
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 10.0,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        resolved_key = _resolve_api_key(api_key)
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._http = httpx.AsyncClient(
            base_url=base_url,
            headers=make_headers(resolved_key),
            timeout=timeout,
            transport=transport,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def check(self, product: str, version: str) -> RiskResult:
        """
        Async version of Client.check(). See Client.check() for full docs.

        Args:
            product: Product slug, e.g. "nginx", "log4j", "openssh".
            version: Version string, e.g. "1.20.0", "2.14.1", "9.2p1".

        Returns:
            RiskResult with the aggregated risk assessment.

        Raises:
            AttestdUnsupportedProductError, AttestdAuthError,
            AttestdRateLimitError, AttestdAPIError. See Client.check().
        """
        response = await self._send_with_retry(product, version)
        return parse_check_response(response, product, version)

    async def batch_check(self, items: list[tuple[str, str]]) -> list[RiskResult | None]:
        """Async version of Client.batch_check(). See Client.batch_check() for full docs."""
        if not items:
            return []
        if len(items) > 100:
            raise AttestdError(
                f"batch_check accepts at most 100 items; got {len(items)}."
            )
        body = {"items": [{"product": p, "version": v} for p, v in items]}
        response = await self._post_with_retry(body)
        return parse_batch_check_response(response, items)

    async def products(self) -> ProductsResult:
        """Async version of Client.products()."""
        response = await self._get_with_retry(PRODUCTS_PATH)
        return parse_products_response(response)

    async def cve(self, cve_id: str) -> CveDetail:
        """Async version of Client.cve()."""
        path = f"{CVE_PATH_PREFIX}{cve_id.strip()}"
        response = await self._get_with_retry(path)
        return parse_cve_response(response, cve_id.strip())

    async def usage(self) -> UsageResult:
        """Async version of Client.usage()."""
        response = await self._get_with_retry(USAGE_PATH)
        return parse_usage_response(response)

    async def aclose(self) -> None:
        """Close the underlying async HTTP connection pool."""
        await self._http.aclose()

    # ------------------------------------------------------------------
    # Async context manager support
    # ------------------------------------------------------------------

    async def __aenter__(self) -> AsyncClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _send_with_retry(self, product: str, version: str) -> httpx.Response:
        params = {"product": product, "version": version}
        last_exc: Exception | None = None

        for attempt in range(self._max_retries + 1):
            if attempt > 0:
                await asyncio.sleep(self._retry_delay * (2 ** (attempt - 1)))
            try:
                response = await self._http.get(CHECK_PATH, params=params)
                if response.status_code not in _RETRY_STATUS_CODES:
                    return response
                await response.aread()
                last_exc = AttestdAPIError(
                    f"Attestd API error (HTTP {response.status_code}).",
                    status_code=response.status_code,
                )
            except httpx.TimeoutException as exc:
                raise AttestdAPIError(
                    f"Request timed out after {self._http.timeout} seconds.",
                    status_code=0,
                ) from exc
            except _RETRYABLE_EXCEPTIONS as exc:
                last_exc = AttestdAPIError(
                    f"Connection to Attestd API failed: {exc}",
                    status_code=0,
                )

        raise last_exc  # type: ignore[misc]

    async def _post_with_retry(self, body: dict) -> httpx.Response:
        last_exc: Exception | None = None

        for attempt in range(self._max_retries + 1):
            if attempt > 0:
                await asyncio.sleep(self._retry_delay * (2 ** (attempt - 1)))
            try:
                response = await self._http.post(BATCH_PATH, json=body)
                if response.status_code not in _RETRY_STATUS_CODES:
                    return response
                await response.aread()
                last_exc = AttestdAPIError(
                    f"Attestd API error (HTTP {response.status_code}).",
                    status_code=response.status_code,
                )
            except httpx.TimeoutException as exc:
                raise AttestdAPIError(
                    f"Request timed out after {self._http.timeout} seconds.",
                    status_code=0,
                ) from exc
            except _RETRYABLE_EXCEPTIONS as exc:
                last_exc = AttestdAPIError(
                    f"Connection to Attestd API failed: {exc}",
                    status_code=0,
                )

        raise last_exc  # type: ignore[misc]

    async def _get_with_retry(self, path: str) -> httpx.Response:
        last_exc: Exception | None = None

        for attempt in range(self._max_retries + 1):
            if attempt > 0:
                await asyncio.sleep(self._retry_delay * (2 ** (attempt - 1)))
            try:
                response = await self._http.get(path)
                if response.status_code not in _RETRY_STATUS_CODES:
                    return response
                await response.aread()
                last_exc = AttestdAPIError(
                    f"Attestd API error (HTTP {response.status_code}).",
                    status_code=response.status_code,
                )
            except httpx.TimeoutException as exc:
                raise AttestdAPIError(
                    f"Request timed out after {self._http.timeout} seconds.",
                    status_code=0,
                ) from exc
            except _RETRYABLE_EXCEPTIONS as exc:
                last_exc = AttestdAPIError(
                    f"Connection to Attestd API failed: {exc}",
                    status_code=0,
                )

        raise last_exc  # type: ignore[misc]
