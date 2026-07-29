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

from attestd._cache import CachePolicy, ResultCache, SessionStats
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
from attestd.errors import AttestdAPIError, AttestdError, AttestdUnsupportedProductError
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
        api_key:       Your Attestd API key (starts with "atst_"). Falls back to
                       the ATTESTD_API_KEY environment variable when omitted.
        base_url:      API base URL. Defaults to https://api.attestd.io.
                       Override to point at a local instance during testing.
        timeout:       Per-request timeout in seconds. Default: 10.
        max_retries:   Maximum number of retries on transient errors. Default: 3.
                       Retry 0 means one attempt total with no retries.
        retry_delay:   Base delay in seconds for exponential backoff between
                       retries. Default: 1.0 (1s, 2s, 4s with max_retries=3).
        transport:     Custom httpx transport. Inject a mock for unit testing.
        cache_policy:  Client-side result cache policy. One of "development"
                       (24h), "runtime" (5min, default), "ci" (never expire),
                       or "none" (always hit the API).
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 10.0,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        transport: httpx.BaseTransport | None = None,
        cache_policy: CachePolicy = "runtime",
    ) -> None:
        resolved_key = _resolve_api_key(api_key)
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._cache = ResultCache(cache_policy)
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

        Results are cached according to ``cache_policy``. Repeated calls for
        the same product+version within the TTL return the cached result and
        do not count against your API quota.

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
        cached = self._cache.get(product, version)
        if cached is not None:
            return cached
        response = self._send_with_retry(product, version)
        result = parse_check_response(response, product, version)
        self._cache.put(product, version, result)
        self._cache.record_api_call()
        return result

    def batch_check(self, items: list[tuple[str, str]]) -> list[RiskResult | None]:
        """
        Check up to 100 product versions in one API call.

        Each tuple is (product, version). Results are returned in the same
        order as the input. None means the product is not in Attestd's
        coverage (supported=false). Each item counts as one API call against
        your quota.

        Cached entries are returned without an API round-trip. Only uncached
        items are sent to the batch endpoint.

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

        results: list[RiskResult | None] = [None] * len(items)
        miss_indices: list[int] = []
        miss_items: list[tuple[str, str]] = []

        for i, (product, version) in enumerate(items):
            cached = self._cache.get(product, version)
            if cached is not None:
                results[i] = cached
            else:
                miss_indices.append(i)
                miss_items.append((product, version))

        if not miss_items:
            return results

        body = {"items": [{"product": p, "version": v} for p, v in miss_items]}
        response = self._post_with_retry(body)
        fetched = parse_batch_check_response(response, miss_items)
        self._cache.record_api_call(len(miss_items))

        for idx, item, result in zip(miss_indices, miss_items, fetched):
            results[idx] = result
            if result is not None:
                self._cache.put(item[0], item[1], result)

        return results

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

    def invalidate_cache(self, product: str, version: str) -> None:
        """Drop a cached result so the next check() hits the API."""
        self._cache.invalidate(product, version)

    def stats(self) -> SessionStats:
        """Return session observability counters (api_calls_made, cache_hits, …)."""
        return self._cache.stats()

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

    Concurrent ``check()`` calls within ``batch_window_ms`` are coalesced into
    a single ``POST /v1/check/batch`` request, reducing quota usage for fan-out
    patterns.

    Args:
        api_key:          Your Attestd API key (starts with "atst_"). Falls back to
                          the ATTESTD_API_KEY environment variable when omitted.
        base_url:         API base URL. Defaults to https://api.attestd.io.
        timeout:          Per-request timeout in seconds. Default: 10.
        max_retries:      Maximum number of retries on transient errors. Default: 3.
        retry_delay:      Base delay in seconds for exponential backoff between
                          retries. Default: 1.0.
        transport:        Custom async httpx transport. Inject a mock for unit testing.
        cache_policy:     Client-side result cache policy. See Client.
        batch_window_ms:  Milliseconds to wait before flushing coalesced check()
                          calls. Default: 5. Set to 0 to disable coalescing.
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 10.0,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        transport: httpx.AsyncBaseTransport | None = None,
        cache_policy: CachePolicy = "runtime",
        batch_window_ms: int = 5,
    ) -> None:
        resolved_key = _resolve_api_key(api_key)
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._batch_window_ms = max(0, batch_window_ms)
        self._cache = ResultCache(cache_policy)
        self._http = httpx.AsyncClient(
            base_url=base_url,
            headers=make_headers(resolved_key),
            timeout=timeout,
            transport=transport,
        )
        self._pending: dict[tuple[str, str], list[asyncio.Future[RiskResult]]] = {}
        self._flush_task: asyncio.Task[None] | None = None
        self._pending_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def check(self, product: str, version: str) -> RiskResult:
        """
        Async version of Client.check(). See Client.check() for full docs.

        Concurrent calls within ``batch_window_ms`` are coalesced into one
        batch API request. Cached results bypass both the window and the API.

        Args:
            product: Product slug, e.g. "nginx", "log4j", "openssh".
            version: Version string, e.g. "1.20.0", "2.14.1", "9.2p1".

        Returns:
            RiskResult with the aggregated risk assessment.

        Raises:
            AttestdUnsupportedProductError, AttestdAuthError,
            AttestdRateLimitError, AttestdAPIError. See Client.check().
        """
        cached = self._cache.get(product, version)
        if cached is not None:
            return cached

        if self._batch_window_ms == 0:
            return await self._check_direct(product, version)

        loop = asyncio.get_running_loop()
        future: asyncio.Future[RiskResult] = loop.create_future()
        key = (product, version)

        async with self._pending_lock:
            waiters = self._pending.setdefault(key, [])
            waiters.append(future)
            if self._flush_task is None or self._flush_task.done():
                self._flush_task = asyncio.create_task(self._flush_batch())

        return await future

    async def batch_check(self, items: list[tuple[str, str]]) -> list[RiskResult | None]:
        """Async version of Client.batch_check(). See Client.batch_check() for full docs."""
        if not items:
            return []
        if len(items) > 100:
            raise AttestdError(
                f"batch_check accepts at most 100 items; got {len(items)}."
            )

        results: list[RiskResult | None] = [None] * len(items)
        miss_indices: list[int] = []
        miss_items: list[tuple[str, str]] = []

        for i, (product, version) in enumerate(items):
            cached = self._cache.get(product, version)
            if cached is not None:
                results[i] = cached
            else:
                miss_indices.append(i)
                miss_items.append((product, version))

        if not miss_items:
            return results

        body = {"items": [{"product": p, "version": v} for p, v in miss_items]}
        response = await self._post_with_retry(body)
        fetched = parse_batch_check_response(response, miss_items)
        self._cache.record_api_call(len(miss_items))

        for idx, item, result in zip(miss_indices, miss_items, fetched):
            results[idx] = result
            if result is not None:
                self._cache.put(item[0], item[1], result)

        return results

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

    def invalidate_cache(self, product: str, version: str) -> None:
        """Drop a cached result so the next check() hits the API."""
        self._cache.invalidate(product, version)

    def stats(self) -> SessionStats:
        """Return session observability counters (api_calls_made, cache_hits, …)."""
        return self._cache.stats()

    async def aclose(self) -> None:
        """Close the underlying async HTTP connection pool."""
        if self._flush_task is not None and not self._flush_task.done():
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
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

    async def _check_direct(self, product: str, version: str) -> RiskResult:
        response = await self._send_with_retry(product, version)
        result = parse_check_response(response, product, version)
        self._cache.put(product, version, result)
        self._cache.record_api_call()
        return result

    async def _flush_batch(self) -> None:
        await asyncio.sleep(self._batch_window_ms / 1000.0)

        async with self._pending_lock:
            pending = self._pending
            self._pending = {}
            self._flush_task = None

        if not pending:
            return

        items = list(pending.keys())
        all_results: dict[tuple[str, str], RiskResult | BaseException] = {}

        try:
            # Single unique key: use GET /v1/check (no batch savings).
            # Multiple keys: coalesce into POST /v1/check/batch.
            if len(items) == 1:
                key = items[0]
                try:
                    all_results[key] = await self._check_direct(key[0], key[1])
                except BaseException as exc:
                    all_results[key] = exc
            else:
                for offset in range(0, len(items), 100):
                    chunk = items[offset : offset + 100]
                    body = {
                        "items": [{"product": p, "version": v} for p, v in chunk]
                    }
                    response = await self._post_with_retry(body)
                    fetched = parse_batch_check_response(response, chunk)
                    self._cache.record_api_call(len(chunk))
                    if len(chunk) > 1:
                        self._cache.record_batch_save(len(chunk) - 1)
                    for key, result in zip(chunk, fetched):
                        if result is None:
                            all_results[key] = AttestdUnsupportedProductError(
                                key[0], key[1]
                            )
                        else:
                            self._cache.put(key[0], key[1], result)
                            all_results[key] = result
        except BaseException as exc:
            for waiters in pending.values():
                for fut in waiters:
                    if not fut.done():
                        fut.set_exception(exc)
            return

        for key, waiters in pending.items():
            outcome = all_results[key]
            for fut in waiters:
                if fut.done():
                    continue
                if isinstance(outcome, BaseException):
                    fut.set_exception(outcome)
                else:
                    fut.set_result(outcome)

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
