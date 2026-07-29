"""
Client-side result cache and session observability.

Not part of the public API surface except for CachePolicy and SessionStats,
which are re-exported from attestd.__init__.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Literal

from attestd.models import RiskResult

CachePolicy = Literal["development", "runtime", "ci", "none"]

# Bump when the on-disk or in-memory entry shape changes.
CACHE_VERSION = 1

# TTL in seconds. None = never expire. 0 = always miss.
_POLICY_TTL: dict[CachePolicy, float | None] = {
    "development": 86_400.0,
    "runtime": 300.0,
    "ci": None,
    "none": 0.0,
}


@dataclass(slots=True)
class SessionStats:
    """Observability counters for one Client / AsyncClient lifetime."""

    api_calls_made: int = 0
    cache_hits: int = 0
    batch_saves: int = 0

    @property
    def calls_saved(self) -> int:
        """Total API calls avoided via cache hits and batch coalescing."""
        return self.cache_hits + self.batch_saves


class ResultCache:
    """
    Thread-safe in-memory cache keyed by (product, version).

    Policies:
        development — 24 h TTL (local loops)
        runtime     — 5 min TTL (default production)
        ci          — never expires (dedup within a CI run)
        none        — always miss (raw mode)
    """

    def __init__(self, policy: CachePolicy = "runtime") -> None:
        if policy not in _POLICY_TTL:
            raise ValueError(
                f"Unknown cache_policy {policy!r}. "
                f"Expected one of: {', '.join(sorted(_POLICY_TTL))}."
            )
        self._policy = policy
        self._ttl = _POLICY_TTL[policy]
        self._store: dict[tuple[str, str], tuple[RiskResult, float]] = {}
        self._lock = threading.Lock()
        self._api_calls_made = 0
        self._cache_hits = 0
        self._batch_saves = 0

    @property
    def policy(self) -> CachePolicy:
        return self._policy

    def get(self, product: str, version: str) -> RiskResult | None:
        """Return a cached result, or None on miss / expiry / none policy."""
        if self._ttl == 0.0:
            return None
        key = (product, version)
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            result, stored_at = entry
            if self._ttl is not None and (time.monotonic() - stored_at) >= self._ttl:
                del self._store[key]
                return None
            self._cache_hits += 1
            return result

    def put(self, product: str, version: str, result: RiskResult) -> None:
        """Store a result. No-op under the none policy."""
        if self._ttl == 0.0:
            return
        with self._lock:
            self._store[(product, version)] = (result, time.monotonic())

    def invalidate(self, product: str, version: str) -> None:
        """Drop one cache entry so the next check() hits the API."""
        with self._lock:
            self._store.pop((product, version), None)

    def record_api_call(self, n: int = 1) -> None:
        with self._lock:
            self._api_calls_made += n

    def record_batch_save(self, n: int) -> None:
        """Record how many check() calls were coalesced away by batching."""
        if n <= 0:
            return
        with self._lock:
            self._batch_saves += n

    def stats(self) -> SessionStats:
        with self._lock:
            return SessionStats(
                api_calls_made=self._api_calls_made,
                cache_hits=self._cache_hits,
                batch_saves=self._batch_saves,
            )
