"""
Internal helpers shared by Client and AsyncClient.

Not part of the public API. May change without notice.
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx

from attestd._version import __version__
from attestd.errors import (
    AttestdAPIError,
    AttestdAuthError,
    AttestdRateLimitError,
    AttestdUnsupportedProductError,
)
from attestd.models import RiskResult, SupplyChainSignal

# HTTP status codes that indicate a transient server error worth retrying.
_RETRY_STATUS_CODES: frozenset[int] = frozenset({500, 502, 503, 504})

# Transport-level exceptions that indicate a transient connection issue.
_RETRYABLE_EXCEPTIONS = (
    httpx.ConnectError,
    httpx.TimeoutException,
    httpx.RemoteProtocolError,
)

DEFAULT_BASE_URL = "https://api.attestd.io"
CHECK_PATH = "/v1/check"
USER_AGENT = f"attestd-python/{__version__}"


def _parse_optional_iso(dt_raw: str | None) -> datetime | None:
    if not dt_raw:
        return None
    dt = datetime.fromisoformat(dt_raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def make_headers(api_key: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {api_key}",
        "User-Agent": USER_AGENT,
    }


def parse_check_response(
    response: httpx.Response,
    product: str,
    version: str,
) -> RiskResult:
    """
    Parse an httpx Response from /v1/check into a RiskResult.

    Raises the appropriate AttestdError subclass for non-200 responses.
    Raises AttestdUnsupportedProductError when supported=false in the body.
    """
    if response.status_code == 401:
        raise AttestdAuthError(
            "Invalid or missing API key. "
            "Obtain a key at https://api.attestd.io/portal/login."
        )

    if response.status_code == 429:
        retry_after: int | None = None
        raw = response.headers.get("Retry-After")
        if raw is not None:
            try:
                retry_after = int(raw)
            except ValueError:
                pass
        msg = (
            f"Rate limit exceeded. Retry after {retry_after} seconds."
            if retry_after is not None
            else "Rate limit exceeded."
        )
        raise AttestdRateLimitError(msg, retry_after=retry_after)

    if response.status_code >= 500:
        raise AttestdAPIError(
            f"Attestd API error (HTTP {response.status_code}). "
            "The service may be temporarily unavailable. Try again shortly.",
            status_code=response.status_code,
        )

    if response.status_code != 200:
        raise AttestdAPIError(
            f"Unexpected HTTP {response.status_code} from Attestd API.",
            status_code=response.status_code,
        )

    data = response.json()

    if not data.get("supported", True):
        # "Outside coverage" is not a safety clearance. See AttestdUnsupportedProductError.
        raise AttestdUnsupportedProductError(product, version)

    # last_updated arrives as an ISO 8601 string.
    # fromisoformat handles the "+00:00" suffix that FastAPI emits.
    last_updated_raw = data.get("last_updated")
    if last_updated_raw:
        last_updated = datetime.fromisoformat(last_updated_raw)
        if last_updated.tzinfo is None:
            last_updated = last_updated.replace(tzinfo=timezone.utc)
    else:
        last_updated = datetime.now(tz=timezone.utc)

    supply_chain: SupplyChainSignal | None = None
    raw_sc = data.get("supply_chain")
    if raw_sc is not None:
        supply_chain = SupplyChainSignal(
            compromised=raw_sc["compromised"],
            sources=tuple(raw_sc.get("sources") or []),
            malware_type=raw_sc.get("malware_type"),
            description=raw_sc.get("description"),
            advisory_url=raw_sc.get("advisory_url"),
            compromised_at=_parse_optional_iso(raw_sc.get("compromised_at")),
            removed_at=_parse_optional_iso(raw_sc.get("removed_at")),
        )

    return RiskResult(
        product=data["product"],
        version=data["version"],
        risk_state=data["risk_state"],
        risk_factors=data.get("risk_factors") or [],
        actively_exploited=data["actively_exploited"],
        remote_exploitable=data["remote_exploitable"],
        authentication_required=data["authentication_required"],
        patch_available=data["patch_available"],
        fixed_version=data.get("fixed_version"),
        confidence=float(data["confidence"]),
        cve_ids=data.get("cve_ids") or [],
        last_updated=last_updated,
        supply_chain=supply_chain,
    )
