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
from attestd.models import RiskResult, RiskState, SupplyChainSignal

# HTTP status codes that indicate a transient server error worth retrying.
_RETRY_STATUS_CODES: frozenset[int] = frozenset({500, 502, 503, 504})

# Transport-level exceptions that indicate a transient connection issue.
_RETRYABLE_EXCEPTIONS = (
    httpx.ConnectError,
    httpx.RemoteProtocolError,
)

_VALID_RISK_STATES: frozenset[str] = frozenset(
    {"critical", "high", "elevated", "low", "none"}
)

DEFAULT_BASE_URL = "https://api.attestd.io"
CHECK_PATH = "/v1/check"
USER_AGENT = f"attestd-python/{__version__}"


def _parse_optional_iso(dt_raw: str | None) -> datetime | None:
    if not dt_raw:
        return None
    try:
        dt = datetime.fromisoformat(dt_raw)
    except ValueError as exc:
        raise AttestdAPIError(
            f"Unexpected response shape: invalid ISO datetime: {dt_raw!r}",
            status_code=200,
        ) from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _require_field(data: dict, field: str, expected_type: type) -> object:
    if field not in data:
        raise AttestdAPIError(
            f"Unexpected response shape: missing '{field}'.",
            status_code=200,
        )
    value = data[field]
    if not isinstance(value, expected_type):
        raise AttestdAPIError(
            f"Unexpected response shape: '{field}' expected {expected_type.__name__}, "
            f"got {type(value).__name__}.",
            status_code=200,
        )
    return value


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

    if response.status_code == 404:
        raise AttestdUnsupportedProductError(product, version)

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

    try:
        data = response.json()
    except ValueError as exc:
        raise AttestdAPIError(
            "Failed to parse Attestd API response as JSON.",
            status_code=200,
        ) from exc

    if not isinstance(data, dict):
        raise AttestdAPIError(
            "Unexpected response shape: expected JSON object.",
            status_code=200,
        )

    if not data.get("supported", True):
        raise AttestdUnsupportedProductError(product, version)

    risk_state_raw = _require_field(data, "risk_state", str)
    if risk_state_raw not in _VALID_RISK_STATES:
        raise AttestdAPIError(
            f"Unexpected response shape: invalid risk_state {risk_state_raw!r}.",
            status_code=200,
        )
    risk_state: RiskState = risk_state_raw  # type: ignore[assignment]

    last_updated_raw = data.get("last_updated")
    if last_updated_raw is not None:
        if not isinstance(last_updated_raw, str):
            raise AttestdAPIError(
                "Unexpected response shape: 'last_updated' expected string.",
                status_code=200,
            )
        try:
            last_updated = datetime.fromisoformat(last_updated_raw)
            if last_updated.tzinfo is None:
                last_updated = last_updated.replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise AttestdAPIError(
                f"Unexpected response shape: invalid last_updated {last_updated_raw!r}.",
                status_code=200,
            ) from exc
    else:
        last_updated = datetime.now(tz=timezone.utc)

    supply_chain: SupplyChainSignal | None = None
    raw_sc = data.get("supply_chain")
    if raw_sc is not None:
        if not isinstance(raw_sc, dict):
            raise AttestdAPIError(
                "Unexpected response shape: supply_chain is not an object.",
                status_code=200,
            )
        if "compromised" not in raw_sc:
            raise AttestdAPIError(
                "Unexpected response shape: supply_chain.compromised is missing.",
                status_code=200,
            )
        if not isinstance(raw_sc["compromised"], bool):
            raise AttestdAPIError(
                "Unexpected response shape: supply_chain.compromised expected bool.",
                status_code=200,
            )
        sources_raw = raw_sc.get("sources") or []
        if not isinstance(sources_raw, list):
            raise AttestdAPIError(
                "Unexpected response shape: supply_chain.sources expected list.",
                status_code=200,
            )
        supply_chain = SupplyChainSignal(
            compromised=raw_sc["compromised"],
            sources=tuple(s for s in sources_raw if isinstance(s, str)),
            malware_type=raw_sc.get("malware_type"),
            description=raw_sc.get("description"),
            advisory_url=raw_sc.get("advisory_url"),
            compromised_at=_parse_optional_iso(raw_sc.get("compromised_at")),
            removed_at=_parse_optional_iso(raw_sc.get("removed_at")),
        )

    risk_factors_raw = data.get("risk_factors") or []
    if not isinstance(risk_factors_raw, list):
        raise AttestdAPIError(
            "Unexpected response shape: 'risk_factors' expected list.",
            status_code=200,
        )

    cve_ids_raw = data.get("cve_ids") or []
    if not isinstance(cve_ids_raw, list):
        raise AttestdAPIError(
            "Unexpected response shape: 'cve_ids' expected list.",
            status_code=200,
        )

    confidence_raw = _require_field(data, "confidence", (int, float))

    return RiskResult(
        product=_require_field(data, "product", str),  # type: ignore[arg-type]
        version=_require_field(data, "version", str),  # type: ignore[arg-type]
        risk_state=risk_state,
        risk_factors=[f for f in risk_factors_raw if isinstance(f, str)],
        actively_exploited=_require_field(data, "actively_exploited", bool),  # type: ignore[arg-type]
        remote_exploitable=_require_field(data, "remote_exploitable", bool),  # type: ignore[arg-type]
        authentication_required=_require_field(data, "authentication_required", bool),  # type: ignore[arg-type]
        patch_available=_require_field(data, "patch_available", bool),  # type: ignore[arg-type]
        fixed_version=data.get("fixed_version"),
        confidence=float(confidence_raw),
        cve_ids=[c for c in cve_ids_raw if isinstance(c, str)],
        last_updated=last_updated,
        supply_chain=supply_chain,
    )
