"""
Internal helpers shared by Client and AsyncClient.

Not part of the public API. May change without notice.
"""

from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import httpx

from attestd._version import __version__
from attestd.errors import (
    AttestdAPIError,
    AttestdAuthError,
    AttestdRateLimitError,
    AttestdUnsupportedProductError,
)
from attestd.models import (
    CveDetail,
    CveSummary,
    ProductEntry,
    ProductsResult,
    RiskResult,
    RiskState,
    SupplyChainEntry,
    SupplyChainSignal,
    TyposquatSignal,
    UsageResult,
)

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
BATCH_PATH = "/v1/check/batch"
PRODUCTS_PATH = "/v1/products"
CVE_PATH_PREFIX = "/v1/cve/"
USAGE_PATH = "/v1/usage"
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


def _parse_retry_after(raw: str) -> int | None:
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        dt = parsedate_to_datetime(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        seconds = int((dt - datetime.now(tz=timezone.utc)).total_seconds())
        return max(0, seconds)
    except (TypeError, ValueError, OverflowError):
        return None


def _parse_typosquat(raw: object | None) -> TyposquatSignal | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise AttestdAPIError(
            "Unexpected response shape: typosquat is not an object.",
            status_code=200,
        )
    detected = _require_field(raw, "detected", bool)
    confidence_raw = _require_field(raw, "confidence", (int, float))
    ecosystem = _require_field(raw, "ecosystem", str)
    resembles_raw = raw.get("resembles")
    if resembles_raw is not None and not isinstance(resembles_raw, str):
        raise AttestdAPIError(
            "Unexpected response shape: typosquat.resembles expected string.",
            status_code=200,
        )
    return TyposquatSignal(
        detected=detected,  # type: ignore[arg-type]
        resembles=resembles_raw,
        confidence=float(confidence_raw),
        ecosystem=ecosystem,  # type: ignore[arg-type]
    )


def _parse_last_updated(data: dict) -> datetime:
    last_updated_raw = data.get("last_updated")
    if last_updated_raw is None:
        raise AttestdAPIError(
            "Unexpected response shape: missing 'last_updated'.",
            status_code=200,
        )
    if not isinstance(last_updated_raw, str):
        raise AttestdAPIError(
            "Unexpected response shape: 'last_updated' expected string.",
            status_code=200,
        )
    try:
        last_updated = datetime.fromisoformat(last_updated_raw)
        if last_updated.tzinfo is None:
            last_updated = last_updated.replace(tzinfo=timezone.utc)
        return last_updated
    except ValueError as exc:
        raise AttestdAPIError(
            f"Unexpected response shape: invalid last_updated {last_updated_raw!r}.",
            status_code=200,
        ) from exc


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


def _parse_check_dict(data: dict, product: str, version: str) -> RiskResult:
    """Parse a supported /v1/check result dict into a RiskResult.

    Caller must ensure the dict represents a supported product (supported=True).
    """
    typosquat = _parse_typosquat(data.get("typosquat"))

    risk_state_raw = _require_field(data, "risk_state", str)
    if risk_state_raw not in _VALID_RISK_STATES:
        raise AttestdAPIError(
            f"Unexpected response shape: invalid risk_state {risk_state_raw!r}.",
            status_code=200,
        )
    risk_state: RiskState = risk_state_raw  # type: ignore[assignment]

    last_updated = _parse_last_updated(data)

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

    max_epss_raw = data.get("max_epss")
    max_epss = float(max_epss_raw) if isinstance(max_epss_raw, (int, float)) else None

    cves: list[CveSummary] = []
    cves_raw = data.get("cves")
    if isinstance(cves_raw, list):
        for item in cves_raw:
            if not isinstance(item, dict):
                continue
            cvss_raw = item.get("cvss_score")
            epss_raw = item.get("epss_score")
            epss_pct_raw = item.get("epss_percentile")
            cves.append(
                CveSummary(
                    cve_id=str(item.get("cve_id", "")),
                    cvss_score=float(cvss_raw) if isinstance(cvss_raw, (int, float)) else None,
                    actively_exploited=bool(item.get("actively_exploited", False)),
                    remote_exploitable=bool(item.get("remote_exploitable", False)),
                    epss_score=float(epss_raw) if isinstance(epss_raw, (int, float)) else None,
                    epss_percentile=(
                        float(epss_pct_raw) if isinstance(epss_pct_raw, (int, float)) else None
                    ),
                )
            )

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
        max_epss=max_epss,
        cves=cves,
        last_updated=last_updated,
        supply_chain=supply_chain,
        typosquat=typosquat,
    )


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
            retry_after = _parse_retry_after(raw)
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

    typosquat = _parse_typosquat(data.get("typosquat"))

    if "supported" not in data:
        raise AttestdAPIError(
            "Unexpected response shape: missing 'supported'.",
            status_code=200,
        )
    supported = _require_field(data, "supported", bool)
    if supported is False:
        raise AttestdUnsupportedProductError(product, version, typosquat=typosquat)

    return _parse_check_dict(data, product, version)


def parse_batch_check_response(
    response: httpx.Response,
    items: list[tuple[str, str]],
) -> list[RiskResult | None]:
    """
    Parse an httpx Response from POST /v1/check/batch.

    Returns one entry per input item, in the same order. None means the
    product is not in Attestd's coverage (supported=false). Auth and rate
    limit errors raise immediately — the whole batch is rejected.

    Raises:
        AttestdAuthError: HTTP 401.
        AttestdRateLimitError: HTTP 429. No items are billed when this fires.
        AttestdAPIError: Any other non-200 response or malformed body.
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
            retry_after = _parse_retry_after(raw)
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

    try:
        data = response.json()
    except ValueError as exc:
        raise AttestdAPIError(
            "Failed to parse Attestd batch API response as JSON.",
            status_code=200,
        ) from exc

    if not isinstance(data, dict):
        raise AttestdAPIError(
            "Unexpected batch response shape: expected JSON object.",
            status_code=200,
        )

    results_raw = data.get("results")
    if not isinstance(results_raw, list):
        raise AttestdAPIError(
            "Unexpected batch response shape: missing 'results' list.",
            status_code=200,
        )

    out: list[RiskResult | None] = []
    for i, entry in enumerate(results_raw):
        if not isinstance(entry, dict):
            raise AttestdAPIError(
                f"Unexpected batch response shape: entry {i} is not an object.",
                status_code=200,
            )
        result_raw = entry.get("result")
        if not isinstance(result_raw, dict):
            raise AttestdAPIError(
                f"Unexpected batch response shape: entry {i} result is not an object.",
                status_code=200,
            )
        if result_raw.get("supported") is False:
            out.append(None)
        else:
            product = str(entry.get("product") or (items[i][0] if i < len(items) else ""))
            version = str(entry.get("version") or (items[i][1] if i < len(items) else ""))
            out.append(_parse_check_dict(result_raw, product, version))

    return out


def _raise_auth_or_rate_limit(response: httpx.Response) -> None:
    if response.status_code == 401:
        raise AttestdAuthError(
            "Invalid or missing API key. "
            "Obtain a key at https://api.attestd.io/portal/login."
        )

    if response.status_code == 429:
        retry_after: int | None = None
        raw = response.headers.get("Retry-After")
        if raw is not None:
            retry_after = _parse_retry_after(raw)
        msg = (
            f"Rate limit exceeded. Retry after {retry_after} seconds."
            if retry_after is not None
            else "Rate limit exceeded."
        )
        raise AttestdRateLimitError(msg, retry_after=retry_after)


def _parse_json_object(response: httpx.Response, *, context: str) -> dict:
    _raise_auth_or_rate_limit(response)

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
            f"Failed to parse Attestd {context} response as JSON.",
            status_code=200,
        ) from exc

    if not isinstance(data, dict):
        raise AttestdAPIError(
            f"Unexpected {context} response shape: expected JSON object.",
            status_code=200,
        )
    return data


def parse_products_response(response: httpx.Response) -> ProductsResult:
    """Parse GET /v1/products into a ProductsResult."""
    data = _parse_json_object(response, context="products")

    cve_raw = data.get("cve_products")
    if not isinstance(cve_raw, list):
        raise AttestdAPIError(
            "Unexpected products response shape: missing 'cve_products' list.",
            status_code=200,
        )

    sc_raw = data.get("supply_chain_packages")
    if not isinstance(sc_raw, list):
        raise AttestdAPIError(
            "Unexpected products response shape: missing 'supply_chain_packages' list.",
            status_code=200,
        )

    total_raw = data.get("total")
    if not isinstance(total_raw, int):
        raise AttestdAPIError(
            "Unexpected products response shape: 'total' expected int.",
            status_code=200,
        )

    cve_products: list[ProductEntry] = []
    for i, item in enumerate(cve_raw):
        if not isinstance(item, dict):
            raise AttestdAPIError(
                f"Unexpected products response shape: cve_products[{i}] is not an object.",
                status_code=200,
            )
        cve_products.append(
            ProductEntry(
                slug=_require_field(item, "slug", str),  # type: ignore[arg-type]
                display_name=_require_field(item, "display_name", str),  # type: ignore[arg-type]
            )
        )

    supply_chain_packages: list[SupplyChainEntry] = []
    for i, item in enumerate(sc_raw):
        if not isinstance(item, dict):
            raise AttestdAPIError(
                f"Unexpected products response shape: supply_chain_packages[{i}] is not an object.",
                status_code=200,
            )
        display_raw = item.get("display_name")
        if display_raw is not None and not isinstance(display_raw, str):
            raise AttestdAPIError(
                f"Unexpected products response shape: supply_chain_packages[{i}].display_name expected string.",
                status_code=200,
            )
        supply_chain_packages.append(
            SupplyChainEntry(
                package=_require_field(item, "package", str),  # type: ignore[arg-type]
                ecosystem=_require_field(item, "ecosystem", str),  # type: ignore[arg-type]
                display_name=display_raw,
            )
        )

    return ProductsResult(
        cve_products=cve_products,
        supply_chain_packages=supply_chain_packages,
        total=total_raw,
    )


def parse_cve_response(response: httpx.Response, cve_id: str) -> CveDetail:
    """Parse GET /v1/cve/{cve_id} into a CveDetail."""
    _raise_auth_or_rate_limit(response)

    if response.status_code == 404:
        raise AttestdAPIError(
            f"CVE not found: {cve_id}",
            status_code=404,
        )

    if response.status_code == 400:
        raise AttestdAPIError(
            "Invalid CVE id format (expected CVE-YYYY-NNNN).",
            status_code=400,
        )

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
            "Failed to parse Attestd CVE response as JSON.",
            status_code=200,
        ) from exc

    if not isinstance(data, dict):
        raise AttestdAPIError(
            "Unexpected CVE response shape: expected JSON object.",
            status_code=200,
        )

    cvss_raw = data.get("cvss_score")
    epss_raw = data.get("epss_score")
    epss_pct_raw = data.get("epss_percentile")
    affected_raw = data.get("affected_products") or []
    if not isinstance(affected_raw, list):
        raise AttestdAPIError(
            "Unexpected CVE response shape: 'affected_products' expected list.",
            status_code=200,
        )

    return CveDetail(
        cve_id=_require_field(data, "cve_id", str),  # type: ignore[arg-type]
        description=data.get("description") if isinstance(data.get("description"), (str, type(None))) else None,
        cvss_score=float(cvss_raw) if isinstance(cvss_raw, (int, float)) else None,
        cvss_vector=data.get("cvss_vector") if isinstance(data.get("cvss_vector"), (str, type(None))) else None,
        actively_exploited=bool(data.get("actively_exploited", False)),
        remote_exploitable=bool(data.get("remote_exploitable", False)),
        authentication_required=bool(data.get("authentication_required", False)),
        affected_products=[p for p in affected_raw if isinstance(p, str)],
        epss_score=float(epss_raw) if isinstance(epss_raw, (int, float)) else None,
        epss_percentile=float(epss_pct_raw) if isinstance(epss_pct_raw, (int, float)) else None,
        source_published_at=_parse_optional_iso(
            data.get("source_published_at") if isinstance(data.get("source_published_at"), (str, type(None))) else None
        ),
        last_checked_at=_parse_optional_iso(
            data.get("last_checked_at") if isinstance(data.get("last_checked_at"), (str, type(None))) else None
        ),
    )


def parse_usage_response(response: httpx.Response) -> UsageResult:
    """Parse GET /v1/usage into a UsageResult."""
    data = _parse_json_object(response, context="usage")

    billing_start = _parse_optional_iso(
        data.get("billing_period_start") if isinstance(data.get("billing_period_start"), str) else None
    )
    billing_end = _parse_optional_iso(
        data.get("billing_period_end") if isinstance(data.get("billing_period_end"), str) else None
    )
    if billing_start is None or billing_end is None:
        raise AttestdAPIError(
            "Unexpected usage response shape: missing billing period timestamps.",
            status_code=200,
        )

    overage_raw = data.get("overage_calls", 0)
    overage_usd_raw = data.get("estimated_overage_usd", 0.0)

    return UsageResult(
        tier=_require_field(data, "tier", str),  # type: ignore[arg-type]
        key_calls_this_month=_require_field(data, "key_calls_this_month", int),  # type: ignore[arg-type]
        account_calls_this_month=_require_field(data, "account_calls_this_month", int),  # type: ignore[arg-type]
        included_calls=_require_field(data, "included_calls", int),  # type: ignore[arg-type]
        billing_period_start=billing_start,
        billing_period_end=billing_end,
        overage_calls=int(overage_raw) if isinstance(overage_raw, int) else 0,
        estimated_overage_usd=float(overage_usd_raw) if isinstance(overage_usd_raw, (int, float)) else 0.0,
    )
