"""
Attestd SDK exception hierarchy.

All exceptions inherit from AttestdError so callers can catch them with a
single broad handler when needed:

    try:
        result = client.check("nginx", "1.20.0")
    except attestd.AttestdUnsupportedProductError:
        ...  # outside coverage: make an explicit policy decision, see below
    except attestd.AttestdRateLimitError as e:
        time.sleep(e.retry_after or 60)
    except attestd.AttestdError:
        ...  # auth error, API error, etc.
"""

from __future__ import annotations


class AttestdError(Exception):
    """Base exception for all Attestd SDK errors."""


class AttestdAuthError(AttestdError):
    """
    Authentication failed. HTTP 401.

    The API key is missing, invalid, or has been revoked.
    Obtain a new key at https://api.attestd.io/portal/login.
    """


class AttestdRateLimitError(AttestdError):
    """
    Monthly call quota exceeded. HTTP 429.

    The SDK does not auto-retry on 429. The caller controls the backoff.
    Check retry_after for the number of seconds to wait, if provided by
    the server.

    Attributes:
        retry_after: Seconds until the quota resets, from the Retry-After
                     response header. May be None if the header was absent.
    """

    def __init__(self, message: str, retry_after: int | None = None) -> None:
        super().__init__(message)
        self.retry_after: int | None = retry_after


class AttestdUnsupportedProductError(AttestdError):
    """
    The requested product is outside Attestd's coverage.

    This means Attestd has no vulnerability data for this product. It does
    NOT mean the product is free of vulnerabilities. The absence of data is
    not a safety signal. Do not treat this exception as a security clearance.

    The correct response is an explicit policy decision by the caller:

      - Block: treat "outside coverage" the same as "unknown risk" and fail
        the check, requiring a human review before proceeding.
      - Allow with warning: proceed but surface the gap to an operator so
        coverage can be requested.
      - Skip: exempt the product from automated checks entirely and document
        the exemption.

    See https://attestd.io/docs/products for the supported product list.
    Each product page lists the exact slug, version format, and notable CVEs.

    Attributes:
        product: The product slug that was queried.
        version: The version string that was queried.
    """

    def __init__(self, product: str, version: str) -> None:
        super().__init__(
            f"Product '{product}' is outside Attestd's coverage. "
            "This does not mean the product is safe. Attestd has no data for it. "
            "See https://attestd.io/docs/products for the supported product list."
        )
        self.product: str = product
        self.version: str = version


class AttestdAPIError(AttestdError):
    """
    Unexpected error from the Attestd API.

    Raised for 5xx responses that persist after all retries, and for any
    other unexpected HTTP status code. Inspect status_code to distinguish
    server errors (5xx) from connection failures (status_code=0).

    Attributes:
        status_code: HTTP status code, or 0 for connection/transport errors.
    """

    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.status_code: int = status_code
