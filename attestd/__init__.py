"""
Attestd Python SDK.

Provides a sync and async client for the Attestd security risk API.
The API returns vulnerability risk assessments for open-source software
components, suitable for use in CI/CD pipelines, deployment gates, and
AI agent tool calls.

Quick start (sync)::

    import attestd

    with attestd.Client(api_key="atst_...") as client:
        result = client.check("nginx", "1.20.0")
        print(result.risk_state)         # "high"
        print(result.cve_ids)            # ["CVE-2021-23017", ...]
        print(result.actively_exploited) # False

Quick start (async)::

    import asyncio
    import attestd

    async def main():
        async with attestd.AsyncClient(api_key="atst_...") as client:
            result = await client.check("log4j", "2.14.1")
            if result.risk_state == "critical":
                raise RuntimeError(f"Critical vulnerability: {result.cve_ids}")

    asyncio.run(main())

Error handling::

    try:
        result = client.check("myproduct", "1.0.0")
    except attestd.AttestdUnsupportedProductError:
        pass  # outside coverage: make an explicit policy decision (block/warn/skip)
    except attestd.AttestdRateLimitError as e:
        time.sleep(e.retry_after or 60)
    except attestd.AttestdAuthError:
        raise  # key is invalid: surface to operator
    except attestd.AttestdError:
        pass  # transient API/network error

Full documentation: https://attestd.io/docs
"""

from attestd._version import __version__
from attestd.client import AsyncClient, Client
from attestd.errors import (
    AttestdAPIError,
    AttestdAuthError,
    AttestdError,
    AttestdRateLimitError,
    AttestdUnsupportedProductError,
)
from attestd.models import RiskFactor, RiskResult, RiskState, SupplyChainSignal

__all__ = [
    "__version__",
    # Clients
    "Client",
    "AsyncClient",
    # Models
    "RiskResult",
    "RiskState",
    "RiskFactor",
    "SupplyChainSignal",
    # Errors
    "AttestdError",
    "AttestdAuthError",
    "AttestdRateLimitError",
    "AttestdUnsupportedProductError",
    "AttestdAPIError",
]
