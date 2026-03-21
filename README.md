# attestd-python

Python SDK for the [Attestd](https://attestd.io) security risk API.

Attestd returns vulnerability risk assessments for open-source software components. Use it in CI/CD deployment gates, autonomous agent tool calls, and security dashboards.

## Installation

```bash
pip install attestd
```

Requires Python 3.10+.

## Quick start

### Sync

```python
import attestd

with attestd.Client(api_key="atst_...") as client:
    result = client.check("nginx", "1.20.0")

print(result.risk_state)          # "high"
print(result.actively_exploited)  # False
print(result.cve_ids)             # ["CVE-2021-23017", ...]
print(result.fixed_version)       # "1.27.4"
```

### Async

```python
import asyncio
import attestd

async def main():
    async with attestd.AsyncClient(api_key="atst_...") as client:
        result = await client.check("log4j", "2.14.1")
        if result.risk_state in ("critical", "high"):
            raise RuntimeError(f"Vulnerable dependency: {result.cve_ids}")

asyncio.run(main())
```

### CI/CD deployment gate

```python
import attestd

DEPENDENCIES = [
    ("nginx",  "1.20.0"),
    ("log4j",  "2.17.1"),
    ("openssh", "9.2p1"),
]

with attestd.Client(api_key="atst_...") as client:
    for product, version in DEPENDENCIES:
        try:
            result = client.check(product, version)
        except attestd.AttestdUnsupportedProductError:
            continue  # not in supported list, skip

        if result.risk_state in ("critical", "high"):
            print(f"BLOCK: {product} {version} ({result.risk_state})")
            print(f"  CVEs: {', '.join(result.cve_ids)}")
            print(f"  Fix:  upgrade to {result.fixed_version}")
            exit(1)
```

### AI agent tool

```python
import attestd

client = attestd.Client(api_key="atst_...")

def check_dependency_risk(product: str, version: str) -> dict:
    """
    Check if a software dependency has known security vulnerabilities.

    Returns a risk assessment including risk_state (critical/high/elevated/low/none),
    whether it is actively exploited, and the fixed version if one exists.
    """
    try:
        result = client.check(product, version)
        return {
            "supported": True,
            "risk_state": result.risk_state,
            "actively_exploited": result.actively_exploited,
            "fixed_version": result.fixed_version,
            "cve_ids": result.cve_ids,
        }
    except attestd.AttestdUnsupportedProductError:
        return {"supported": False}
```

## Error handling

```python
import time
import attestd

with attestd.Client(api_key="atst_...") as client:
    try:
        result = client.check("nginx", "1.20.0")
    except attestd.AttestdUnsupportedProductError:
        # Product is outside Attestd's coverage.
        # This does NOT mean the product is safe. It means Attestd has no data.
        # Make an explicit policy decision: block, warn an operator, or skip.
        # Do not silently allow — see "Outside coverage" below.
        pass
    except attestd.AttestdRateLimitError as e:
        # Monthly quota exceeded
        time.sleep(e.retry_after or 60)
    except attestd.AttestdAuthError:
        # API key is invalid or revoked
        raise
    except attestd.AttestdAPIError as e:
        # Unexpected server error; e.status_code is 0 for connection failures
        print(f"API error: {e.status_code}")
    except attestd.AttestdError:
        # Catch-all for any Attestd SDK exception
        pass
```

### Outside coverage — not a safety signal

`AttestdUnsupportedProductError` means **Attestd has no vulnerability data for
this product**, not that the product is free of vulnerabilities. This distinction
matters most in AI agent integrations, where an agent that catches the exception
and infers "safe to proceed" is making a dangerous inference.

Recommended handling:

```python
try:
    result = client.check(product, version)
except attestd.AttestdUnsupportedProductError as e:
    # Option 1: block - treat "outside coverage" as unknown risk
    raise RuntimeError(
        f"{e.product} is outside Attestd's coverage. "
        "Manual security review required before deploying."
    )

    # Option 2: warn - proceed but surface the gap
    logger.warning("Attestd has no coverage for %s, proceeding without check", e.product)

    # Option 3: skip - exempted product, documented
    if e.product in EXEMPTED_PRODUCTS:
        return  # explicitly opted out of coverage check for this product
```

## RiskResult fields

| Field | Type | Description |
|---|---|---|
| `product` | `str` | Product name |
| `version` | `str` | Version queried |
| `risk_state` | `str` | One of `critical`, `high`, `elevated`, `low`, `none` |
| `risk_factors` | `list[str]` | Machine-readable factors (see below) |
| `actively_exploited` | `bool` | On the CISA KEV list |
| `remote_exploitable` | `bool` | Remotely exploitable |
| `authentication_required` | `bool` | True only if ALL CVEs require auth |
| `patch_available` | `bool` | A fixed version is known |
| `fixed_version` | `str \| None` | Earliest version that resolves all CVEs |
| `confidence` | `float` | Synthesis confidence (0.0–1.0) |
| `cve_ids` | `list[str]` | CVE IDs in this assessment |
| `last_updated` | `datetime` | UTC timestamp of last synthesis run |

### Risk states

| State | Meaning |
|---|---|
| `critical` | Actively exploited in the wild (CISA KEV) |
| `high` | Remote unauthenticated exploitation possible |
| `elevated` | Remote exploitation requires authentication |
| `low` | Local-only or low-impact vulnerability |
| `none` | No known vulnerabilities affecting this version |

### Risk factors

| Factor | Meaning |
|---|---|
| `active_exploitation` | CVE on CISA KEV list |
| `remote_code_execution` | Remote exploitation possible |
| `no_authentication_required` | Remote + no auth required |
| `internet_exposed_service` | Remote + no auth (surface area flag) |
| `patch_available` | A fix is available |

## Configuration

```python
client = attestd.Client(
    api_key="atst_...",
    base_url="https://api.attestd.io",  # override for testing
    timeout=10.0,                        # per-request timeout in seconds
    max_retries=3,                       # retries on 5xx / connection errors
)
```

The SDK retries on transient 5xx responses and connection failures with
exponential backoff (1s, 2s, 4s between attempts). `401` and `429` are
surfaced immediately without retry.

## Supported products

See [attestd.io/docs/products](https://attestd.io/docs/products) for the
full list of supported products. Each product page documents the exact API
slug, version format, and notable CVEs. Querying an unsupported product
raises `AttestdUnsupportedProductError`. This is not an error in your code.

## Testing your integration

The SDK ships a `attestd.testing` module with httpx transports for injecting
controlled API responses into your tests. No local Attestd instance required.

```python
import attestd
from attestd.testing import (
    MockTransport,
    MockAsyncTransport,
    SequentialMockTransport,
    SequentialMockAsyncTransport,
    # Ready-made response bodies
    NGINX_SAFE,
    NGINX_VULNERABLE,
    LOG4J_CRITICAL,
    UNSUPPORTED,
)
```

### Test a deployment gate

```python
from attestd.testing import MockTransport, LOG4J_CRITICAL

def test_deployment_blocked_on_critical():
    client = attestd.Client(
        api_key="test",
        transport=MockTransport(200, LOG4J_CRITICAL),
    )
    with pytest.raises(DeploymentBlockedError):
        run_deployment_gate(client, "log4j", "2.14.1")
```

### Test retry behaviour

```python
from attestd.testing import SequentialMockTransport, NGINX_SAFE

def test_retry_succeeds_on_second_attempt():
    transport = SequentialMockTransport([
        (503, {}),         # first attempt, server error
        (200, NGINX_SAFE), # second attempt, success
    ])
    client = attestd.Client(api_key="test", transport=transport, max_retries=1)
    result = client.check("nginx", "1.27.4")
    assert result.risk_state == "none"
    assert transport.call_count == 2
```

### Test the "outside coverage" policy branch

```python
from attestd.testing import MockTransport, UNSUPPORTED

def test_outside_coverage_is_blocked_not_allowed():
    """Verify your code treats missing coverage as unknown risk, not as safe."""
    client = attestd.Client(api_key="test", transport=MockTransport(200, UNSUPPORTED))
    with pytest.raises(attestd.AttestdUnsupportedProductError):
        run_check(client, "unknownproduct", "1.0.0")
    # If run_check silently passes here, your coverage gap handling is broken.
```

### Custom response bodies

All ready-made bodies (`NGINX_SAFE`, etc.) are plain dicts — merge in overrides:

```python
from attestd.testing import MockTransport, NGINX_VULNERABLE

# Same as NGINX_VULNERABLE but with actively_exploited=True
body = {**NGINX_VULNERABLE, "actively_exploited": True, "risk_state": "critical"}
client = attestd.Client(api_key="test", transport=MockTransport(200, body))
```

## License

MIT
