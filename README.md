# attestd

[![PyPI version](https://img.shields.io/pypi/v/attestd)](https://pypi.org/project/attestd/)

> Attestd checks whether a dependency version has exploitable CVEs or a confirmed supply-chain compromise. One API call returns a structured risk response.

[Get a free API key](https://api.attestd.io/portal/login) · [Full docs](https://attestd.io/docs)

Requires Python 3.10+.

## Install

```bash
pip install attestd
```

## Quick start

```python
import os
import attestd

client = attestd.Client(api_key=os.environ["ATTESTD_API_KEY"])
result = client.check("nginx", "1.20.0")
print(result.risk_state)  # "high"
print(result.cve_ids)     # ["CVE-2021-23017", ...]
```

## Supply chain check

Attestd monitors select PyPI and npm packages for known malicious publishes.

```python
result = client.check("litellm", "1.82.7")
print(result.supply_chain.compromised)  # True
```

## Error handling

`AttestdUnsupportedProductError` means the product is outside Attestd coverage. That is unknown risk, not a safety signal.

```python
try:
    result = client.check(product, version)
except attestd.AttestdUnsupportedProductError:
    raise RuntimeError(f"{product} is outside Attestd coverage")
```

See [Outside coverage](#outside-coverage-not-a-safety-signal) below for policy options.

---

## Async

```python
import asyncio
import os
import attestd

async def main():
    async with attestd.AsyncClient(api_key=os.environ["ATTESTD_API_KEY"]) as client:
        result = await client.check("log4j", "2.14.1")
        if result.risk_state in ("critical", "high"):
            raise RuntimeError(f"Vulnerable dependency: {result.cve_ids}")

asyncio.run(main())
```

## CI/CD deployment gate

```python
import os
import attestd

DEPENDENCIES = [
    ("nginx", "1.20.0"),
    ("log4j", "2.17.1"),
    ("openssh", "9.2p1"),
]

with attestd.Client(api_key=os.environ["ATTESTD_API_KEY"]) as client:
    for product, version in DEPENDENCIES:
        try:
            result = client.check(product, version)
        except attestd.AttestdUnsupportedProductError:
            continue

        if result.risk_state in ("critical", "high"):
            print(f"BLOCK: {product} {version} ({result.risk_state})")
            print(f"  CVEs: {', '.join(result.cve_ids)}")
            print(f"  Fix:  upgrade to {result.fixed_version}")
            exit(1)
```

## AI agent tool

```python
import os
import attestd

client = attestd.Client(api_key=os.environ["ATTESTD_API_KEY"])

def check_dependency_risk(product: str, version: str) -> dict:
    """Return risk_state, CVE IDs, and fixed version for a dependency."""
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

## Full error handling

```python
import os
import time
import attestd

with attestd.Client(api_key=os.environ["ATTESTD_API_KEY"]) as client:
    try:
        result = client.check("nginx", "1.20.0")
    except attestd.AttestdUnsupportedProductError:
        pass
    except attestd.AttestdRateLimitError as e:
        time.sleep(e.retry_after or 60)
    except attestd.AttestdAuthError:
        raise
    except attestd.AttestdAPIError as e:
        print(f"API error: {e.status_code}")
    except attestd.AttestdError:
        pass
```

### Outside coverage: not a safety signal

`AttestdUnsupportedProductError` means Attestd has no vulnerability data for this product, not that the product is free of vulnerabilities. An agent that catches the exception and treats it as safe to proceed is making a dangerous inference.

Recommended handling:

```python
try:
    result = client.check(product, version)
except attestd.AttestdUnsupportedProductError as e:
    raise RuntimeError(
        f"{e.product} is outside Attestd's coverage. "
        "Manual security review required before deploying."
    )
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
| `confidence` | `float` | Synthesis confidence (0.0-1.0) |
| `cve_ids` | `list[str]` | CVE IDs in this assessment |
| `last_updated` | `datetime` | UTC timestamp of last synthesis run |
| `supply_chain` | `SupplyChainSignal \| None` | PyPI/npm supply chain signal when monitored; `None` for CVE-only products |

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
    api_key=os.environ.get("ATTESTD_API_KEY"),
    base_url="https://api.attestd.io",
    timeout=10.0,
    max_retries=3,
    retry_delay=1.0,
)
```

Set `ATTESTD_API_KEY` in your environment from the [portal](https://api.attestd.io/portal/login). Then omit `api_key` in the constructor:

```python
with attestd.Client() as client:
    result = client.check("nginx", "1.20.0")
```

The SDK retries on transient 5xx responses and connection failures with exponential backoff (1s, 2s, 4s between attempts). `401` and `429` are surfaced immediately without retry.

## Supported products

See [attestd.io/docs/products](https://attestd.io/docs/products) for the full list. Each product page documents the API slug, version format, and notable CVEs. Querying an unsupported product raises `AttestdUnsupportedProductError`.

## Testing your integration

The SDK ships an `attestd.testing` module with httpx transports for injecting controlled API responses. No local Attestd instance required.

```python
import attestd
from attestd.testing import (
    MockTransport,
    MockAsyncTransport,
    SequentialMockTransport,
    SequentialMockAsyncTransport,
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
        (503, {}),
        (200, NGINX_SAFE),
    ])
    client = attestd.Client(api_key="test", transport=transport, max_retries=1)
    result = client.check("nginx", "1.27.4")
    assert result.risk_state == "none"
    assert transport.call_count == 2
```

### Test the outside coverage policy branch

```python
from attestd.testing import MockTransport, UNSUPPORTED

def test_outside_coverage_is_blocked_not_allowed():
    client = attestd.Client(api_key="test", transport=MockTransport(200, UNSUPPORTED))
    with pytest.raises(attestd.AttestdUnsupportedProductError):
        run_check(client, "unknownproduct", "1.0.0")
```

### Custom response bodies

All ready-made bodies (`NGINX_SAFE`, etc.) are plain dicts. Merge in overrides:

```python
from attestd.testing import MockTransport, NGINX_VULNERABLE

body = {**NGINX_VULNERABLE, "actively_exploited": True, "risk_state": "critical"}
client = attestd.Client(api_key="test", transport=MockTransport(200, body))
```

## License

MIT
