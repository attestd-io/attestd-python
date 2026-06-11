"""
Tests for error paths in response parsing and client configuration.
"""

from __future__ import annotations

import pytest

import attestd
from attestd import Client
from attestd.errors import AttestdAPIError, AttestdError, AttestdUnsupportedProductError
from attestd.testing import MockTransport

from tests.conftest import SUPPORTED_NGINX_BODY, make_client


def test_malformed_json_raises_api_error():
    import httpx

    class BadJsonTransport(httpx.BaseTransport):
        def handle_request(self, request):  # type: ignore[override]
            return httpx.Response(200, content=b"not json")

    client = Client(api_key="atst_test", transport=BadJsonTransport())
    with pytest.raises(AttestdAPIError) as exc_info:
        client.check("nginx", "1.20.0")
    assert exc_info.value.status_code == 200
    assert "JSON" in str(exc_info.value)


def test_404_raises_unsupported_product_error():
    client = make_client([(404, {"detail": "not found"})])
    with pytest.raises(AttestdUnsupportedProductError) as exc_info:
        client.check("unknownproduct", "1.0.0")
    assert exc_info.value.product == "unknownproduct"
    assert exc_info.value.version == "1.0.0"


def test_missing_risk_state_raises_api_error():
    body = {**SUPPORTED_NGINX_BODY}
    del body["risk_state"]
    client = make_client([(200, body)])
    with pytest.raises(AttestdAPIError) as exc_info:
        client.check("nginx", "1.20.0")
    assert "risk_state" in str(exc_info.value)


def test_invalid_risk_state_raises_api_error():
    body = {**SUPPORTED_NGINX_BODY, "risk_state": "unknown"}
    client = make_client([(200, body)])
    with pytest.raises(AttestdAPIError) as exc_info:
        client.check("nginx", "1.20.0")
    assert "risk_state" in str(exc_info.value)


def test_invalid_last_updated_raises_api_error():
    body = {**SUPPORTED_NGINX_BODY, "last_updated": "not-a-date"}
    client = make_client([(200, body)])
    with pytest.raises(AttestdAPIError) as exc_info:
        client.check("nginx", "1.20.0")
    assert "last_updated" in str(exc_info.value)


def test_api_key_from_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ATTESTD_API_KEY", "  atst_from_env  ")
    client = Client(transport=MockTransport(200, SUPPORTED_NGINX_BODY))
    result = client.check("nginx", "1.20.0")
    assert result.product == "nginx"


def test_missing_api_key_raises(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("ATTESTD_API_KEY", raising=False)
    with pytest.raises(AttestdError) as exc_info:
        Client()
    assert "ATTESTD_API_KEY" in str(exc_info.value)


def test_timeout_does_not_retry():
    import httpx

    class TimeoutTransport(httpx.BaseTransport):
        def handle_request(self, request):  # type: ignore[override]
            raise httpx.TimeoutException("timed out")

    client = Client(
        api_key="atst_test",
        transport=TimeoutTransport(),
        max_retries=3,
    )
    with pytest.raises(AttestdAPIError) as exc_info:
        client.check("nginx", "1.20.0")
    assert exc_info.value.status_code == 0
    assert "timed out" in str(exc_info.value).lower()


def test_non_dict_json_raises_api_error():
    import httpx

    class ArrayJsonTransport(httpx.BaseTransport):
        def handle_request(self, request):  # type: ignore[override]
            return httpx.Response(200, content=b"[1, 2, 3]")

    client = Client(api_key="atst_test", transport=ArrayJsonTransport())
    with pytest.raises(AttestdAPIError):
        client.check("nginx", "1.20.0")
