"""Tests for products(), cve(), and usage() on Client and AsyncClient."""

from __future__ import annotations

import pytest

import attestd
from attestd.errors import AttestdAPIError
from attestd.testing import CVE_LOG4SHELL, PRODUCTS_RESPONSE, USAGE_SOLO

from tests.conftest import make_async_client, make_client


def test_products_returns_result():
    client = make_client([(200, PRODUCTS_RESPONSE)])
    result = client.products()
    assert result.total == 3
    assert len(result.cve_products) == 2
    assert result.cve_products[0].slug == "nginx"
    assert result.supply_chain_packages[0].package == "litellm"


def test_cve_returns_detail():
    client = make_client([(200, CVE_LOG4SHELL)])
    detail = client.cve("CVE-2021-44228")
    assert detail.cve_id == "CVE-2021-44228"
    assert detail.cvss_score == pytest.approx(10.0)
    assert detail.epss_score == pytest.approx(0.97568)
    assert "log4j" in detail.affected_products


def test_cve_404_raises_api_error():
    client = make_client([(404, {"detail": "CVE not found"})])
    with pytest.raises(AttestdAPIError) as exc_info:
        client.cve("CVE-9999-99999")
    assert exc_info.value.status_code == 404


def test_usage_returns_result():
    client = make_client([(200, USAGE_SOLO)])
    usage = client.usage()
    assert usage.tier == "solo"
    assert usage.included_calls == 250000
    assert usage.key_calls_this_month == 1200
    assert usage.billing_period_start is not None
    assert usage.billing_period_end is not None


def test_top_level_exports():
    assert hasattr(attestd, "UsageResult")
    assert hasattr(attestd, "CveDetail")
    assert hasattr(attestd, "ProductsResult")
    assert hasattr(attestd, "ProductEntry")
    assert hasattr(attestd, "SupplyChainEntry")


@pytest.mark.asyncio
async def test_async_products_returns_result():
    client = make_async_client([(200, PRODUCTS_RESPONSE)])
    result = await client.products()
    assert result.total == 3
    assert result.cve_products[0].display_name == "NGINX"


@pytest.mark.asyncio
async def test_async_cve_returns_detail():
    client = make_async_client([(200, CVE_LOG4SHELL)])
    detail = await client.cve("CVE-2021-44228")
    assert detail.epss_percentile == pytest.approx(0.99976)


@pytest.mark.asyncio
async def test_async_cve_404_raises_api_error():
    client = make_async_client([(404, {"detail": "CVE not found"})])
    with pytest.raises(AttestdAPIError) as exc_info:
        await client.cve("CVE-9999-99999")
    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_async_usage_returns_result():
    client = make_async_client([(200, USAGE_SOLO)])
    usage = await client.usage()
    assert usage.account_calls_this_month == 1200
    assert usage.overage_calls == 0
