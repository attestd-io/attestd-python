"""
Attestd response models.

RiskResult is the return type of Client.check() and AsyncClient.check().
It is a frozen dataclass. All fields are set at construction and cannot
be modified. This makes it safe to cache and pass between threads.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

# The five risk states in ascending severity order.
RiskState = Literal["critical", "high", "elevated", "low", "none"]

# Risk factor labels returned in the risk_factors list.
# These are computed deterministically from the boolean fields.
RiskFactor = Literal[
    "active_exploitation",       # CVE is on the CISA KEV list
    "remote_code_execution",     # remote_exploitable = True
    "no_authentication_required",# remote_exploitable = True and authentication_required = False
    "internet_exposed_service",  # remote_exploitable = True and authentication_required = False
    "patch_available",           # a fixed_version is known
]


@dataclass(frozen=True, slots=True)
class TyposquatSignal:
    """Package name resembles a known product (possible typosquat)."""

    detected: bool
    resembles: str | None = None
    confidence: float = 0.0
    ecosystem: str = ""


@dataclass(frozen=True, slots=True)
class CveSummary:
    """Per-CVE detail record returned when include=cves is passed."""

    cve_id: str
    cvss_score: float | None = None
    actively_exploited: bool = False
    remote_exploitable: bool = False
    epss_score: float | None = None
    epss_percentile: float | None = None


@dataclass(frozen=True, slots=True)
class SupplyChainSignal:
    """
    PyPI supply chain assessment for monitored packages (independent of CVE risk_state).

    Present when the product has supply-chain monitoring; see API docs for null semantics.
    """

    compromised: bool
    sources: tuple[str, ...] = ()
    malware_type: str | None = None
    description: str | None = None
    advisory_url: str | None = None
    compromised_at: datetime | None = None
    removed_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class RiskResult:
    """
    Security risk assessment for a specific product version.

    Returned by Client.check() and AsyncClient.check() when the queried
    product is in Attestd's supported product list.

    Attributes:
        product:               Product name as recognised by Attestd (e.g. "nginx").
        version:               Version string as submitted to check().
        risk_state:            Aggregated risk classification. See RiskState.
        risk_factors:          Machine-readable factors driving risk_state.
                               See RiskFactor for the possible values.
        actively_exploited:    True if any matching CVE is on the CISA KEV list.
        remote_exploitable:    True if any matching CVE is remotely exploitable.
        authentication_required: True only if ALL matching CVEs require authentication.
                               (Worst-case: a single no-auth CVE sets this to False.)
        patch_available:       True if a known fixed version exists.
        fixed_version:         The earliest version that resolves all known CVEs, if known.
        confidence:            Synthesis confidence (0.0–1.0).
                               Values < 0.7 indicate LLM fallback to DB-derived fields.
        cve_ids:               CVE IDs contributing to this assessment.
        max_epss:              Highest EPSS probability across matching CVEs, or None.
        cves:                  Per-CVE detail when include=cves was requested.
        last_updated:          UTC timestamp of the most recent synthesis run.
        supply_chain:          PyPI supply chain signal when monitored; None if CVE-only product.
        typosquat:             Typosquat warning when the package name resembles a known product.
    """

    product: str
    version: str
    risk_state: RiskState
    risk_factors: list[str]
    actively_exploited: bool
    remote_exploitable: bool
    authentication_required: bool
    patch_available: bool
    fixed_version: str | None
    confidence: float
    cve_ids: list[str] = field(default_factory=list)
    max_epss: float | None = None
    cves: list[CveSummary] = field(default_factory=list)
    last_updated: datetime = field(default_factory=lambda: datetime.min)
    supply_chain: SupplyChainSignal | None = None
    typosquat: TyposquatSignal | None = None
