"""
Shared data models for the security toolkit.

These are plain dataclasses with zero GUI dependencies so they can be
reused by the Network Scanner, Android Analyzer, Report Generator, and
any future CLI front-end without coupling to PyQt.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional


class PortState(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


@dataclass
class CVEFinding:
    cve_id: str
    description: str
    severity: Severity
    cvss_score: Optional[float] = None
    published_date: Optional[str] = None
    references: List[str] = field(default_factory=list)


@dataclass
class ServiceInfo:
    name: str
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None

    @property
    def search_term(self) -> str:
        """Best-effort string to feed the CVE matcher, e.g. 'Apache 2.4.49'."""
        parts = [p for p in (self.product, self.version) if p]
        return " ".join(parts) if parts else self.name


@dataclass
class PortResult:
    port: int
    protocol: str
    state: PortState
    service: Optional[ServiceInfo] = None
    cves: List[CVEFinding] = field(default_factory=list)


@dataclass
class HostResult:
    ip: str
    hostname: Optional[str]
    is_up: bool
    ports: List[PortResult] = field(default_factory=list)
    os_guess: Optional[str] = None


@dataclass
class NetworkScanResult:
    target: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    hosts: List[HostResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def total_open_ports(self) -> int:
        return sum(1 for h in self.hosts for p in h.ports if p.state == PortState.OPEN)

    @property
    def total_cves(self) -> int:
        return sum(len(p.cves) for h in self.hosts for p in h.ports)

    @property
    def highest_severity(self) -> Severity:
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.UNKNOWN]
        found = {cve.severity for h in self.hosts for p in h.ports for cve in p.cves}
        for sev in order:
            if sev in found:
                return sev
        return Severity.UNKNOWN
