"""
Core network scanning engine.

Wraps python-nmap for host discovery / port / service-version detection,
and enriches open-port findings with CVE data via CVEMatcher. Deliberately
has zero Qt dependency: it can be unit tested or driven from a future CLI
exactly the same way the GUI drives it.
"""

import logging
import shutil
from datetime import datetime
from typing import Callable, Optional

import nmap

from src.core.cve_matcher import CVEMatcher
from src.core.models import HostResult, NetworkScanResult, PortResult, PortState, ServiceInfo
from src.utils.validators import validate_port_range, validate_target

logger = logging.getLogger(__name__)


class NmapNotFoundError(RuntimeError):
    """Raised when the nmap binary is not found on the system PATH."""


class NetworkScannerEngine:
    def __init__(self, cve_matcher: Optional[CVEMatcher] = None):
        if shutil.which("nmap") is None:
            raise NmapNotFoundError(
                "nmap binary not found on PATH. Install it first: "
                "'sudo apt install nmap' (Linux), 'brew install nmap' (macOS), "
                "or https://nmap.org/download.html (Windows)."
            )
        self._nm = nmap.PortScanner()
        self._cve_matcher = cve_matcher or CVEMatcher()
        self._cancelled = False

    def cancel(self) -> None:
        """Request cancellation. Checked between hosts/ports; not instantaneous."""
        self._cancelled = True

    def scan(
        self,
        target: str,
        port_range: str = "1-1024",
        enable_cve_lookup: bool = True,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> NetworkScanResult:
        self._cancelled = False
        target = validate_target(target)
        port_range = validate_port_range(port_range)

        result = NetworkScanResult(target=target, started_at=datetime.now())

        def report(msg: str) -> None:
            logger.info(msg)
            if progress_callback:
                progress_callback(msg)

        try:
            report(f"Starting scan of {target} (ports {port_range})...")
            # -sV: service/version detection. -T4: faster timing template.
            # No -sS/-O here, so this runs fine WITHOUT root (unprivileged
            # TCP connect scan). Add -sS/-O as an opt-in "privileged mode"
            # later if you want SYN scans / OS fingerprinting.
            self._nm.scan(hosts=target, ports=port_range, arguments="-sV -T4")
        except nmap.PortScannerError as exc:
            result.errors.append(f"Scan failed: {exc}")
            result.finished_at = datetime.now()
            return result
        except Exception as exc:  # noqa: BLE001 - surface any OS/nmap-level failure to the UI
            result.errors.append(f"Unexpected scan error: {exc}")
            result.finished_at = datetime.now()
            return result

        for host_ip in self._nm.all_hosts():
            if self._cancelled:
                report("Scan cancelled by user.")
                break

            host_data = self._nm[host_ip]
            host_result = HostResult(
                ip=host_ip,
                hostname=host_data.hostname() or None,
                is_up=host_data.state() == "up",
                os_guess=self._guess_os(host_data),
            )
            report(f"Host {host_ip} is {'up' if host_result.is_up else 'down'}")

            for proto in host_data.all_protocols():
                if self._cancelled:
                    break
                for port in sorted(host_data[proto].keys()):
                    if self._cancelled:
                        break
                    host_result.ports.append(
                        self._build_port_result(host_data[proto][port], port, proto, enable_cve_lookup, report)
                    )

            result.hosts.append(host_result)

        result.finished_at = datetime.now()
        report("Scan complete.")
        return result

    # ------------------------------------------------------------- helpers

    def _build_port_result(self, port_info: dict, port: int, proto: str, enable_cve_lookup: bool, report) -> PortResult:
        state = self._map_state(port_info.get("state", "filtered"))

        service = None
        if port_info.get("name") or port_info.get("product"):
            service = ServiceInfo(
                name=port_info.get("name", "unknown"),
                product=port_info.get("product") or None,
                version=port_info.get("version") or None,
                extra_info=port_info.get("extrainfo") or None,
            )

        port_result = PortResult(port=port, protocol=proto, state=state, service=service)

        if state == PortState.OPEN and service and enable_cve_lookup:
            report(f"  Checking CVEs for {service.search_term or service.name}...")
            try:
                port_result.cves = self._cve_matcher.lookup(service.search_term)
            except Exception as exc:  # noqa: BLE001 - a failed CVE lookup must not abort the scan
                logger.warning("CVE lookup failed for %s: %s", service.search_term, exc)

        return port_result

    @staticmethod
    def _map_state(nmap_state: str) -> PortState:
        return {
            "open": PortState.OPEN,
            "closed": PortState.CLOSED,
            "filtered": PortState.FILTERED,
        }.get(nmap_state, PortState.FILTERED)

    @staticmethod
    def _guess_os(host_data) -> Optional[str]:
        os_matches = host_data.get("osmatch")
        if os_matches:
            return os_matches[0].get("name")
        return None
