"""
Input validation for scan targets and port ranges.

Rejecting malformed/malicious input here — before it ever reaches a
subprocess call to nmap — is the primary defense against argument or
shell injection, even though python-nmap itself does not use shell=True.
"""

import ipaddress
import re

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
_ILLEGAL_CHARS_RE = re.compile(r"[;&|`$<>\\\"']")
_PORT_RANGE_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")


class InvalidTargetError(ValueError):
    """Raised when a scan target or port range fails validation."""


def validate_target(target: str) -> str:
    """
    Validate a scan target: single IP, CIDR range, or hostname.

    Returns the cleaned target string, or raises InvalidTargetError.
    """
    target = (target or "").strip()
    if not target:
        raise InvalidTargetError("Target cannot be empty.")

    if _ILLEGAL_CHARS_RE.search(target):
        raise InvalidTargetError("Target contains illegal characters.")

    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass

    if _HOSTNAME_RE.match(target):
        return target

    raise InvalidTargetError(f"'{target}' is not a valid IP, CIDR range, or hostname.")


def validate_port_range(port_range: str) -> str:
    """
    Validate a port range string like '80', '1-1024', or '22,80,443,8000-9000'.
    """
    port_range = (port_range or "").strip()
    if not _PORT_RANGE_RE.match(port_range):
        raise InvalidTargetError(
            f"'{port_range}' is not a valid port range (examples: '80', '1-1024', '22,443,8080-8090')."
        )

    for part in port_range.split(","):
        bounds = [int(b) for b in part.split("-")]
        for b in bounds:
            if not (0 <= b <= 65535):
                raise InvalidTargetError(f"Port {b} is out of the valid range (0-65535).")
        if len(bounds) == 2 and bounds[0] > bounds[1]:
            raise InvalidTargetError(f"Invalid range '{part}': start port exceeds end port.")

    return port_range
