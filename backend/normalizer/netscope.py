"""
ULPF network scope resolution.

Determines whether an address belongs to the monitored estate ("internal") or
not. Traffic direction, and therefore most security meaning, depends on this.

Why this is not `ipaddress.ip_address(x).is_private`
----------------------------------------------------
Python's `is_private` follows the IANA special-purpose registry, which marks the
RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
and the RFC 2544 benchmarking range (198.18.0.0/15) as private. Those are the
exact ranges every vendor uses to represent *external* hosts in sample logs, so
`is_private` reports an inbound attack from 203.0.113.45 as internal traffic and
the direction field silently becomes wrong.

"Internal" is also not a property of an address in the abstract - it is a
property of a deployment. ULPF therefore takes the same approach as Zeek's
`local_nets` and the Splunk CIM: the operator declares which prefixes are
internal, and everything else is external. RFC 1918 plus loopback and
link-local is only the default.

Configure per site with the ULPF_INTERNAL_NETWORKS environment variable, e.g.
    ULPF_INTERNAL_NETWORKS="10.0.0.0/8,192.168.0.0/16,2001:db8:1::/48"
"""

from __future__ import annotations

import ipaddress
import os
from typing import Iterable, List, Optional, Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

#: Default internal estate: RFC 1918 private space, loopback, link-local,
#: RFC 6598 carrier-grade NAT, and IPv6 unique-local / link-local.
#: Deliberately excludes RFC 5737 documentation and RFC 2544 benchmark ranges.
DEFAULT_INTERNAL_NETWORKS: tuple = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
)

#: Ranges reserved for documentation and benchmarking. These are routable-looking
#: but never real hosts; they appear constantly in sample and training data.
#: Tracked separately so the UI can label demo traffic honestly.
DOCUMENTATION_NETWORKS: tuple = (
    "192.0.2.0/24",      # RFC 5737 TEST-NET-1
    "198.51.100.0/24",   # RFC 5737 TEST-NET-2
    "203.0.113.0/24",    # RFC 5737 TEST-NET-3
    "198.18.0.0/15",     # RFC 2544 benchmarking
    "2001:db8::/32",     # RFC 3849 documentation
)


def _parse_networks(specs: Iterable[str]) -> List[IPNetwork]:
    nets: List[IPNetwork] = []
    for spec in specs:
        spec = spec.strip()
        if not spec:
            continue
        try:
            nets.append(ipaddress.ip_network(spec, strict=False))
        except ValueError:
            # An unparseable prefix must not silently widen or narrow the
            # estate definition; skip it and keep the rest.
            continue
    return nets


class NetworkScope:
    """Resolves addresses to internal / external / documentation scope."""

    def __init__(self, internal_networks: Optional[Iterable[str]] = None):
        if internal_networks is None:
            env = os.environ.get("ULPF_INTERNAL_NETWORKS", "")
            specs = env.split(",") if env.strip() else DEFAULT_INTERNAL_NETWORKS
        else:
            specs = internal_networks
        self.internal_networks: List[IPNetwork] = _parse_networks(specs)
        self.documentation_networks: List[IPNetwork] = _parse_networks(DOCUMENTATION_NETWORKS)

    @staticmethod
    def parse(value) -> Optional[IPAddress]:
        if not value:
            return None
        try:
            return ipaddress.ip_address(str(value).strip())
        except ValueError:
            return None

    def _in(self, addr: IPAddress, nets: List[IPNetwork]) -> bool:
        return any(addr.version == n.version and addr in n for n in nets)

    def is_internal(self, value) -> Optional[bool]:
        """True if inside the monitored estate, False if outside, None if the
        value is not an IP address at all. None is meaningful: it means unknown,
        and callers must not treat it as False."""
        addr = self.parse(value)
        if addr is None:
            return None
        return self._in(addr, self.internal_networks)

    def is_documentation(self, value) -> bool:
        """True for RFC 5737 / RFC 3849 / RFC 2544 reserved ranges."""
        addr = self.parse(value)
        return addr is not None and self._in(addr, self.documentation_networks)

    def scope_of(self, value) -> str:
        """Human-readable scope label: internal, external, documentation, unknown."""
        addr = self.parse(value)
        if addr is None:
            return "unknown"
        if self._in(addr, self.internal_networks):
            return "internal"
        if self._in(addr, self.documentation_networks):
            return "documentation"
        return "external"

    def direction(self, src, dst, explicit: object = None) -> str:
        """Canonical traffic direction.

        An explicit direction reported by the device wins, but only if it is a
        value we recognise - vendors overload this field (PAN-OS uses
        client-to-server, Zeek uses orig/resp), and silently accepting those
        produces a canonical field that is not canonical.
        """
        if explicit:
            token = str(explicit).strip().upper()
            if token in ("INBOUND", "OUTBOUND", "INTERNAL", "EXTERNAL"):
                return token

        s_int = self.is_internal(src)
        d_int = self.is_internal(dst)

        if s_int is None or d_int is None:
            return "UNKNOWN"
        if s_int and d_int:
            return "INTERNAL"
        if not s_int and d_int:
            return "INBOUND"
        if s_int and not d_int:
            return "OUTBOUND"
        return "EXTERNAL"


#: Shared default instance, configured from the environment at import time.
default_scope = NetworkScope()
