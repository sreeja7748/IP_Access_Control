import ipaddress
from typing import Union

# ─────────────────────────────────────────────
# ALLOWLIST — Class A and Class C only
# ─────────────────────────────────────────────
ALLOWED_CIDRS = [
    "10.0.0.0/8",        # Class A private
    "192.168.0.0/16",    # Class C private
    "127.0.0.1/32",      # Loopback (for local testing)
]

# Pre-compile networks once at startup for performance
_COMPILED_NETWORKS = [
    ipaddress.ip_network(cidr, strict=False) for cidr in ALLOWED_CIDRS
]


def parse_ip(raw_ip: str) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address]:
    """
    Parse a raw IP string into an address object.
    Handles IPv4-mapped IPv6 addresses like ::ffff:192.168.1.1
    and strips port numbers if present (e.g. '10.0.0.1:8080').
    """
    raw_ip = raw_ip.strip()

    # Strip port from IPv4 (e.g. "1.2.3.4:8080" → "1.2.3.4")
    if raw_ip.count(":") == 1:
        raw_ip = raw_ip.split(":")[0]

    # Strip brackets from IPv6 (e.g. "[::1]:8080" → "::1")
    if raw_ip.startswith("["):
        raw_ip = raw_ip.split("]")[0].lstrip("[")

    addr = ipaddress.ip_address(raw_ip)

    # Unwrap IPv4-mapped IPv6 → treat as native IPv4
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return addr.ipv4_mapped

    return addr


def is_allowed(raw_ip: str) -> bool:
    """
    Returns True if the IP falls within any allowed CIDR range.
    Returns False immediately if the IP is invalid or not matched.
    """
    try:
        addr = parse_ip(raw_ip)
    except ValueError:
        return False  # Malformed IP → deny

    return any(addr in network for network in _COMPILED_NETWORKS)


def get_real_ip(headers: dict, remote_addr: str) -> str:
    """
    Safely extract the real client IP from request headers.
    WARNING: X-Forwarded-For can be spoofed by clients.
    Only trust it when you control the upstream proxy/load balancer.
    Always take the LAST (rightmost) IP added by your trusted proxy.
    """
    forwarded_for = headers.get("X-Forwarded-For", "")
    if forwarded_for:
        # Rightmost IP is added by your trusted load balancer
        # Leftmost is client-supplied and can be spoofed
        ips = [ip.strip() for ip in forwarded_for.split(",")]
        return ips[-1]  # Use rightmost = most trustworthy

    # CF-Connecting-IP (Cloudflare) or True-Client-IP (Akamai)
    for header in ("CF-Connecting-IP", "True-Client-IP", "X-Real-IP"):
        if headers.get(header):
            return headers[header].strip()

    return remote_addr  # Fallback to direct connection IP