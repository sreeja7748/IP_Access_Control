import pytest
from ip_access_control import is_allowed, parse_ip

# ── Should be ALLOWED ──────────────────────────────────────
@pytest.mark.parametrize("ip", [
    "10.0.0.1",           # IPv4 private Class A
    "10.255.255.255",     # IPv4 private Class A edge
    "172.16.5.10",        # IPv4 private Class B
    "192.168.1.100",      # IPv4 private Class C
    "127.0.0.1",          # IPv4 loopback
    "203.0.113.45",       # IPv4 public (your range)
    "::1",                # IPv6 loopback
    "fc00::1",            # IPv6 unique local
    "fe80::1",            # IPv6 link-local
    "2001:db8::1",        # IPv6 public (your range)
    "::ffff:10.0.0.1",   # IPv4-mapped IPv6 → treated as 10.0.0.1
])
def test_allowed(ip):
    assert is_allowed(ip) is True, f"Expected {ip} to be ALLOWED"


# ── Should be DENIED ───────────────────────────────────────
@pytest.mark.parametrize("ip", [
    "8.8.8.8",            # Google DNS — not in allowlist
    "1.1.1.1",            # Cloudflare DNS — not in allowlist
    "0.0.0.0",            # Null address
    "169.254.0.1",        # IPv4 link-local (APIPA) — not explicitly allowed
    "2600::1",            # Random IPv6 public — not in allowlist
    "192.0.2.1",          # TEST-NET — not in allowlist
])
def test_denied(ip):
    assert is_allowed(ip) is False, f"Expected {ip} to be DENIED"


# ── Edge cases ─────────────────────────────────────────────
def test_malformed_ip_denied():
    assert is_allowed("not_an_ip") is False
    assert is_allowed("999.999.999.999") is False
    assert is_allowed("") is False

def test_ipv4_mapped_ipv6():
    # ::ffff:10.0.0.1 should be treated as 10.0.0.1 and allowed
    assert is_allowed("::ffff:10.0.0.1") is True

def test_ip_with_port_stripped():
    assert is_allowed("192.168.1.1:8080") is True

def test_boundary_cidrs():
    assert is_allowed("172.15.255.255") is False  # just outside 172.16.0.0/12
    assert is_allowed("172.16.0.0") is True        # first IP in range
    assert is_allowed("172.31.255.255") is True    # last IP in range
    assert is_allowed("172.32.0.0") is False       # just outside