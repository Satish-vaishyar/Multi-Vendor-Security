"""SSRF guard for outbound webhook URLs.

A tenant administrator chooses the URL, so the server must refuse destinations that would let them probe the
platform's own network: loopback, link-local (incl. cloud metadata 169.254.169.254), multicast, unspecified,
reserved. RFC1918 private ranges are refused unless the operator opts in (WEBHOOK_ALLOW_PRIVATE=true), because
an on-prem deployment legitimately posts to an internal SIEM/chat gateway. Loopback is only ever allowed in
development with that same opt-in (used by tests). The check runs when the webhook is saved AND again just
before every delivery (the hostname may have been re-pointed since).

DNS rebinding: ``pin()`` resolves and validates ONCE and returns a URL whose host is the validated IP address
(the original name travels in the Host header / TLS SNI), so the connection can only go to an address that passed
the check - there is no second resolution a hostile DNS server could answer differently. Network egress rules on the
worker hosts remain the authoritative control (defence in depth).
"""
from __future__ import annotations
import ipaddress
import socket
from typing import Dict, List, NamedTuple, Optional
from urllib.parse import urlparse, urlunparse

from app.core import config as cfg


class UnsafeURL(ValueError):
    pass


# Cloud metadata / control-plane endpoints that are refused even with WEBHOOK_ALLOW_PRIVATE=true.
_ALWAYS_BLOCKED = {ipaddress.ip_address(a) for a in (
    "169.254.169.254", "169.254.170.2", "100.100.100.200",       # AWS/GCP/Azure/ECS, Alibaba
    "168.63.129.16",                                              # Azure wire server
    "fd00:ec2::254")}                                             # AWS IMDS over IPv6
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _embedded_v4(ip):
    """The IPv4 address tunnelled inside an IPv6 one (v4-mapped, NAT64, 6to4), else None."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            return ip.ipv4_mapped
        if ip in _NAT64:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if ip.sixtofour:
            return ip.sixtofour
    return None


def _check_ip(raw: str) -> None:
    ip = ipaddress.ip_address(raw.split("%", 1)[0])             # drop an IPv6 zone id
    inner = _embedded_v4(ip)
    if inner is not None:
        ip = inner
    if ip in _ALWAYS_BLOCKED:
        raise UnsafeURL(f"address {ip} is not allowed (cloud metadata / control plane)")
    dev_loopback = cfg.ENV != "production" and cfg.WEBHOOK_ALLOW_PRIVATE
    if ip.is_loopback:
        if not dev_loopback:
            raise UnsafeURL("loopback addresses are not allowed")
        return
    if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        raise UnsafeURL(f"address {ip} is not allowed (link-local / metadata / reserved)")
    if ip.is_private and not cfg.WEBHOOK_ALLOW_PRIVATE:
        raise UnsafeURL("private-network destinations are disabled (set WEBHOOK_ALLOW_PRIVATE=true to allow an internal SIEM)")
    if not ip.is_global and not ip.is_private and not cfg.WEBHOOK_ALLOW_PRIVATE:
        # e.g. 100.64.0.0/10 carrier-grade NAT, 192.0.0.0/24, benchmarking ranges: not private, not public either
        raise UnsafeURL(f"address {ip} is not a publicly routable address")


def validate(url: str) -> List[str]:
    """Raise UnsafeURL unless the URL is acceptable; returns the resolved addresses."""
    try:
        u = urlparse(url)
        port = u.port
    except ValueError:
        raise UnsafeURL("malformed URL")
    if u.scheme not in ("https", "http"):
        raise UnsafeURL("only http(s) URLs are allowed")
    if u.scheme == "http" and cfg.ENV == "production" and not cfg.WEBHOOK_ALLOW_HTTP:
        raise UnsafeURL("plain http is not allowed in production (use https)")
    if not u.hostname:
        raise UnsafeURL("URL has no host")
    if u.username or u.password:
        raise UnsafeURL("credentials in the URL are not allowed")
    if port is not None and not (1 <= port <= 65535):
        raise UnsafeURL("invalid port")
    try:
        infos = socket.getaddrinfo(u.hostname, port or (443 if u.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise UnsafeURL("host name does not resolve")
    ips = sorted({i[4][0] for i in infos}, key=lambda a: (":" in a, a))      # IPv4 first (many hosts have no IPv6 route)
    if not ips:
        raise UnsafeURL("host name does not resolve")
    for ip in ips:
        _check_ip(ip)
    return ips


class Pinned(NamedTuple):
    """One validated connection target for a webhook URL."""
    url: str                       # same URL with the host replaced by the validated IP address
    headers: Dict[str, str]        # {"Host": original authority}
    sni_hostname: Optional[str]    # original name for TLS SNI + certificate verification (https with a DNS name)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def pin(url: str) -> List[Pinned]:
    """Validate ``url`` and return one connection target per resolved address (IPv4 first).

    The caller connects to ``Pinned.url`` only; ``validate`` and the connection therefore use the very same
    resolution, closing the DNS-rebinding window between check and use.
    """
    ips = validate(url)
    u = urlparse(url)
    host = u.hostname or ""
    default_port = 443 if u.scheme == "https" else 80
    port = u.port or default_port
    shown = f"[{host}]" if ":" in host else host
    authority = shown if port == default_port else f"{shown}:{port}"
    out: List[Pinned] = []
    for ip in ips:
        netloc = f"[{ip}]" if ":" in ip else ip
        if port != default_port:
            netloc = f"{netloc}:{port}"
        pinned = urlunparse((u.scheme, netloc, u.path or "/", u.params, u.query, ""))
        sni = host if (u.scheme == "https" and not _is_ip_literal(host)) else None
        out.append(Pinned(pinned, {"Host": authority}, sni))
    return out
