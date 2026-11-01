"""Read-only live collection of device configurations over SSH.

Design rules (each has a test in tests/test_collector.py):
  * READ ONLY: only commands from a per-platform allow-list are ever sent, as exec requests (no interactive shell, so
    no way to "enter config mode"). An unknown command raises before any connection is opened.
  * The device's host key is PINNED (SHA-256 fingerprint stored per target) and verified BEFORE authentication, so a
    credential is never offered to an impostor. There is no trust-on-first-use inside a collection run: the operator
    scans the key (``scan_host_key``) and confirms the fingerprint once.
  * Credentials live only in ``device_credentials``, encrypted with the field-encryption keys, and are never returned
    by any API. They are decrypted in the worker for the duration of one connection.
  * Targets are validated like webhooks: metadata / loopback / link-local / multicast are refused; private ranges are
    allowed by default (devices are usually private) and can be confined to ``COLLECT_ALLOWED_CIDRS``.
  * Output is capped (``COLLECT_MAX_BYTES``) and every command has a timeout; the transport is injectable so the
    orchestration is tested without a network.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import io
import ipaddress
import socket
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Protocol

from app.core import config as cfg
from app.core import urlcheck


class CollectError(Exception):
    """Collection failed; the message is safe to show to the operator (never contains credentials)."""


@dataclass(frozen=True)
class Profile:
    key: str
    label: str
    commands: List[str]          # sent in order; the FIRST is the configuration, the rest are appended as comments
    vendor_hint: str


# The ONLY commands the collector will ever send. Adding one is a reviewed code change, never a runtime setting.
PROFILES: Dict[str, Profile] = {p.key: p for p in (
    Profile("cisco_ios", "Cisco IOS / IOS-XE", ["show running-config", "show version"], "cisco"),
    Profile("cisco_nxos", "Cisco NX-OS", ["show running-config", "show version"], "cisco"),
    Profile("juniper_junos", "Juniper Junos", ["show configuration | display set", "show version"], "juniper"),
    Profile("fortinet_fortios", "Fortinet FortiOS", ["show full-configuration", "get system status"], "fortinet"),
    Profile("paloalto_panos", "Palo Alto PAN-OS", ["show config running", "show system info"], "paloalto"),
    Profile("arista_eos", "Arista EOS", ["show running-config", "show version"], "arista"),
)}


def assert_read_only(profile: str, command: str) -> None:
    p = PROFILES.get(profile)
    if p is None:
        raise CollectError(f"unknown device profile {profile!r}")
    if command not in p.commands:
        raise CollectError("command is not on the read-only allow-list")


# ---------------------------------------------------------------- targets
def check_target(host: str, port: int) -> str:  # noqa: C901
    """Resolve and validate the SSH target; returns the address to connect to (the one that was validated)."""
    if not (1 <= int(port) <= 65535):
        raise CollectError("invalid port")
    if not host or len(host) > 253 or any(c in host for c in " /\\@\x00"):
        raise CollectError("invalid host")
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise CollectError("host name does not resolve")
    ips = sorted({str(i[4][0]) for i in infos}, key=lambda a: (":" in a, a))
    if not ips:
        raise CollectError("host name does not resolve")
    nets = [ipaddress.ip_network(n.strip(), strict=False) for n in cfg.COLLECT_ALLOWED_CIDRS if n.strip()]
    for ip in ips:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
        if addr in urlcheck._ALWAYS_BLOCKED or addr.is_link_local or addr.is_multicast or addr.is_unspecified or addr.is_reserved:
            raise CollectError(f"address {addr} is not allowed")
        if addr.is_loopback and not (cfg.ENV != "production" and cfg.COLLECT_ALLOW_LOOPBACK):
            raise CollectError("loopback addresses are not allowed")
        if nets and not any(addr in n for n in nets):
            raise CollectError(f"address {addr} is outside COLLECT_ALLOWED_CIDRS")
        if addr.is_private and not addr.is_loopback and not cfg.COLLECT_ALLOW_PRIVATE and not nets:
            raise CollectError("private addresses are disabled (COLLECT_ALLOW_PRIVATE=false)")
    return ips[0]


def fingerprint(raw_key: bytes) -> str:
    """OpenSSH-style SHA256 fingerprint of a public-key blob."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw_key).digest()).decode().rstrip("=")


def same_fingerprint(a: str, b: str) -> bool:
    return hmac.compare_digest(a.strip().encode(), b.strip().encode())


# ---------------------------------------------------------------- transport
class Transport(Protocol):
    def host_key(self) -> bytes: ...
    def login(self, username: str, secret: str, auth_type: str) -> None: ...
    def run(self, command: str, max_bytes: int, timeout: float) -> str: ...
    def close(self) -> None: ...


TransportFactory = Callable[[str, int, float], Transport]


class ParamikoTransport:
    """Real SSH. paramiko is imported lazily so the rest of the application runs without it."""

    def __init__(self, address: str, port: int, timeout: float):
        import paramiko
        self._p = paramiko
        sock = socket.create_connection((address, port), timeout=timeout)
        self._t = paramiko.Transport(sock)
        self._t.banner_timeout = timeout
        try:
            self._t.start_client(timeout=timeout)
        except Exception as e:
            self.close()
            raise CollectError(f"SSH negotiation failed: {type(e).__name__}")

    def host_key(self) -> bytes:
        return self._t.get_remote_server_key().asbytes()

    def login(self, username: str, secret: str, auth_type: str) -> None:
        try:
            if auth_type == "key":
                key = None
                for cls in (self._p.Ed25519Key, self._p.ECDSAKey, self._p.RSAKey):
                    try:
                        key = cls.from_private_key(io.StringIO(secret))
                        break
                    except Exception:
                        continue
                if key is None:
                    raise CollectError("the stored private key could not be read")
                self._t.auth_publickey(username, key)
            else:
                self._t.auth_password(username, secret)
        except CollectError:
            raise
        except Exception:
            raise CollectError("authentication failed")

    def run(self, command: str, max_bytes: int, timeout: float) -> str:
        try:
            chan = self._t.open_session(timeout=timeout)
            chan.settimeout(timeout)
            chan.exec_command(command)
        except self._p.SSHException:
            raise CollectError("the device refused the command channel")
        buf = bytearray()
        while True:
            try:
                chunk = chan.recv(65536)
            except socket.timeout:
                raise CollectError("command timed out")
            except self._p.SSHException:
                break
            if not chunk:
                break
            buf += chunk
            if len(buf) > max_bytes:
                chan.close()
                raise CollectError("output exceeded COLLECT_MAX_BYTES")
        chan.close()
        return buf.decode("utf-8", "replace")

    def close(self) -> None:
        try:
            self._t.close()
        except Exception:
            pass


def _default_factory(address: str, port: int, timeout: float) -> Transport:
    return ParamikoTransport(address, port, timeout)


# ---------------------------------------------------------------- operations
def scan_host_key(host: str, port: int = 22, factory: Optional[TransportFactory] = None) -> str:
    """Return the device's host-key fingerprint WITHOUT authenticating (for the operator to confirm once)."""
    addr = check_target(host, port)
    t = (factory or _default_factory)(addr, port, cfg.COLLECT_TIMEOUT_S)
    try:
        return fingerprint(t.host_key())
    finally:
        t.close()


def collect(*, host: str, port: int, profile: str, username: str, secret: str, auth_type: str,
            pinned_fingerprint: str, factory: Optional[TransportFactory] = None) -> str:
    """Connect, verify the pinned host key, authenticate, run the profile's read-only commands, return the text.

    The first command's output is the configuration; the others are appended as a comment block (``! ---``) so the
    parser still sees one file but a human can find the version banner.
    """
    if profile not in PROFILES:
        raise CollectError(f"unknown device profile {profile!r}")
    if not pinned_fingerprint:
        raise CollectError("no host key is pinned for this device; scan and confirm it first")
    p = PROFILES[profile]
    for c in p.commands:
        assert_read_only(profile, c)
    addr = check_target(host, port)
    t = (factory or _default_factory)(addr, port, cfg.COLLECT_TIMEOUT_S)
    try:
        if not same_fingerprint(fingerprint(t.host_key()), pinned_fingerprint):
            raise CollectError("host key does not match the pinned fingerprint (device replaced, or an impostor)")
        t.login(username, secret, auth_type)               # only reached once the key matched
        outputs = [t.run(c, cfg.COLLECT_MAX_BYTES, cfg.COLLECT_TIMEOUT_S) for c in p.commands]
    finally:
        t.close()
    if not outputs[0].strip():
        raise CollectError("the device returned an empty configuration")
    text = outputs[0]
    for c, o in zip(p.commands[1:], outputs[1:]):
        text += f"\n! --- {c} ---\n" + "\n".join("! " + ln for ln in o.splitlines()) + "\n"
    return text
