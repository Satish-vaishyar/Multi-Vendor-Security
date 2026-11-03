"""Structured parser for Palo Alto Networks PAN-OS (firewalls and Panorama exports).

Accepts the three formats operators actually have:
  * CLI `set` format             set deviceconfig system service disable-telnet yes
  * CLI hierarchical format      deviceconfig { system { service { disable-telnet yes; } } }
  * XML configuration snapshot   <config><devices><entry name="localhost.localdomain">...
All are normalised to the same path tuples (XML `entry`/`member` wrappers are dropped), and
rules then match path *fragments* anywhere, so vsys / template nesting does not matter.
"""
from __future__ import annotations
import re
from typing import Iterable, List, Optional, Sequence, Tuple
from xml.parsers import expat

from .base import IOS_ONLY, ROUTING_AUTH, SWITCH_ONLY, Facts, ParseResult, run_extractors
from .junos import to_paths

Path = Tuple[Tuple[str, ...], int]

KNOWN_TOP = {"deviceconfig", "mgt-config", "shared", "vsys", "network", "devices", "config", "template",
             "device-group", "readonly", "panorama", "log-collector", "template-stack", "plugins"}
ANCHORS = {"deviceconfig", "mgt-config", "shared", "vsys", "network", "panorama"}
DEFAULT_USERS = {"admin"}
WEAK_CRYPTO = re.compile(r"\b(md5|sha1|des|3des|null|group1|group2|group5|tls1-0|tls1-1)\b", re.I)
WEAK_SSH = re.compile(r"cbc|3des|arcfour|hmac-sha1|hmac-md5|md5", re.I)


def _from_xml(text: str, facts: Facts) -> List[Path]:
    """Namespace-free XML -> path tuples with line numbers (expat gives exact lines)."""
    paths: List[Path] = []
    stack: List[str] = []
    buf: List[str] = []
    parser = expat.ParserCreate()
    parser.buffer_text = True

    def start(tag: str, attrs: dict) -> None:
        stack.append(tag)
        if "name" in attrs:
            stack.append("\x00" + attrs["name"])        # entry name marker
        buf.clear()
        facts.consume(parser.CurrentLineNumber)

    def chars(data: str) -> None:
        buf.append(data)

    def end(tag: str) -> None:
        value = "".join(buf).strip()
        buf.clear()
        names = [t for t in stack]
        tokens = []
        for t in names:
            if t.startswith("\x00"):
                tokens.append(t[1:])
            elif t not in ("entry", "member"):
                tokens.append(t)
        if value:
            tokens.append(value)
        if tokens:
            paths.append((tuple(tokens), parser.CurrentLineNumber))
        if stack and stack[-1].startswith("\x00"):
            stack.pop()
        if stack:
            stack.pop()

    parser.StartElementHandler, parser.CharacterDataHandler, parser.EndElementHandler = start, chars, end
    try:
        parser.Parse(text, True)
    except expat.ExpatError as e:
        facts.res.notes.append(f"XML parse stopped at line {e.lineno}: {expat.ErrorString(e.code)}")
    return paths


def _normalise(paths: Iterable[Path]) -> List[Path]:
    """Cut each path to start at its first PAN-OS anchor (deviceconfig/shared/network/vsys/...)."""
    out: List[Path] = []
    for toks, n in paths:
        toks = tuple(t for t in toks if t not in ("member",)) if any(t == "member" for t in toks) else toks
        for i, t in enumerate(toks):
            if t in ANCHORS:
                toks = toks[i:]
                break
        out.append((toks, n))
    return out


class PanOS:
    def __init__(self, text: str, platform: str):
        self.lines = text.splitlines()
        self.f = Facts("paloalto", platform or "panos", self.lines)
        if text.lstrip().startswith("<"):
            raw = _from_xml(text, self.f)
        else:
            raw = to_paths(text, self.f, KNOWN_TOP)
        self.paths = _normalise(raw)

    # ------------------------------------------------------------------ query
    @staticmethod
    def _contains(tokens: Sequence[str], frag: Sequence[str]) -> Optional[int]:
        n = len(frag)
        for i in range(len(tokens) - n + 1):
            if all(p == "*" or p == t for p, t in zip(frag, tokens[i:i + n])):
                return i
        return None

    def find(self, *frag: str) -> List[Path]:
        return [(t, n) for t, n in self.paths if self._contains(t, frag) is not None]

    def first(self, *frag: str) -> Optional[Path]:
        r = self.find(*frag)
        return r[0] if r else None

    def after(self, *frag: str) -> List[Tuple[str, int]]:
        """Token immediately following `frag` in every matching path."""
        out = []
        for t, n in self.paths:
            i = self._contains(t, frag)
            if i is not None and i + len(frag) < len(t):
                out.append((t[i + len(frag)], n))
        return out

    @staticmethod
    def _ln(p: Optional[Path]) -> Optional[int]:
        return p[1] if p else None

    # ------------------------------------------------------------------- main
    def parse(self) -> ParseResult:
        return run_extractors(self.f, (
            self._services, self._admin, self._logging_ntp, self._snmp, self._rules, self._crypto, self._misc,
            self._declare_na))

    def _declare_na(self) -> None:
        f = self.f
        f.na(IOS_ONLY + SWITCH_ONLY + ("IP.REDIRECTS_DISABLED", "PROXY_ARP.DISABLED"),
             "not a PAN-OS concept (IOS/switch-specific setting)")
        if not (self.first("protocol", "bgp") or self.first("protocol", "ospf")):
            f.na(ROUTING_AUTH, "no dynamic routing protocol configured")

    # ---------------------------------------------------------------- services
    def _services(self) -> None:
        f = self.f
        for prop, key in (("TELNET.ENABLED", "disable-telnet"), ("HTTP.ENABLED", "disable-http"),
                          ("HTTPS.ENABLED", "disable-https"), ("SSH.ENABLED", "disable-ssh")):
            vals = self.after("deviceconfig", "system", "service", key)
            if vals:
                f.put(prop, vals[0][0].lower() != "yes", vals[0][1])
        # Dataplane exposure: interface -> management profile -> allowed admin services, interface -> zone
        profile_services = self._profile_services()
        iface_profile = self._interface_profiles()
        for prop, key in (("TELNET.ENABLED", "telnet"), ("HTTP.ENABLED", "http")):
            profs = [(prof, svcs[key]) for prof, svcs in profile_services.items()
                     if prof in iface_profile.values() and key in svcs]
            if profs:
                f.put(prop, True, profs[0][1], override=True, targets=[{"name": p} for p, _ in profs])
        if not f.has("TELNET.ENABLED"):
            f.default("TELNET.ENABLED", False, "PAN-OS management telnet is disabled by default")
        if not f.has("HTTP.ENABLED"):
            f.default("HTTP.ENABLED", False, "PAN-OS management http is disabled by default")
        if not f.has("HTTPS.ENABLED"):
            f.default("HTTPS.ENABLED", True, "PAN-OS management https is enabled by default")
        if not f.has("SSH.ENABLED"):
            f.default("SSH.ENABLED", True, "PAN-OS management ssh is enabled by default")
        f.default("SSH.VERSION", 2, "PAN-OS SSH server speaks SSHv2 only")
        ciph = [(t, n) for t, n in self.paths if self._contains(t, ("ssh", "ciphers")) is not None]
        macs = [(t, n) for t, n in self.paths if self._contains(t, ("ssh", "mac")) is not None]
        if ciph:
            f.put("SSH.WEAK_CIPHERS", any(WEAK_SSH.search(t[-1]) for t, _ in ciph), ciph[0][1])
        if macs:
            f.put("SSH.MACS_STRONG", not any(WEAK_SSH.search(t[-1]) for t, _ in macs), macs[0][1])
        t, h = f.get("TELNET.ENABLED"), f.get("HTTP.ENABLED")
        f.put("MGMT.ENCRYPTED_ONLY", not (t or h), f.res.provenance.get("TELNET.ENABLED", {}).get("line_no"))
        self._internet_exposure(profile_services, iface_profile)

        f.default("FTP.ENABLED", False, "PAN-OS has no FTP server")
        f.default("TFTP.ENABLED", False, "PAN-OS has no TFTP server")
        lldp = self.first("network", "lldp", "enable", "yes")
        if lldp:
            f.put("CDP.DISABLED_EDGE", False, lldp[1])
        else:
            f.default("CDP.DISABLED_EDGE", True, "LLDP is disabled unless 'network lldp enable yes'")
        pa = self.first("deviceconfig", "system", "permitted-ip")
        f.put("ACL.MGMT_RESTRICTED", True, pa[1]) if pa else f.default(
            "ACL.MGMT_RESTRICTED", False, "no 'deviceconfig system permitted-ip' restriction")
        f.put("VTY.ACL_APPLIED", True, pa[1]) if pa else f.default(
            "VTY.ACL_APPLIED", False, "no 'deviceconfig system permitted-ip' restriction")
        it = self.after("deviceconfig", "setting", "management", "idle-timeout")
        if it and it[0][0].isdigit():
            ok = int(it[0][0]) > 0
            f.put("MGMT.SESSION_TIMEOUT", ok, it[0][1])
            f.put("VTY.TIMEOUT_SET", ok, it[0][1])
        else:
            f.default("MGMT.SESSION_TIMEOUT", True, "PAN-OS default management idle timeout is 60 minutes")
            f.default("VTY.TIMEOUT_SET", True, "PAN-OS default management idle timeout is 60 minutes")


    def _profile_services(self) -> dict:
        """{profile: {service: line}} for services switched on in interface-management-profiles."""
        out: dict = {}
        for t, n in self.paths:
            i = self._contains(t, ("interface-management-profile",))
            if i is None or "profiles" not in t or i + 3 >= len(t):
                continue
            prof, svc, val = t[i + 1], t[i + 2], t[i + 3]
            if svc in ("ssh", "https", "http", "telnet", "snmp") and val.lower() == "yes":
                out.setdefault(prof, {})[svc] = n
        return out

    def _interface_profiles(self) -> dict:
        """{interface: profile} for layer3 interfaces."""
        out: dict = {}
        for t, _ in self.paths:
            i = self._contains(t, ("layer3", "interface-management-profile"))
            if i is None or i + 2 >= len(t):
                continue
            ifname = next((x for x in reversed(t[:i]) if re.match(r"^(ethernet|ae|vlan|loopback|tunnel)", x)), None)
            if ifname:
                out[ifname] = t[i + 2]
        return out

    def _internet_exposure(self, profile_services: dict, iface_profile: dict) -> None:
        f = self.f
        untrust: set = set()
        for t, _ in self.paths:
            i = self._contains(t, ("zone",))
            if i is None or i + 1 >= len(t) or "layer3" not in t:
                continue
            if re.search(r"untrust|wan|outside|internet|external|isp", t[i + 1], re.I):
                untrust.add(t[-1])
        risky = [(ifn, prof) for ifn, prof in iface_profile.items()
                 if ifn in untrust and any(s in profile_services.get(prof, {}) for s in ("ssh", "https", "http", "telnet"))]
        if risky:
            ifn, prof = risky[0]
            line = min(profile_services[prof].values())
            f.put("MGMT.INTERNET_EXPOSED", True, line,
                  note=f"management profile '{prof}' exposes admin services on untrust interface {ifn}",
                  targets=[{"name": p} for p in sorted({p for i, p in risky})])
        elif untrust or iface_profile:
            f.default("MGMT.INTERNET_EXPOSED", False, "no admin-service management profile on an untrust interface")

    # ------------------------------------------------------------------- admin
    def _admin(self) -> None:
        f = self.f
        users = sorted({t for t, _ in self.after("mgt-config", "users")})
        if users:
            bad = [u for u in users if u.lower() in DEFAULT_USERS]
            n = self._ln(self.first("mgt-config", "users", (bad or users)[0]))
            f.put("USER.DEFAULT_ACCOUNTS", bool(bad), n,
                  note="default 'admin' account name still in use" if bad else "",
                  targets=[{"name": u} for u in bad])
            ph = self.first("mgt-config", "users", "*", "phash") or self.first("mgt-config", "users", "*", "password")
            if ph:
                f.put("PASSWORD.ENCRYPTED", True, ph[1])
        lock = self.after("deviceconfig", "setting", "management", "admin-lockout", "failed-attempts")
        if lock and lock[0][0].isdigit():
            f.put("AAA.LOCKOUT_ENABLED", int(lock[0][0]) > 0, lock[0][1])
            f.put("SSH.RETRIES_LIMITED", 0 < int(lock[0][0]) <= 5, lock[0][1])
        else:
            f.default("AAA.LOCKOUT_ENABLED", False, "no 'admin-lockout' configured")
        ml = self.after("mgt-config", "password-complexity", "minimum-length")
        enabled = self.first("mgt-config", "password-complexity", "enabled", "yes")
        if enabled and ml and ml[0][0].isdigit():
            f.put("PASSWORD.MIN_LENGTH", int(ml[0][0]), ml[0][1])
            f.put("PASSWORD.POLICY_STRONG", int(ml[0][0]) >= 8, ml[0][1])
        else:
            f.default("PASSWORD.POLICY_STRONG", False, "'password-complexity' not enabled")
        tac = [(t, n) for t, n in self.paths if self._contains(t, ("server-profile", "tacplus")) is not None]
        rad = [(t, n) for t, n in self.paths if self._contains(t, ("server-profile", "radius")) is not None]
        f.put("AAA.TACACS_CONFIGURED", True, tac[0][1]) if tac else f.default(
            "AAA.TACACS_CONFIGURED", False, "no TACACS+ server profile")
        f.put("AAA.RADIUS_CONFIGURED", True, rad[0][1]) if rad else f.default(
            "AAA.RADIUS_CONFIGURED", False, "no RADIUS server profile")
        servers = {(t[i + 1:i + 3]) for t, _ in tac + rad for i in [self._contains(t, ("server",))] if i is not None and i + 1 < len(t)}
        if servers:
            f.put("AAA.SERVER_REDUNDANT", len(servers) >= 2, (tac or rad)[0][1])
        prof = self.first("authentication-profile") or self.first("deviceconfig", "system", "authentication-profile")
        if prof and (tac or rad or self.first("server-profile", "ldap")):
            f.put("AAA.AUTHENTICATION", True, prof[1])
        else:
            f.default("AAA.AUTHENTICATION", False, "administrators authenticate locally (no external authentication profile)")
        if users:
            f.default("AAA.AUTHORIZATION", True, "role-based admin permissions (mgt-config users ... permissions)")

    # ------------------------------------------------------------ logging / ntp
    def _logging_ntp(self) -> None:
        f = self.f
        sysl = self.first("syslog", "*", "server") or self.first("log-settings", "syslog")
        f.put("LOGGING.REMOTE_SERVER", True, sysl[1]) if sysl else f.default(
            "LOGGING.REMOTE_SERVER", False, "no syslog server profile configured")
        f.default("LOGGING.ENABLED", True, "PAN-OS always logs locally (traffic/threat/system/config)")
        f.default("LOGGING.BUFFERED", True, "PAN-OS keeps logs on local disk")
        f.default("LOGGING.TIMESTAMPS", True, "PAN-OS log records always carry timestamps")
        ntp = self.first("ntp-servers", "primary-ntp-server", "ntp-server-address")
        if ntp:
            f.put("NTP.ENABLED", True, ntp[1])
            auth = self.first("ntp-servers", "*", "authentication-type", "*")
            real = auth and auth[0][-1] in ("symmetric-key", "autokey")
            f.put("NTP.AUTHENTICATED", bool(real), (auth or ntp)[1])
        else:
            f.default("NTP.ENABLED", False, "no NTP server configured")
        tz = self.first("deviceconfig", "system", "timezone")
        f.put("CLOCK.TIMEZONE_SET", True, tz[1]) if tz else f.default("CLOCK.TIMEZONE_SET", False, "no timezone")
        ban = self.first("deviceconfig", "system", "login-banner")
        for prop in ("BANNER.LOGIN_SET", "BANNER.MOTD_SET", "BANNER.EXEC_SET"):
            f.put(prop, True, ban[1]) if ban else f.default(prop, False, "no 'login-banner' configured")

    # -------------------------------------------------------------------- snmp
    def _snmp(self) -> None:
        f = self.f
        snmp = self.first("deviceconfig", "system", "snmp-setting")
        if not snmp:
            f.default("SNMP.ENABLED", False, "no 'snmp-setting' configured")
            return
        f.put("SNMP.ENABLED", True, snmp[1])
        comm = [(t[-1], n) for t, n in self.paths if self._contains(t, ("snmp-community-string",)) is not None]
        users = [(t, n) for t, n in self.paths if self._contains(t, ("v3", "users")) is not None]
        if comm:
            pub = next((c for c in comm if c[0].lower() in ("public", "private")), None)
            f.put("SNMP.COMMUNITY_PUBLIC", bool(pub), (pub or comm[0])[1])
            f.put("SNMP.VERSION", 2, comm[0][1])
        else:
            f.put("SNMP.COMMUNITY_PUBLIC", False, snmp[1])
        f.put("SNMP.READWRITE", False, snmp[1], note="PAN-OS SNMP is read-only")
        if users:
            priv = [x for x in users if "privpwd" in x[0]]
            f.put("SNMP.V3_PRIV", bool(priv), (priv or users)[0][1])
            if not comm:
                f.put("SNMP.VERSION", 3, users[0][1])
        elif comm:
            f.put("SNMP.V3_PRIV", False, comm[0][1])

    # ------------------------------------------------------------------- rules
    def _rules(self) -> None:
        f = self.f
        rules = {}
        for t, n in self.paths:
            i = self._contains(t, ("rulebase", "security", "rules"))
            if i is None or i + 3 >= len(t):          # need at least: rules <name> <attribute>
                continue
            name, rest = t[i + 3], t[i + 4:]
            if not rest:
                continue
            d = rules.setdefault(name, {"line": n})
            d.setdefault(rest[0], []).append(rest[1] if len(rest) > 1 else "")
        if rules:
            f.put("FIREWALL.POLICY_SET", True, next(iter(rules.values()))["line"])
            def is_any(d: dict, k: str) -> bool:
                return "any" in [x.lower() for x in d.get(k, [])]
            bad = [(nm, d) for nm, d in rules.items()
                   if any(x.lower() == "allow" for x in d.get("action", ["allow"])) and "disabled" not in d
                   and is_any(d, "from") and is_any(d, "to") and is_any(d, "source") and is_any(d, "destination")
                   and is_any(d, "application") and (is_any(d, "service") or "service" not in d)]
            f.put("ACL.PERMIT_ANY", bool(bad), (bad or list(rules.items()))[0][1]["line"],
                  note=f"rule '{bad[0][0]}' allows any source/destination/application" if bad else "",
                  targets=[{"name": nm} for nm, _ in bad])
        else:
            f.default("ACL.PERMIT_ANY", False, "no security rules found")
        zones = self.first("zone", "*", "network")
        if zones:
            f.put("ZONE.SECURED", True, zones[1])
        dos = self.first("zone-protection-profile") or self.first("rulebase", "dos")
        f.put("DOS.PROTECTION", True, dos[1]) if dos else f.default(
            "DOS.PROTECTION", False, "no zone-protection / DoS profile configured")
        nf = self.first("netflow-profile") or self.first("netflow", "*", "server")
        f.put("MONITORING.NETFLOW", True, nf[1]) if nf else f.default(
            "MONITORING.NETFLOW", False, "no NetFlow profile configured")

    # ------------------------------------------------------------------ crypto
    def _crypto(self) -> None:
        f = self.f
        weak = None
        for t, n in self.paths:
            if (self._contains(t, ("ike-crypto-profiles",)) is not None or self._contains(t, ("ipsec-crypto-profiles",)) is not None) \
                    and WEAK_CRYPTO.search(t[-1]):
                weak = (n, f"weak algorithm '{t[-1]}' in a crypto profile")
                break
            if self._contains(t, ("ssl-tls-service-profile",)) is not None and "min-version" in t and WEAK_CRYPTO.search(t[-1]):
                weak = (n, f"minimum TLS version {t[-1]}")
                break
            if self._contains(t, ("ssh", "ciphers")) is not None or self._contains(t, ("ssh", "mac")) is not None:
                if WEAK_SSH.search(t[-1]):
                    weak = (n, f"weak SSH algorithm '{t[-1]}'")
                    break
        if weak:
            f.put("CRYPTO.WEAK_ALGO", True, weak[0], note=weak[1])
        else:
            f.default("CRYPTO.WEAK_ALGO", False, "no weak algorithm found in the configuration (absence of evidence)")
        tun = self.first("network", "tunnel", "ipsec") or self.first("tunnel", "ipsec")
        f.put("CRYPTO.IPSEC_ENABLED", True, tun[1]) if tun else f.default(
            "CRYPTO.IPSEC_ENABLED", False, "no IPsec tunnel configured")
        gws = {t for t, _ in self.after("ike", "gateway")}
        if gws:
            ver = [t[-1] for t, _ in self.paths if self._contains(t, ("protocol", "version")) is not None and "ike" in t]
            f.put("CRYPTO.IKE_VERSION", 2 if ver and all(v == "ikev2" for v in ver) else 1,
                  self._ln(self.first("ike", "gateway")))
        if tun:
            pfs = [t[-1] for t, _ in self.paths if "dh-group" in t and "ipsec-crypto-profiles" in t]
            f.put("CRYPTO.PFS_ENABLED", bool(pfs) and all(v != "no-pfs" for v in pfs), tun[1])
        for t, n in self.paths:
            if self._contains(t, ("ssl-tls-service-profile",)) is not None and "min-version" in t:
                f.put("CRYPTO.TLS_MIN", t[-1], n)
                break

    # -------------------------------------------------------------------- misc
    def _misc(self) -> None:
        f = self.f
        arch = self.first("scheduled-config-export")
        f.put("AUDIT.CONFIG_ARCHIVED", True, arch[1]) if arch else f.default(
            "AUDIT.CONFIG_ARCHIVED", False, "no scheduled configuration export")
        clear = [(t, n) for t, n in self.paths if t and t[-2:-1] in (("password",), ("psk",), ("secret",), ("key",))
                 and t[-1] and not (t[-1].startswith("-A") or t[-1].startswith("$") or t[-1].startswith("ENC"))
                 and self._contains(t, ("mgt-config",)) is None]
        if clear:
            f.put("KEY.STORED_SECURE", False, clear[0][1], note="cleartext key/secret in configuration")
        else:
            f.default("KEY.STORED_SECURE", True, "no cleartext key/secret statements found")


def parse(text: str, platform: str = "") -> ParseResult:
    return PanOS(text, platform).parse()
