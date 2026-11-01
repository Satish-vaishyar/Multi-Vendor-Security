"""Structured parser for Juniper Junos (EX / QFX / MX / SRX) - hierarchical `{}` and `set` formats.

Both formats are normalised to *configuration paths* (``system services ssh protocol-version v2``)
so one rule set serves both. `inactive:` / `deactivate` nodes are treated as absent, which is
what the device actually does.
"""
from __future__ import annotations
import re
import shlex
from typing import Iterable, List, Optional, Sequence, Tuple

from .base import IOS_ONLY, ROUTING_AUTH, SWITCH_ONLY, Facts, ParseResult, community_ref, run_extractors

Path = Tuple[Tuple[str, ...], int]       # (tokens, 1-based line number)

KNOWN_TOP = {"version", "groups", "apply-groups", "system", "chassis", "services", "interfaces", "snmp",
             "forwarding-options", "routing-options", "policy-options", "protocols", "firewall", "security",
             "class-of-service", "vlans", "ethernet-switching-options", "switch-options", "routing-instances",
             "event-options", "applications", "access", "accounting-options", "poe", "virtual-chassis",
             "multi-chassis", "bridge-domains", "schedulers", "unified-access-control", "fabric", "logical-systems",
             "tenants", "wlan", "ethernet-switching"}
DEFAULT_USERS = {"admin", "juniper", "super", "test", "guest", "root", "user", "default"}
WEAK_SSH = re.compile(r"3des|cbc|arcfour|blowfish|hmac-md5|hmac-sha1(?!-)|hmac-sha1$|umac-64|sha1", re.I)


# shlex is a pure-Python character-at-a-time tokenizer that grows its token with `+=`: QUADRATIC on one huge token
# (a single 3 MB "aaaa..." line took > 100 s). Real CLI lines are far shorter, so longer ones use plain whitespace
# splitting (docs/SECURITY_REVIEW.md PT-09).
_MAX_SHLEX_CHARS = 4096


def _split(line: str) -> List[str]:
    if len(line) > _MAX_SHLEX_CHARS:
        return line.split()
    try:
        return shlex.split(line, posix=True)
    except ValueError:
        return line.split()


def to_paths(text: str, facts: Facts, known_top=None) -> List[Path]:
    """Normalise `set` or hierarchical `{}` text to config paths. `known_top` = the top-level
    keywords of the platform (used to decide which lines count as "understood")."""
    known = KNOWN_TOP if known_top is None else known_top
    lines = text.splitlines()
    if any(re.match(r"^\s*set\s+\S", l) for l in lines):
        return _from_set(lines, facts, known)
    return _from_braces(lines, facts, known)


def _from_set(lines: List[str], facts: Facts, known=KNOWN_TOP) -> List[Path]:
    paths: List[Path] = []
    deactivated: List[Tuple[str, ...]] = []
    for i, raw in enumerate(lines, 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            facts.consume(i)
            continue
        toks = _split(s)
        if toks[0] == "deactivate" and len(toks) > 1:
            deactivated.append(tuple(toks[1:]))
            facts.consume(i)
        elif toks[0] == "set" and len(toks) > 1:
            paths.append((tuple(toks[1:]), i))
            if toks[1] in known:
                facts.consume(i)
        elif toks[0] in ("delete", "activate"):
            facts.consume(i)
    if deactivated:
        paths = [(t, n) for t, n in paths if not any(t[:len(d)] == d for d in deactivated)]
    return paths


def _from_braces(lines: List[str], facts: Facts, known=KNOWN_TOP) -> List[Path]:
    paths: List[Path] = []
    stack: List[Tuple[str, ...]] = []
    inactive_depth: List[bool] = []
    in_block_comment = False
    for i, raw in enumerate(lines, 1):
        s = raw.strip()
        if in_block_comment:
            facts.consume(i)
            in_block_comment = "*/" not in s
            continue
        if s.startswith("/*") and "*/" not in s:
            in_block_comment = True
            facts.consume(i)
            continue
        if not s or s.startswith(("#", "/*", "##")):
            facts.consume(i)
            continue
        s = re.sub(r"(?<=[;{}\]])\s*##.*$", "", s)      # trailing `## SECRET-DATA` / `## Inactive` markers
        if s.startswith("}"):
            if stack:
                stack.pop()
                inactive_depth.pop()
            facts.consume(i)
            continue
        inactive = False
        if s.startswith("inactive:"):
            inactive, s = True, s[len("inactive:"):].strip()
        if s.endswith("{"):
            toks = tuple(_split(s[:-1].strip()))
            stack.append(toks)
            inactive_depth.append(inactive)
            if len(stack) == 1 and toks and toks[0] in known:
                facts.consume(i)
            elif len(stack) > 1 and stack[0] and stack[0][0] in known:
                facts.consume(i)
            full = tuple(t for lvl in stack for t in lvl)
            if full and not any(inactive_depth):
                paths.append((full, i))
            continue
        if s.endswith(";"):
            s = s[:-1].strip()
            toks = _split(s)
            if not stack and toks and toks[0] in known:
                facts.consume(i)                           # top-level leaf, e.g. `version 20.4R3;`
            if toks and not (inactive or any(inactive_depth)):
                base = tuple(t for lvl in stack for t in lvl)
                lst = re.match(r"^(.*?)\s*\[\s*(.*?)\s*\]$", s)
                if lst:                                   # `ciphers [ a b c ];`
                    head = tuple(_split(lst.group(1)))
                    for item in _split(lst.group(2)):
                        paths.append((base + head + (item,), i))
                else:
                    paths.append((base + tuple(toks), i))
            if stack and stack[0] and stack[0][0] in known:
                facts.consume(i)
    return paths


class Junos:
    def __init__(self, text: str, platform: str):
        self.lines = text.splitlines()
        self.f = Facts("juniper", platform or "junos", self.lines)
        self.paths = to_paths(text, self.f)
        self.srx = any(p[0][:1] == ("security",) and len(p[0]) > 1 for p in self.paths)

    # ------------------------------------------------------------------ query
    @staticmethod
    def _match(tokens: Sequence[str], prefix: Sequence[str]) -> bool:
        if len(tokens) < len(prefix):
            return False
        return all(p == "*" or p == t for p, t in zip(prefix, tokens))

    def find(self, *prefix: str) -> List[Path]:
        return [(t, n) for t, n in self.paths if self._match(t, prefix)]

    def first(self, *prefix: str) -> Optional[Path]:
        r = self.find(*prefix)
        return r[0] if r else None

    def has(self, *prefix: str) -> bool:
        return self.first(*prefix) is not None

    def values(self, *prefix: str) -> List[str]:
        """The token directly after `prefix` for every matching path."""
        return [t[len(prefix)] for t, _ in self.find(*prefix) if len(t) > len(prefix)]

    # ------------------------------------------------------------------- main
    def parse(self) -> ParseResult:
        return run_extractors(self.f, (
            self._ssh_services, self._snmp, self._aaa, self._logging_ntp, self._banners_console,
            self._mgmt_plane, self._interfaces, self._routing, self._switching, self._crypto, self._misc,
            self._declare_na))

    def _declare_na(self) -> None:
        f = self.f
        f.na(IOS_ONLY, "IOS-only setting; Junos has no equivalent command")
        if not (self.has("protocols", "ospf") or self.has("protocols", "ospf3") or self.has("protocols", "bgp")):
            f.na(ROUTING_AUTH, "no dynamic routing protocol configured")
        if not f.has("STP.BPDU_GUARD"):
            f.na(SWITCH_ONLY, "device has no ethernet-switching configuration (router/firewall role)")

    def _line(self, p: Optional[Path]) -> Optional[int]:
        return p[1] if p else None

    # --------------------------------------------------------- ssh / services
    def _ssh_services(self) -> None:
        f = self.f
        ssh = self.first("system", "services", "ssh")
        if ssh:
            f.put("SSH.ENABLED", True, ssh[1])
            vers = self.values("system", "services", "ssh", "protocol-version")
            if vers:
                f.put("SSH.VERSION", 1 if "v1" in vers else 2, self._line(self.first("system", "services", "ssh", "protocol-version")))
            else:
                f.default("SSH.VERSION", 2, "Junos accepts SSHv2 only unless 'protocol-version v1' is configured")
            ciphers = self.values("system", "services", "ssh", "ciphers")
            if ciphers:
                f.put("SSH.WEAK_CIPHERS", any(WEAK_SSH.search(c) for c in ciphers),
                      self._line(self.first("system", "services", "ssh", "ciphers")))
            macs = self.values("system", "services", "ssh", "macs")
            if macs:
                f.put("SSH.MACS_STRONG", not any(WEAK_SSH.search(m) for m in macs),
                      self._line(self.first("system", "services", "ssh", "macs")))
            ca = self.first("system", "services", "ssh", "client-alive-interval")
            if ca:
                f.put("SSH.TIMEOUT_SET", True, ca[1])
            else:
                f.default("SSH.TIMEOUT_SET", False, "no client-alive-interval configured")
        tries = self.first("system", "login", "retry-options", "tries-before-disconnect")
        if tries:
            f.put("SSH.RETRIES_LIMITED", int(tries[0][-1]) <= 3 if tries[0][-1].isdigit() else False, tries[1])
        elif ssh:
            f.default("SSH.RETRIES_LIMITED", False, "Junos default is 10 tries before disconnect")
        tel = self.first("system", "services", "telnet")
        if tel:
            f.put("TELNET.ENABLED", True, tel[1])
        else:
            f.default("TELNET.ENABLED", False, "Junos has no telnet service unless 'system services telnet' is configured")
        http = self.first("system", "services", "web-management", "http")
        https = self.first("system", "services", "web-management", "https")
        if http:
            f.put("HTTP.ENABLED", True, http[1])
        else:
            f.default("HTTP.ENABLED", False, "web-management http not configured")
        if https:
            f.put("HTTPS.ENABLED", True, https[1])
        else:
            f.default("HTTPS.ENABLED", False, "web-management https not configured")
        ftp = self.first("system", "services", "ftp")
        if ftp:
            f.put("FTP.ENABLED", True, ftp[1])
        else:
            f.default("FTP.ENABLED", False, "no 'system services ftp'")
        f.default("TFTP.ENABLED", False, "Junos does not run a TFTP server")

    # -------------------------------------------------------------------- snmp
    def _snmp(self) -> None:
        f = self.f
        comms = sorted({t[2] for t, _ in self.find("snmp", "community", "*") if len(t) > 2})
        v3 = self.first("snmp", "v3")
        if not (comms or v3 or self.has("snmp")):
            f.default("SNMP.ENABLED", False, "no snmp configuration")
            return
        anchor = self.first("snmp", "community") or v3 or self.first("snmp")
        f.put("SNMP.ENABLED", True, self._line(anchor))
        if comms:
            pub = next((c for c in comms if c.lower() in ("public", "private")), None)
            rw = [c for c in comms if self.has("snmp", "community", c, "authorization", "read-write")]
            open_c = [c for c in comms if not self.has("snmp", "community", c, "clients")]
            f.put("SNMP.COMMUNITY_PUBLIC", bool(pub), self._line(self.first("snmp", "community", pub or comms[0])),
                  targets=[{"name": community_ref(c, self._line(self.first("snmp", "community", c)))}
                           for c in comms if c.lower() in ("public", "private")])
            f.put("SNMP.READWRITE", bool(rw), self._line(self.first("snmp", "community", (rw or comms)[0])),
                  targets=[{"name": community_ref(c, self._line(self.first("snmp", "community", c)))} for c in rw])
            f.put("SNMP.ACL_RESTRICTED", not open_c, self._line(self.first("snmp", "community", (open_c or comms)[0])),
                  targets=[{"name": community_ref(c, self._line(self.first("snmp", "community", c)))} for c in open_c])
            f.put("SNMP.VERSION", 2, self._line(anchor))
        else:
            f.put("SNMP.COMMUNITY_PUBLIC", False, self._line(anchor))
            f.put("SNMP.READWRITE", False, self._line(anchor))
        if v3:
            priv = [t for t, _ in self.find("snmp", "v3", "usm", "*", "*", "*", "privacy-*")] if False else \
                [(t, n) for t, n in self.paths if t[:2] == ("snmp", "v3") and any(x.startswith("privacy-") and x != "privacy-none" for x in t)]
            none = [(t, n) for t, n in self.paths if t[:2] == ("snmp", "v3") and "privacy-none" in t]
            f.put("SNMP.V3_PRIV", bool(priv) and not none, (priv or none or [(None, v3[1])])[0][1])
            if not comms:
                f.put("SNMP.VERSION", 3, v3[1])
        elif comms:
            f.put("SNMP.V3_PRIV", False, self._line(anchor))

    # --------------------------------------------------------------------- aaa
    def _aaa(self) -> None:
        f = self.f
        order = self.values("system", "authentication-order")
        tac = self.find("system", "tacplus-server")
        rad = self.find("system", "radius-server")
        central = any(o in ("tacplus", "radius") for o in order) or bool(tac or rad)
        anchor = self.first("system", "authentication-order") or (tac or rad or [None])[0]
        if central:
            f.put("AAA.AUTHENTICATION", True, self._line(anchor))
        else:
            f.default("AAA.AUTHENTICATION", False, "local password authentication only (no tacplus/radius)")
        f.put("AAA.TACACS_CONFIGURED", True, tac[0][1]) if tac else f.default(
            "AAA.TACACS_CONFIGURED", False, "no 'system tacplus-server'")
        f.put("AAA.RADIUS_CONFIGURED", True, rad[0][1]) if rad else f.default(
            "AAA.RADIUS_CONFIGURED", False, "no 'system radius-server'")
        servers = {t[2] for t, _ in tac + rad if len(t) > 2}
        if servers:
            f.put("AAA.SERVER_REDUNDANT", len(servers) >= 2, (tac or rad)[0][1])
        acct = self.first("system", "accounting")
        f.put("AAA.ACCOUNTING", True, acct[1]) if acct else f.default(
            "AAA.ACCOUNTING", False, "no 'system accounting' configured")
        if self.has("system", "login", "class") or self.has("system", "login", "user"):
            f.put("AAA.AUTHORIZATION", True, self._line(self.first("system", "login", "class") or self.first("system", "login", "user")))
        lock = self.first("system", "login", "retry-options", "lockout-period")
        f.put("AAA.LOCKOUT_ENABLED", True, lock[1]) if lock else f.default(
            "AAA.LOCKOUT_ENABLED", False, "no 'retry-options lockout-period' configured")
        ml = self.first("system", "login", "password", "minimum-length")
        if ml and ml[0][-1].isdigit():
            n = int(ml[0][-1])
            f.put("PASSWORD.MIN_LENGTH", n, ml[1])
            f.put("PASSWORD.POLICY_STRONG", n >= 8, ml[1])
        else:
            f.default("PASSWORD.POLICY_STRONG", False, "no 'system login password minimum-length' policy")
        enc = self.first("system", "*", "encrypted-password") or self.first("system", "login", "user", "*", "authentication", "encrypted-password") \
            or self.first("system", "root-authentication", "encrypted-password")
        plain = [p for p in self.paths if "plain-text-password" in p[0] and "plain-text-password-value" not in p[0]]
        if plain:
            f.put("PASSWORD.ENCRYPTED", False, plain[0][1], note="plain-text-password configured")
        elif enc:
            f.put("PASSWORD.ENCRYPTED", True, enc[1])
        # accounts
        users = sorted({t[3] for t, _ in self.find("system", "login", "user", "*") if len(t) > 3})
        bad = []
        for u in users:
            if u.lower() not in DEFAULT_USERS:
                continue
            hashes = [t[-1] for t, _ in self.find("system", "login", "user", u, "authentication", "encrypted-password")]
            if not hashes or any(h.startswith("$1$") for h in hashes):
                bad.append(u)
        if users:
            f.put("USER.DEFAULT_ACCOUNTS", bool(bad), self._line(self.first("system", "login", "user", (bad or users)[0])),
                  note="well-known account name with no/weak credential" if bad else "",
                  targets=[{"name": u} for u in bad])
        else:
            f.default("USER.DEFAULT_ACCOUNTS", False, "no local user accounts besides root-authentication")

    # ---------------------------------------------------------- logging / ntp
    def _logging_ntp(self) -> None:
        f = self.f
        sy = self.first("system", "syslog")
        host = self.first("system", "syslog", "host")
        files = self.first("system", "syslog", "file")
        if sy:
            f.put("LOGGING.ENABLED", True, sy[1])
        else:
            f.default("LOGGING.ENABLED", False, "no 'system syslog' configuration")
        f.put("LOGGING.REMOTE_SERVER", True, host[1]) if host else f.default(
            "LOGGING.REMOTE_SERVER", False, "no 'system syslog host' configured")
        f.put("LOGGING.BUFFERED", True, files[1]) if files else f.default(
            "LOGGING.BUFFERED", False, "no 'system syslog file' configured")
        if sy:
            f.default("LOGGING.TIMESTAMPS", True, "Junos syslog messages always carry timestamps")
        ntp = self.first("system", "ntp", "server") or self.first("system", "ntp", "peer") or self.first("system", "ntp", "boot-server")
        if ntp:
            f.put("NTP.ENABLED", True, ntp[1])
            ak, tk = self.first("system", "ntp", "authentication-key"), self.first("system", "ntp", "trusted-key")
            f.put("NTP.AUTHENTICATED", bool(ak and tk), (ak or tk or ntp)[1])
            sa = self.first("system", "ntp", "source-address")
            f.put("NTP.SOURCE_SET", True, sa[1]) if sa else f.default("NTP.SOURCE_SET", False, "no ntp source-address")
        else:
            f.default("NTP.ENABLED", False, "no 'system ntp' server configured")
        tz = self.first("system", "time-zone")
        f.put("CLOCK.TIMEZONE_SET", True, tz[1]) if tz else f.default("CLOCK.TIMEZONE_SET", False, "no 'system time-zone'")
        arch = self.first("system", "archival", "configuration")
        f.put("AUDIT.CONFIG_ARCHIVED", True, arch[1]) if arch else f.default(
            "AUDIT.CONFIG_ARCHIVED", False, "no 'system archival configuration'")

    # ---------------------------------------------------------------- banners
    def _banners_console(self) -> None:
        f = self.f
        msg = self.first("system", "login", "message")
        ann = self.first("system", "login", "announcement")
        f.put("BANNER.LOGIN_SET", True, msg[1]) if msg else f.default("BANNER.LOGIN_SET", False, "no 'system login message'")
        f.put("BANNER.MOTD_SET", True, ann[1]) if ann else f.default("BANNER.MOTD_SET", False, "no 'system login announcement'")
        f.put("BANNER.EXEC_SET", True, ann[1]) if ann else f.default("BANNER.EXEC_SET", False, "no 'system login announcement'")
        insecure = self.first("system", "ports", "console", "insecure")
        if insecure:
            f.put("CONSOLE.SECURED", False, insecure[1])
        else:
            f.default("CONSOLE.SECURED", True, "Junos console requires login unless 'console insecure' is set")
        aux = self.first("system", "ports", "auxiliary", "disable")
        if aux:
            f.put("AUX.DISABLED", True, aux[1])

    # ------------------------------------------------------------- mgmt plane
    def _mgmt_plane(self) -> None:
        f = self.f
        lo = self.first("interfaces", "lo0", "unit", "*", "family", "inet", "filter", "input")
        lo6 = self.first("interfaces", "lo0", "unit", "*", "family", "inet", "filter", "input-list")
        applied = lo or lo6
        if applied:
            f.put("ACL.MGMT_RESTRICTED", True, applied[1])
            f.put("VTY.ACL_APPLIED", True, applied[1])
        else:
            f.default("ACL.MGMT_RESTRICTED", False, "no firewall filter applied to lo0 (control plane)")
            f.default("VTY.ACL_APPLIED", False, "no firewall filter applied to lo0 (control plane)")
        idle = [(t, n) for t, n in self.find("system", "login", "class", "*", "idle-timeout")]
        if idle and any(t[-1].isdigit() and int(t[-1]) > 0 for t, _ in idle):
            f.put("MGMT.SESSION_TIMEOUT", True, idle[0][1])
            f.put("VTY.TIMEOUT_SET", True, idle[0][1])
        else:
            f.default("MGMT.SESSION_TIMEOUT", False, "no login class idle-timeout (Junos default: none)")
            f.default("VTY.TIMEOUT_SET", False, "no login class idle-timeout (Junos default: none)")
        t, h = f.get("TELNET.ENABLED"), f.get("HTTP.ENABLED")
        f.put("MGMT.ENCRYPTED_ONLY", not (t or h), f.res.provenance.get("TELNET.ENABLED", {}).get("line_no"))

    # -------------------------------------------------------------- interfaces
    def _interfaces(self) -> None:
        f = self.f
        inet = [p for p in self.find("interfaces", "*", "unit", "*", "family", "inet") if not p[0][1].startswith("lo")]
        rpf = self.first("interfaces", "*", "unit", "*", "family", "inet", "rpf-check")
        if inet:
            f.put("URPF.ENABLED", True, rpf[1]) if rpf else f.default(
                "URPF.ENABLED", False, "no 'rpf-check' on any inet interface")
        nr = self.first("system", "no-redirects")
        f.put("IP.REDIRECTS_DISABLED", True, nr[1]) if nr else (
            f.default("IP.REDIRECTS_DISABLED", False, "Junos sends ICMP redirects unless 'system no-redirects'") if inet else None)
        pa = self.first("interfaces", "*", "unit", "*", "family", "inet", "proxy-arp") or self.first("interfaces", "*", "proxy-arp")
        if pa:
            f.put("PROXY_ARP.DISABLED", False, pa[1])
        elif inet:
            f.default("PROXY_ARP.DISABLED", True, "proxy-arp is off unless configured per interface")
        lldp = self.first("protocols", "lldp")
        if lldp and not self.has("protocols", "lldp", "disable"):
            f.put("CDP.DISABLED_EDGE", False, lldp[1])
        else:
            f.default("CDP.DISABLED_EDGE", True, "LLDP is off unless 'protocols lldp' is configured")
        self._permit_any()

    def _permit_any(self) -> None:
        f = self.f
        terms = {}
        for t, n in self.find("firewall", "*", "*", "filter", "*", "term", "*") + self.find("firewall", "filter", "*", "term", "*"):
            idx = t.index("term")
            key = t[:idx + 2]
            d = terms.setdefault(key, {"from": False, "accept": False, "line": n})
            rest = t[idx + 2:]
            if rest[:1] == ("from",):
                d["from"] = True
            if rest[:2] == ("then", "accept"):
                d["accept"] = True
        bad = [d for d in terms.values() if d["accept"] and not d["from"]]
        # SRX security policies: any/any/any permit
        for t, n in self.find("security", "policies", "from-zone", "*", "to-zone", "*", "policy", "*", "match", "source-address", "any"):
            base = t[:8]
            if self.has(*base, "match", "destination-address", "any") and self.has(*base, "match", "application", "any") \
                    and self.has(*base, "then", "permit"):
                bad.append({"line": n})
        if bad:
            f.put("ACL.PERMIT_ANY", True, bad[0]["line"])
        elif terms or self.has("security", "policies"):
            f.put("ACL.PERMIT_ANY", False, None)
        else:
            f.default("ACL.PERMIT_ANY", False, "no firewall filters or security policies defined")

    # ----------------------------------------------------------------- routing
    def _routing(self) -> None:
        f = self.f
        ospf = self.first("protocols", "ospf") or self.first("protocols", "ospf3")
        if ospf:
            auth = self.first("protocols", "ospf", "area", "*", "interface", "*", "authentication")
            f.put("ROUTING.OSPF_AUTH", bool(auth), (auth or ospf)[1])
        bgp = self.first("protocols", "bgp")
        bgp_ok = None
        if bgp:
            unprotected = []
            for gp in {t[3] for t, _ in self.find("protocols", "bgp", "group", "*") if len(t) > 3}:
                g_auth = self.has("protocols", "bgp", "group", gp, "authentication-key") or \
                    self.has("protocols", "bgp", "group", gp, "authentication-key-chain")
                for nb in {t[5] for t, _ in self.find("protocols", "bgp", "group", gp, "neighbor", "*") if len(t) > 5}:
                    n_auth = self.has("protocols", "bgp", "group", gp, "neighbor", nb, "authentication-key") or \
                        self.has("protocols", "bgp", "group", gp, "neighbor", nb, "authentication-key-chain")
                    if not (g_auth or n_auth):
                        unprotected.append(nb)
            bgp_ok = not unprotected
            groups = sorted({g for g in (t[3] for t, _ in self.find("protocols", "bgp", "group", "*") if len(t) > 3)
                             if any(nb in unprotected for nb in {x[5] for x, _ in self.find("protocols", "bgp", "group", g, "neighbor", "*") if len(x) > 5})})
            f.put("ROUTING.BGP_AUTH", bgp_ok, bgp[1], note=f"no authentication for: {', '.join(unprotected)}" if unprotected else "",
                  targets=[{"name": g} for g in groups])
        if ospf or bgp:
            f.put("ROUTING.AUTH_ENABLED", bool(f.get("ROUTING.OSPF_AUTH")) or bool(bgp_ok), (ospf or bgp)[1])

    # --------------------------------------------------------------- switching
    def _switching(self) -> None:
        f = self.f
        if not (self.has("ethernet-switching-options") or self.has("vlans") or self.has("switch-options")
                or any("ethernet-switching" in t for t, _ in self.paths)):
            return
        sa = self.first("ethernet-switching-options", "secure-access-port")
        dhcp = [p for p in self.paths if p[0][:2] == ("ethernet-switching-options", "secure-access-port") and
                any(x in p[0] for x in ("examine-dhcp", "dhcp-trusted"))]
        f.put("DHCP.SNOOPING", True, dhcp[0][1]) if dhcp else f.default(
            "DHCP.SNOOPING", False, "no DHCP snooping ('examine-dhcp') configured")
        mac = self.first("ethernet-switching-options", "secure-access-port", "interface", "*", "mac-limit")
        f.put("PORT_SECURITY.ENABLED", True, mac[1]) if mac else f.default(
            "PORT_SECURITY.ENABLED", False, "no port security ('mac-limit') configured")
        bpdu = self.first("protocols", "*", "bpdu-block-on-edge") or self.first("protocols", "layer2-control", "bpdu-block")
        f.put("STP.BPDU_GUARD", True, bpdu[1]) if bpdu else f.default(
            "STP.BPDU_GUARD", False, "no 'bpdu-block-on-edge' configured")

    # ------------------------------------------------------------------ crypto
    def _crypto(self) -> None:
        f = self.f
        weak: Optional[Path] = None
        for t, n in self.paths:
            if not t:
                continue
            tail = t[-1].lower()
            if "ike" in t or "ipsec" in t or "proposal" in t:
                if t[-2:-1] in (("encryption-algorithm",), ("authentication-algorithm",)) and re.search(
                        r"des-cbc|3des|md5|sha1|sha-1|hmac-sha1|null", tail):
                    weak = (t, n)
                    break
                if t[-2:-1] == ("dh-group",) and tail in ("group1", "group2", "group5"):
                    weak = (t, n)
                    break
            if t[-2:-1] in (("ciphers",), ("macs",)) and WEAK_SSH.search(tail) and "ssh" in t:
                weak = (t, n)
                break
            if t[-2:-1] == ("encrypted-password",) and tail.startswith("$1$"):
                weak = (t, n)
                break
        if weak:
            f.put("CRYPTO.WEAK_ALGO", True, weak[1], note="weak algorithm/hash in configuration")
        else:
            f.default("CRYPTO.WEAK_ALGO", False, "no weak algorithm found in the configuration (absence of evidence)")
        ipsec = self.first("security", "ipsec") or self.first("services", "ipsec-vpn")
        f.put("CRYPTO.IPSEC_ENABLED", True, ipsec[1]) if ipsec else f.default(
            "CRYPTO.IPSEC_ENABLED", False, "no IPsec configuration")
        gws = {t[3] for t, _ in self.find("security", "ike", "gateway", "*") if len(t) > 3}
        if gws:
            v2 = [g for g in gws if self.has("security", "ike", "gateway", g, "version", "v2-only")]
            f.put("CRYPTO.IKE_VERSION", 2 if len(v2) == len(gws) else 1, self._line(self.first("security", "ike", "gateway")))

    # -------------------------------------------------------------------- misc
    def _misc(self) -> None:
        f = self.f
        nf = (self.first("forwarding-options", "sampling") or self.first("forwarding-options", "monitoring")
              or self.first("services", "flow-monitoring") or self.first("protocols", "sflow"))
        f.put("MONITORING.NETFLOW", True, nf[1]) if nf else f.default(
            "MONITORING.NETFLOW", False, "no sampling/flow-monitoring/sflow configured")
        dos = (self.first("system", "ddos-protection") or self.first("firewall", "policer") or self.first("security", "screen")
               or self.first("firewall", "family", "*", "filter", "*", "term", "*", "then", "policer"))
        f.put("DOS.PROTECTION", True, dos[1]) if dos else f.default(
            "DOS.PROTECTION", False, "no ddos-protection/policer/screen configured")
        # secrets must be stored obfuscated/hashed ($9$ / $6$ ...), never plain
        clear = [(t, n) for t, n in self.paths if len(t) >= 2 and t[-2] in ("authentication-key", "secret", "pre-shared-key")
                 and not t[-1].startswith("$") and t[-1] not in ("ascii-text", "hexadecimal")]
        clear += [(t, n) for t, n in self.paths if len(t) >= 3 and t[-3] == "pre-shared-key" and t[-2] in ("ascii-text", "hexadecimal")
                  and not t[-1].startswith("$")]
        if clear:
            f.put("KEY.STORED_SECURE", False, clear[0][1], note="cleartext key/secret in configuration")
        else:
            f.default("KEY.STORED_SECURE", True, "no cleartext key/secret statements found")


def parse(text: str, platform: str = "") -> ParseResult:
    return Junos(text, platform).parse()
