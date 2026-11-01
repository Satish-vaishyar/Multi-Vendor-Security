"""Structured parser for Fortinet FortiOS (FortiGate) `show full-configuration` / backup files.

Grammar:  config <section words> / edit <name> / set <key> <values...> / unset <key> / next / end
Nested `config` blocks inside an `edit` (e.g. SNMP community hosts) are stored as
``<parent section>/<child section>`` entries named ``<parent edit>/<child edit>``.
"""
from __future__ import annotations
import re
import shlex
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .base import IOS_ONLY, ROUTING_AUTH, SWITCH_ONLY, Facts, ParseResult, run_extractors

DEFAULT_ADMINS = {"admin"}
WEAK_PROPOSAL = re.compile(r"(?:^|-|_)(des|3des|md5|sha1|null)(?:$|-|_)|sha1$", re.I)
TLS_OLD = re.compile(r"sslv3|tlsv1-0|tlsv1-1|tlsv1\.0|tlsv1\.1|^tlsv1$", re.I)


@dataclass
class Entry:
    section: str
    name: Optional[str]
    line_no: int
    settings: Dict[str, List[str]] = field(default_factory=dict)
    lines: Dict[str, int] = field(default_factory=dict)

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        v = self.settings.get(key)
        return v[0] if v else default

    def has(self, key: str) -> bool:
        return key in self.settings


# shlex is a pure-Python character-at-a-time tokenizer that grows its token with `+=`: QUADRATIC on one huge token
# (a single 3 MB "aaaa..." line took > 100 s). Real CLI lines are far shorter, so longer ones use plain whitespace
# splitting (docs/SECURITY_REVIEW.md PT-09).
_MAX_SHLEX_CHARS = 4096


def _split(s: str) -> List[str]:
    if len(s) > _MAX_SHLEX_CHARS:
        return s.split()
    try:
        return shlex.split(s, posix=True)
    except ValueError:
        return s.split()


class FortiOS:
    def __init__(self, text: str, platform: str):
        self.lines = text.splitlines()
        self.f = Facts("fortinet", platform or "fortios", self.lines)
        self.sections: Dict[str, List[Entry]] = {}
        self._parse_structure()

    # --------------------------------------------------------------- structure
    def _parse_structure(self) -> None:
        stack: List[Tuple[str, Optional[Entry]]] = []     # (section_key, current edit entry)
        for i, raw in enumerate(self.lines, 1):
            s = raw.strip()
            if not s or s.startswith("#"):
                self.f.consume(i)
                continue
            t = _split(s)
            if t[0] == "config":
                parent = stack[-1] if stack else None
                key = " ".join(t[1:])
                if parent and parent[1] is not None:
                    key = f"{parent[0]}/{key}"
                stack.append((key, None))
                self.sections.setdefault(key, [])
                if not parent or parent[1] is None:        # singleton sections have no `edit`
                    entry = Entry(key, None, i)
                    self.sections[key].append(entry)
                    stack[-1] = (key, entry)
                self.f.consume(i)
            elif t[0] == "edit" and stack:
                key = stack[-1][0]
                # drop the placeholder singleton created at `config`
                if self.sections[key] and self.sections[key][-1].name is None and not self.sections[key][-1].settings:
                    self.sections[key].pop()
                name = t[1] if len(t) > 1 else ""
                parent_edit = None
                if "/" in key and len(stack) > 1 and stack[-2][1] is not None:
                    parent_edit = stack[-2][1].name
                entry = Entry(key, f"{parent_edit}/{name}" if parent_edit else name, i)
                self.sections[key].append(entry)
                stack[-1] = (key, entry)
                self.f.consume(i)
            elif t[0] == "set" and stack and stack[-1][1] is not None:
                entry = stack[-1][1]
                entry.settings[t[1]] = t[2:]
                entry.lines[t[1]] = i
                self.f.consume(i)
            elif t[0] == "unset" and stack and stack[-1][1] is not None:
                stack[-1][1].settings.pop(t[1], None)
                self.f.consume(i)
            elif t[0] == "next":
                if stack:
                    stack[-1] = (stack[-1][0], None)
                self.f.consume(i)
            elif t[0] == "end":
                if stack:
                    stack.pop()
                self.f.consume(i)

    # ------------------------------------------------------------------ query
    def entries(self, section: str) -> List[Entry]:
        return [e for e in self.sections.get(section, []) if e.settings or e.name is not None]

    def single(self, section: str) -> Optional[Entry]:
        es = self.sections.get(section) or []
        return es[0] if es else None

    def exists(self, section: str) -> bool:
        return bool(self.entries(section))

    # ------------------------------------------------------------------- main
    def parse(self) -> ParseResult:
        return run_extractors(self.f, (
            self._admin_access, self._global_hardening, self._accounts, self._logging_ntp,
            self._snmp, self._firewall, self._crypto, self._misc, self._declare_na))

    def _declare_na(self) -> None:
        f = self.f
        f.na(IOS_ONLY + SWITCH_ONLY + ("IP.REDIRECTS_DISABLED", "PROXY_ARP.DISABLED"),
             "not a FortiOS concept (IOS/switch-specific setting)")
        if not (self.exists("router ospf") or self.exists("router bgp")):
            f.na(ROUTING_AUTH, "no dynamic routing protocol configured")

    # ------------------------------------------------------------ admin access
    def _admin_access(self) -> None:
        f = self.f
        up = [e for e in self.entries("system interface") if e.get("status", "up") != "down"]
        access = {e.name: set(e.settings.get("allowaccess", [])) for e in up}
        def first_with(tok: str) -> Optional[Entry]:
            return next((e for e in up if tok in access[e.name]), None)
        def access_targets(tok: str) -> List[Dict[str, str]]:
            """Interfaces that expose `tok`, with the allowaccess list before/after removing it."""
            out = []
            for e in up:
                if tok in access[e.name]:
                    left = [x for x in e.settings.get("allowaccess", []) if x != tok]
                    out.append({"name": e.name or "", "allowaccess": " ".join(left),
                                "allowaccess_before": " ".join(e.settings.get("allowaccess", []))})
            return out

        for prop, tok in (("TELNET.ENABLED", "telnet"), ("HTTP.ENABLED", "http"),
                          ("HTTPS.ENABLED", "https"), ("SSH.ENABLED", "ssh")):
            e = first_with(tok)
            if e:
                f.put(prop, True, e.lines.get("allowaccess", e.line_no),
                      targets=access_targets(tok) if prop in ("TELNET.ENABLED", "HTTP.ENABLED") else None)
            elif up and prop != "SSH.ENABLED":
                f.put(prop, False, up[0].lines.get("allowaccess", up[0].line_no))
        # legacy global switch
        g = self.single("system global")
        if g and g.get("admin-telnet") == "enable":
            f.put("TELNET.ENABLED", True, g.lines["admin-telnet"], override=True)
        if f.get("SSH.ENABLED"):
            f.default("SSH.VERSION", 2, "FortiOS accepts SSHv2 only")
        wan = [e for e in up if (e.get("role") == "wan" or re.match(r"^wan", e.name or "", re.I))
               and access[e.name] & {"https", "http", "ssh", "telnet"}]
        if up:
            if wan:
                f.put("MGMT.INTERNET_EXPOSED", True, wan[0].lines.get("allowaccess", wan[0].line_no),
                      note=f"admin access on WAN interface {wan[0].name}")
            else:
                f.default("MGMT.INTERNET_EXPOSED", False, "no admin access (https/ssh/telnet/http) on a WAN interface")
        t, h = f.get("TELNET.ENABLED"), f.get("HTTP.ENABLED")
        if t is not None and h is not None:
            f.put("MGMT.ENCRYPTED_ONLY", not (t or h), f.res.provenance.get("HTTP.ENABLED", {}).get("line_no"))
        # FTP/TFTP are not services on a FortiGate
        f.default("FTP.ENABLED", False, "FortiOS has no FTP server")
        f.default("TFTP.ENABLED", False, "FortiOS has no TFTP server")
        # LLDP
        lldp = next((e for e in up if e.get("lldp-reception") == "enable" or e.get("lldp-transmission") == "enable"), None)
        if lldp:
            f.put("CDP.DISABLED_EDGE", False, lldp.line_no)
        else:
            f.default("CDP.DISABLED_EDGE", True, "LLDP is disabled per interface unless enabled")

    # --------------------------------------------------------- global hardening
    def _global_hardening(self) -> None:
        f = self.f
        g = self.single("system global")
        def ln(k: str) -> Optional[int]:
            return g.lines.get(k) if g else None
        if not g:
            return
        at = g.get("admintimeout")
        if at and at.isdigit():
            f.put("MGMT.SESSION_TIMEOUT", int(at) > 0, ln("admintimeout"))
            f.put("VTY.TIMEOUT_SET", int(at) > 0, ln("admintimeout"))
        else:
            f.default("MGMT.SESSION_TIMEOUT", True, "FortiOS default admintimeout is 5 minutes")
            f.default("VTY.TIMEOUT_SET", True, "FortiOS default admintimeout is 5 minutes")
        thr = g.get("admin-lockout-threshold")
        if thr and thr.isdigit():
            f.put("AAA.LOCKOUT_ENABLED", int(thr) > 0, ln("admin-lockout-threshold"))
            f.put("SSH.RETRIES_LIMITED", 0 < int(thr) <= 5, ln("admin-lockout-threshold"))
        else:
            f.default("AAA.LOCKOUT_ENABLED", True, "FortiOS default lockout: 3 failed logins for 60 s")
            f.default("SSH.RETRIES_LIMITED", True, "FortiOS default lockout threshold is 3")
        if g.has("admin-ssh-grace-time"):
            f.put("SSH.TIMEOUT_SET", True, ln("admin-ssh-grace-time"))
        sc = g.get("strong-crypto") == "enable"
        if sc:
            f.put("SSH.WEAK_CIPHERS", False, ln("strong-crypto"), note="strong-crypto enable")
            f.put("SSH.MACS_STRONG", True, ln("strong-crypto"), note="strong-crypto enable")
        if g.get("ssh-cbc-cipher") == "enable":
            f.put("SSH.WEAK_CIPHERS", True, ln("ssh-cbc-cipher"), override=True)
        if g.get("ssh-hmac-md5") == "enable" or g.get("ssh-mac-weak") == "enable":
            f.put("SSH.MACS_STRONG", False, ln("ssh-hmac-md5") or ln("ssh-mac-weak"), override=True)
        if g.has("ssl-min-proto-version"):
            f.put("CRYPTO.TLS_MIN", g.get("ssl-min-proto-version"), ln("ssl-min-proto-version"))
        for key, prop in (("pre-login-banner", "BANNER.LOGIN_SET"), ("post-login-banner", "BANNER.MOTD_SET")):
            on = g.get(key) == "enable"
            f.put(prop, True, ln(key)) if on else f.default(prop, False, f"'{key}' not enabled")
        f.put("BANNER.EXEC_SET", f.get("BANNER.MOTD_SET", False), ln("post-login-banner")) if g.get("post-login-banner") == "enable" else \
            f.default("BANNER.EXEC_SET", False, "'post-login-banner' not enabled")
        if g.has("timezone"):
            f.put("CLOCK.TIMEZONE_SET", True, ln("timezone"))
        else:
            f.default("CLOCK.TIMEZONE_SET", False, "no 'timezone' set")
        if g.get("revision-backup-on-logout") == "enable" or g.get("revision-image-auto-backup") == "enable":
            f.put("AUDIT.CONFIG_ARCHIVED", True, ln("revision-backup-on-logout") or ln("revision-image-auto-backup"))
        else:
            f.default("AUDIT.CONFIG_ARCHIVED", False, "no revision backup / archive configured")

    @staticmethod
    def _has_trusthost(admin: Entry) -> bool:
        """An admin is source-restricted when any trusthostN is something other than 0.0.0.0/0.0.0.0."""
        for i in range(1, 11):
            v = admin.settings.get(f"trusthost{i}")
            if v and v[0] != "0.0.0.0":
                return True
        return any(admin.has(f"ip6-trusthost{i}") and admin.settings[f"ip6-trusthost{i}"][0] not in ("::/0", "::")
                   for i in range(1, 11))

    # ---------------------------------------------------------------- accounts
    def _accounts(self) -> None:
        f = self.f
        admins = self.entries("system admin")
        if admins:
            no_trust = [a for a in admins if not self._has_trusthost(a)]
            nt_targets = [{"name": a.name or ""} for a in no_trust]
            f.put("ACL.MGMT_RESTRICTED", not no_trust, (no_trust or admins)[0].line_no,
                  note=f"no trusted hosts for: {', '.join(a.name or '' for a in no_trust)}" if no_trust else "",
                  targets=nt_targets)
            f.put("VTY.ACL_APPLIED", not no_trust, (no_trust or admins)[0].line_no, targets=nt_targets)
            bad = [a for a in admins if (a.name or "").lower() in DEFAULT_ADMINS]
            f.put("USER.DEFAULT_ACCOUNTS", bool(bad), (bad or admins)[0].line_no,
                  note="default 'admin' account name still in use (CIS: rename or disable)" if bad else "",
                  targets=[{"name": a.name or ""} for a in bad])
            clear = [a for a in admins if a.has("password") and a.settings["password"] and a.settings["password"][0] != "ENC"]
            if clear:
                f.put("PASSWORD.ENCRYPTED", False, clear[0].lines["password"], note="admin password not stored as ENC")
            elif any(a.has("password") for a in admins):
                f.put("PASSWORD.ENCRYPTED", True, next(a.lines["password"] for a in admins if a.has("password")))
            remote = any(a.get("remote-auth") == "enable" for a in admins)
        else:
            remote = False
        tac, rad = self.entries("user tacacs+"), self.entries("user radius")
        ldap, saml = self.entries("user ldap"), self.entries("user saml")
        f.put("AAA.TACACS_CONFIGURED", True, tac[0].line_no) if tac else f.default(
            "AAA.TACACS_CONFIGURED", False, "no 'config user tacacs+' server")
        f.put("AAA.RADIUS_CONFIGURED", True, rad[0].line_no) if rad else f.default(
            "AAA.RADIUS_CONFIGURED", False, "no 'config user radius' server")
        servers = len(tac) + len(rad) + len(ldap)
        if servers:
            f.put("AAA.SERVER_REDUNDANT", servers >= 2, (tac or rad or ldap)[0].line_no)
        central = bool(tac or rad or ldap or saml)
        if central and (remote or self.exists("user group")):
            f.put("AAA.AUTHENTICATION", True, (tac or rad or ldap or saml)[0].line_no)
        else:
            f.default("AAA.AUTHENTICATION", False, "administrators authenticate locally (no remote auth server in use)")
        if self.exists("system accprofile") or admins:
            f.default("AAA.AUTHORIZATION", True, "admin access profiles (accprofile) provide role-based authorisation")
        pp = self.single("system password-policy")
        if pp and pp.get("status") == "enable":
            ml = pp.get("minimum-length") or "0"
            ok = ml.isdigit() and int(ml) >= 8
            f.put("PASSWORD.MIN_LENGTH", int(ml) if ml.isdigit() else 0, pp.lines.get("minimum-length", pp.line_no))
            f.put("PASSWORD.POLICY_STRONG", ok, pp.lines.get("minimum-length", pp.line_no))
        else:
            f.default("PASSWORD.POLICY_STRONG", False, "'system password-policy' not enabled")

    # ------------------------------------------------------------ logging / ntp
    def _logging_ntp(self) -> None:
        f = self.f
        remote = None
        for sec in ("log syslogd setting", "log syslogd2 setting", "log syslogd3 setting", "log syslogd4 setting",
                    "log fortianalyzer setting", "log fortianalyzer2 setting", "log fortianalyzer3 setting"):
            for e in self.entries(sec):
                if e.get("status") == "enable" and (e.get("server") or e.get("ips")):
                    remote = remote or e
        f.put("LOGGING.REMOTE_SERVER", True, remote.line_no) if remote else f.default(
            "LOGGING.REMOTE_SERVER", False, "no syslog/FortiAnalyzer destination enabled")
        local = next((e for sec in ("log memory setting", "log disk setting")
                      for e in self.entries(sec) if e.get("status") == "enable"), None)
        if local or remote:
            f.put("LOGGING.ENABLED", True, (local or remote).line_no)
        else:
            f.default("LOGGING.ENABLED", False, "no log destination enabled")
        f.put("LOGGING.BUFFERED", True, local.line_no) if local else f.default(
            "LOGGING.BUFFERED", False, "no local (memory/disk) logging enabled")
        f.default("LOGGING.TIMESTAMPS", True, "FortiOS log records always carry date and time")
        ntp = self.single("system ntp")
        if ntp and ntp.get("ntpsync") == "enable":
            f.put("NTP.ENABLED", True, ntp.lines.get("ntpsync", ntp.line_no))
            servers = self.entries("system ntp/ntpserver")
            auth = any(s.get("authentication") == "enable" for s in servers)
            f.put("NTP.AUTHENTICATED", auth, (servers or [ntp])[0].line_no)
            if ntp.has("source-ip") or ntp.has("interface"):
                f.put("NTP.SOURCE_SET", True, ntp.lines.get("source-ip") or ntp.lines.get("interface"))
        else:
            f.default("NTP.ENABLED", False, "'ntpsync' not enabled")

    # -------------------------------------------------------------------- snmp
    def _snmp(self) -> None:
        f = self.f
        comms = [e for e in self.entries("system snmp community") if e.get("status", "enable") == "enable"]
        users = [e for e in self.entries("system snmp user") if e.get("status", "enable") == "enable"]
        sysinfo = self.single("system snmp sysinfo")
        on = bool(comms or users) or (sysinfo is not None and sysinfo.get("status") == "enable")
        if not on:
            f.default("SNMP.ENABLED", False, "SNMP agent not enabled")
            return
        f.put("SNMP.ENABLED", True, (comms or users or [sysinfo])[0].line_no)
        if comms:
            pub = next((c for c in comms if (c.get("name") or "").lower() in ("public", "private")), None)
            open_c = [c for c in comms if not self.entries(f"system snmp community/hosts") or
                      not any((h.name or "").startswith(f"{c.name}/") for h in self.entries("system snmp community/hosts"))]
            f.put("SNMP.COMMUNITY_PUBLIC", bool(pub), (pub or comms[0]).lines.get("name", comms[0].line_no),
                  targets=[{"name": c.name or ""} for c in comms if (c.get("name") or "").lower() in ("public", "private")])
            f.put("SNMP.READWRITE", False, comms[0].line_no, note="FortiOS SNMPv1/v2c communities are read-only")
            f.put("SNMP.ACL_RESTRICTED", not open_c, (open_c or comms)[0].line_no,
                  targets=[{"name": c.name or ""} for c in open_c])
            f.put("SNMP.VERSION", 2, comms[0].line_no)
        else:
            f.put("SNMP.COMMUNITY_PUBLIC", False, users[0].line_no)
            f.put("SNMP.READWRITE", False, users[0].line_no)
        if users:
            priv = [u for u in users if u.get("security-level") == "auth-priv"]
            f.put("SNMP.V3_PRIV", bool(priv) and len(priv) == len(users), (priv or users)[0].line_no)
            if not comms:
                f.put("SNMP.VERSION", 3, users[0].line_no)
        elif comms:
            f.put("SNMP.V3_PRIV", False, comms[0].line_no)

    # ---------------------------------------------------------------- firewall
    def _firewall(self) -> None:
        f = self.f
        pols = [e for e in self.entries("firewall policy") if e.get("status", "enable") == "enable"]
        if pols:
            f.put("FIREWALL.POLICY_SET", True, pols[0].line_no)
            anyany = [p for p in pols if p.get("action") == "accept"
                      and "all" in [x.lower() for x in p.settings.get("srcaddr", [])]
                      and "all" in [x.lower() for x in p.settings.get("dstaddr", [])]
                      and any(x.upper() == "ALL" for x in p.settings.get("service", []))]
            f.put("ACL.PERMIT_ANY", bool(anyany), (anyany or pols)[0].line_no,
                  note=f"policy {anyany[0].name} allows all sources/destinations/services" if anyany else "",
                  targets=[{"name": p.name or ""} for p in anyany])
        else:
            f.default("ACL.PERMIT_ANY", False, "no firewall policies configured")
        if self.exists("system zone"):
            f.put("ZONE.SECURED", True, self.entries("system zone")[0].line_no)
        dos = self.entries("firewall DoS-policy") or self.entries("firewall DoS-policy6")
        f.put("DOS.PROTECTION", True, dos[0].line_no) if dos else f.default(
            "DOS.PROTECTION", False, "no 'firewall DoS-policy' configured")
        nf = self.entries("system netflow") or self.entries("system sflow")
        nf_ok = [e for e in nf if e.get("collector-ip") and e.get("collector-ip") != "0.0.0.0"]
        f.put("MONITORING.NETFLOW", True, nf_ok[0].line_no) if nf_ok else f.default(
            "MONITORING.NETFLOW", False, "no NetFlow/sFlow collector configured")

    # ------------------------------------------------------------------ crypto
    def _crypto(self) -> None:
        f = self.f
        p1 = self.entries("vpn ipsec phase1-interface") + self.entries("vpn ipsec phase1")
        p2 = self.entries("vpn ipsec phase2-interface") + self.entries("vpn ipsec phase2")
        weak: Optional[int] = None
        weak_note = ""
        for e in p1 + p2:
            for tok in e.settings.get("proposal", []):
                if WEAK_PROPOSAL.search(tok):
                    weak, weak_note = e.lines["proposal"], f"weak IPsec proposal {tok}"
                    break
            dh = [x for x in e.settings.get("dhgrp", []) if x in ("1", "2", "5")]
            if dh and weak is None:
                weak, weak_note = e.lines["dhgrp"], f"weak DH group {dh[0]}"
            if weak:
                break
        g = self.single("system global")
        if weak is None and g:
            if g.get("ssh-cbc-cipher") == "enable" or g.get("ssh-hmac-md5") == "enable":
                weak, weak_note = g.lines.get("ssh-cbc-cipher") or g.lines["ssh-hmac-md5"], "weak SSH cipher/MAC enabled"
            elif TLS_OLD.search(g.get("ssl-min-proto-version") or ""):
                weak, weak_note = g.lines["ssl-min-proto-version"], "TLS/SSL minimum version below TLS 1.2"
        if weak:
            f.put("CRYPTO.WEAK_ALGO", True, weak, note=weak_note)
        else:
            f.default("CRYPTO.WEAK_ALGO", False, "no weak algorithm found in the configuration (absence of evidence)")
        if p1:
            f.put("CRYPTO.IPSEC_ENABLED", True, p1[0].line_no)
            versions = {e.get("ike-version", "1") for e in p1}
            f.put("CRYPTO.IKE_VERSION", 2 if versions == {"2"} else 1, p1[0].lines.get("ike-version", p1[0].line_no))
            if p2:
                f.put("CRYPTO.PFS_ENABLED", all(e.get("pfs", "enable") == "enable" for e in p2), p2[0].line_no)
        else:
            f.default("CRYPTO.IPSEC_ENABLED", False, "no IPsec phase1 configured")

    # -------------------------------------------------------------------- misc
    def _misc(self) -> None:
        f = self.f
        clear: List[int] = []
        for entries in self.sections.values():
            for e in entries:
                for key in ("password", "psksecret", "secret", "key", "passwd"):
                    v = e.settings.get(key)
                    if v and v[0] != "ENC" and not v[0].startswith("ENC") and e.section not in ("system interface",):
                        clear.append(e.lines[key])
        if clear:
            f.put("KEY.STORED_SECURE", False, sorted(clear)[0], note="secret not stored as ENC")
        else:
            f.default("KEY.STORED_SECURE", True, "all stored secrets are encrypted (ENC)")


def parse(text: str, platform: str = "") -> ParseResult:
    return FortiOS(text, platform).parse()
