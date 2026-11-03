"""Structured parser for IOS-style CLIs: Cisco IOS / IOS-XE / NX-OS and Arista EOS.

Unlike a line-regex registry this understands CONTEXT: which `transport input` belongs to
which `line vty`, whether *every* L3 interface has `no ip redirects`, banner bodies,
`no` negations, and the documented platform defaults when a command is absent.
Documented defaults are recorded with basis="default" (see base.py) so reports can show
"assumed" separately from "observed".
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .base import IOS_ONLY, ROUTING_AUTH, SWITCH_ONLY, Facts, ParseResult, community_ref, run_extractors

Child = Tuple[int, str]            # (line_no, stripped text)


@dataclass
class Block:
    header: str
    line_no: int
    children: List[Child] = field(default_factory=list)

    def has(self, rx: str) -> Optional[int]:
        pat = re.compile(rx, re.I)
        for n, t in self.children:
            if pat.search(t):
                return n
        return None

    def find(self, rx: str) -> Optional[Tuple[int, "re.Match[str]"]]:
        pat = re.compile(rx, re.I)
        for n, t in self.children:
            m = pat.search(t)
            if m:
                return n, m
        return None


def _blocks(lines: List[str], facts: Facts) -> List[Block]:
    """Group into top-level blocks. Comments/banner bodies/cert blobs are consumed, not parsed."""
    blocks: List[Block] = []
    cur: Optional[Block] = None
    i, n = 0, len(lines)
    in_cert = False
    while i < n:
        raw = lines[i]
        ln = i + 1
        s = raw.strip()
        i += 1
        if not s or s.startswith(("!", "#")):
            facts.consume(ln)
            continue
        if in_cert:                       # certificate chain hex + `quit`
            facts.consume(ln)
            if s == "quit":
                in_cert = False
            continue
        indented = raw[0] in " \t"
        eos_banner = re.match(r"^banner\s+(\S+)$", s, re.I) if not indented else None
        if eos_banner:                    # EOS: banner <type> / body / EOF
            blocks.append(Block(f"banner {eos_banner.group(1).lower()}", ln))
            cur = None
            facts.consume(ln)
            while i < n:
                facts.consume(i + 1)
                done = lines[i].strip() == "EOF"
                i += 1
                if done:
                    break
            continue
        m = re.match(r"^banner\s+(\S+)\s+(\S)(.*)$", s, re.I) if not indented else None
        if m:                             # banner <type> <delim> ... <delim>
            delim, rest = m.group(2), m.group(3)
            blocks.append(Block(f"banner {m.group(1).lower()}", ln))
            cur = None
            facts.consume(ln)
            if delim not in rest:
                while i < n:
                    facts.consume(i + 1)
                    if delim in lines[i]:
                        i += 1
                        break
                    i += 1
            continue
        if not indented:
            cur = Block(s, ln)
            blocks.append(cur)
            if re.match(r"^crypto (pki|ca) certificate chain", s, re.I):
                in_cert = True
        elif cur is not None:
            cur.children.append((ln, s))
        else:
            blocks.append(Block(s, ln))
    return blocks


def _tok(s: str) -> List[str]:
    return s.split()


def _line_name(b: "Block") -> str:
    """`line vty 0 4` -> `vty 0 4` (the argument of the `line` command)."""
    return re.sub(r"^line\s+", "", b.header, flags=re.I)


def _iface_name(b: "Block") -> str:
    return re.sub(r"^interface\s+", "", b.header, flags=re.I)


WEAK_SSH = re.compile(r"cbc|3des|arcfour|blowfish|des-|md5|sha1(?!\d)|hmac-sha1|umac-64|none", re.I)
DEFAULT_USERS = {"admin", "cisco", "guest", "test", "root", "user", "default", "manager"}


class IosLike:
    def __init__(self, text: str, vendor: str, platform: str):
        self.lines = text.splitlines()
        self.vendor = vendor
        self.platform = (platform or "").lower()
        self.f = Facts(vendor, self.platform or vendor, self.lines)
        self.blocks = _blocks(self.lines, self.f)
        self.tops = [b.header for b in self.blocks]
        self.eos = vendor == "arista" or "eos" in self.platform
        self.nxos = (vendor == "cisco" and (any(re.match(r"feature\s+\S+", h, re.I) for h in self.tops)
                                             or "nx" in self.platform))

    # ---------------------------------------------------------------- helpers
    def top(self, rx: str) -> List[Block]:
        pat = re.compile(rx, re.I)
        return [b for b in self.blocks if pat.search(b.header)]

    def first(self, rx: str) -> Optional[Block]:
        r = self.top(rx)
        return r[0] if r else None

    def negated(self, name_rx: str) -> Optional[Block]:
        return self.first(rf"^no\s+{name_rx}")

    # ------------------------------------------------------------------ main
    def parse(self) -> ParseResult:
        return run_extractors(self.f, (
            self._recognise_benign, self._ssh, self._remote_access, self._snmp, self._aaa,
            self._passwords, self._logging, self._ntp, self._banners, self._services,
            self._interfaces, self._routing, self._switching, self._crypto, self._misc,
            self._declare_na))

    def _declare_na(self) -> None:
        f = self.f
        if self.eos or self.nxos:
            f.na(IOS_ONLY, "IOS-only setting; this platform has no equivalent command")
        if not any(self.top(rf"^router\s+{p}") for p in ("ospf", "bgp", "eigrp", "rip", "isis")):
            f.na(ROUTING_AUTH, "no dynamic routing protocol configured")
        if not f.has("STP.BPDU_GUARD") and not f.has("DHCP.SNOOPING"):
            f.na(SWITCH_ONLY, "device has no switching configuration (router/L3 role)")

    # ------------------------------------------------- understood-but-neutral
    def _recognise_benign(self) -> None:
        """Mark lines we understand but that carry no security property, so they do not
        flood the 'unknown tokens' queue."""
        benign = re.compile(
            r"^(hostname|version|boot|platform|subscriber|multilink|vdc|limit-resource|dns|spanning-tree|ip forward-protocol|clock|ip domain[- ](name|list)|ip name-server|ip cef|ipv6 unicast|"
            r"spanning-tree (mode|extend|logging)|mls|license|memory|vtp|vlan\s+[\d,\- ]+$|vlan$|username\b|"
            r"service (timestamps|sequence|tcp|udp|call-home|routing|compress)|ip classless|ip subnet-zero|"
            r"errdisable|redundancy|no ip routing|ip routing|interface\b|ip route|ipv6 route|name\b|"
            r"transceiver|daemon|end$|ntp|ip vrf|vrf|ip dhcp|ip cef|cdp|lldp|ip ssh|no ip|no service|"
            r"no aaa|no logging|logging|snmp-server|aaa|line\b|banner|enable|key chain|router|access-list|"
            r"ip access-list|ipv6 access-list|archive|crypto|control-plane|class-map|policy-map|"
            r"ip http|feature|management|system|ip tcp|ip icmp|ip igmp|ip multicast|ip pim|mac address-table|"
            r"switchport|monitor|flow|sflow|tacacs|radius|scheduler|alias|event|track|ip sla|call-home|"
            r"service-policy|login|security passwords|ip verify|ip finger|ip bootp|ip source-route)\b", re.I)
        for b in self.blocks:
            if benign.match(b.header):
                self.f.consume(b.line_no, *(n for n, _ in b.children))

    # -------------------------------------------------------------------- SSH
    def _ssh(self) -> None:
        f = self.f
        mgmt_ssh = self.first(r"^management ssh$") if self.eos else None
        vty_ssh = any(
            (r := b.find(r"^transport input (.+)$")) and re.search(r"\b(ssh|all)\b", r[1].group(1), re.I)
            for b in self.top(r"^line vty"))
        cfg_ssh = bool(self.top(r"^ip ssh\b|^ssh\b|^crypto key generate rsa"))
        nx_ssh = self.nxos and not self.negated(r"feature ssh$")
        eos_ssh = bool(mgmt_ssh) and not mgmt_ssh.has(r"^shutdown$")
        ssh_used = bool(vty_ssh or cfg_ssh or nx_ssh or eos_ssh)
        for b in self.top(r"^ip ssh\b|^ssh\b|^feature ssh"):
            f.consume(b.line_no)
        anchor = (self.first(r"^ip ssh\b") or mgmt_ssh)
        if ssh_used:
            f.put("SSH.ENABLED", True, anchor.line_no if anchor else None)

        v = self.first(r"^ip ssh version\s+(\d)")
        if v:
            f.put("SSH.VERSION", int(v.header.split()[-1]), v.line_no)
        elif ssh_used:
            if self.eos or self.nxos:
                f.default("SSH.VERSION", 2, "EOS/NX-OS support SSH protocol 2 only")
            else:
                f.default("SSH.VERSION", 1.99, "IOS accepts SSHv1 and v2 unless 'ip ssh version 2' is set")

        t = self.first(r"^ip ssh time-out\s+(\d+)")
        idle = mgmt_ssh.find(r"^idle-timeout\s+(\d+)") if mgmt_ssh else None
        if t:
            f.put("SSH.TIMEOUT_SET", True, t.line_no)
        elif idle:
            f.put("SSH.TIMEOUT_SET", True, idle[0])
        elif ssh_used and not (self.eos or self.nxos):
            f.default("SSH.TIMEOUT_SET", False, "no explicit SSH time-out configured")
        r = self.first(r"^ip ssh authentication-retries\s+(\d+)")
        if r:
            f.put("SSH.RETRIES_LIMITED", int(r.header.split()[-1]) <= 3, r.line_no)
        elif ssh_used and not (self.eos or self.nxos):
            f.default("SSH.RETRIES_LIMITED", True, "IOS default is 3 authentication retries")

        ciph = self.first(r"^ip ssh server algorithm encryption\s+(.+)") or self.first(r"^ip ssh cipher")
        eos_c = mgmt_ssh.find(r"^cipher\s+(.+)") if mgmt_ssh else None
        if ciph:
            f.put("SSH.WEAK_CIPHERS", bool(WEAK_SSH.search(ciph.header)), ciph.line_no)
        elif eos_c:
            f.put("SSH.WEAK_CIPHERS", bool(WEAK_SSH.search(eos_c[1].group(1))), eos_c[0])
        mac = self.first(r"^ip ssh server algorithm mac\s+(.+)") or self.first(r"^ip ssh mac")
        eos_m = mgmt_ssh.find(r"^mac\s+(.+)") if mgmt_ssh else None
        if mac:
            f.put("SSH.MACS_STRONG", not WEAK_SSH.search(mac.header), mac.line_no)
        elif eos_m:
            f.put("SSH.MACS_STRONG", not WEAK_SSH.search(eos_m[1].group(1)), eos_m[0])

    def _remote_access(self) -> None:
        f = self.f
        vtys = self.top(r"^line vty")
        con = self.first(r"^line con")
        aux = self.first(r"^line aux")
        self._vty_security(vtys)
        self._telnet_http()
        # FTP / TFTP servers
        ftp = self.first(r"^(ftp-server enable|ip ftp server|feature ftp)")
        if ftp:
            f.put("FTP.ENABLED", True, ftp.line_no)
        else:
            f.default("FTP.ENABLED", False, "no FTP server statement present")
        tftp = self.first(r"^(tftp-server\b|feature tftp-server|tftp server)")
        if tftp:
            f.put("TFTP.ENABLED", True, tftp.line_no)
        else:
            f.default("TFTP.ENABLED", False, "no TFTP server statement present")
        # console / aux
        if con:
            has_login = bool(con.has(r"^(login|password)\b"))
            et = con.find(r"^exec-timeout\s+(\d+)(?:\s+(\d+))?")
            to_ok = int(et[1].group(1)) + int(et[1].group(2) or 0) > 0 if et else True
            f.put("CONSOLE.SECURED", has_login and to_ok, con.line_no)
        if aux:
            f.put("AUX.DISABLED", bool(aux.has(r"^no exec$") or aux.has(r"^transport input none$")), aux.line_no)
        for b in vtys + [x for x in (con, aux) if x]:
            f.consume(b.line_no, *(n for n, _ in b.children))

    def _vty_security(self, vtys: List[Block]) -> None:
        """ACL + idle timeout on vty lines (every vty block must comply)."""
        f = self.f
        if self.eos:
            ms = self.first(r"^management ssh$")
            if ms:
                acl = ms.find(r"^ip access-group\s+\S+")
                idle = ms.find(r"^idle-timeout\s+(\d+)")
                f.put("ACL.MGMT_RESTRICTED", bool(acl), acl[0] if acl else ms.line_no)
                f.put("VTY.ACL_APPLIED", bool(acl), acl[0] if acl else ms.line_no)
                if idle:
                    ok = int(idle[1].group(1)) > 0
                    f.put("MGMT.SESSION_TIMEOUT", ok, idle[0])
                    f.put("VTY.TIMEOUT_SET", ok, idle[0])
                else:
                    f.default("MGMT.SESSION_TIMEOUT", False, "no idle-timeout configured under 'management ssh'")
        if not vtys:
            return
        acl_all = timeout_all = True
        acl_ln = None
        no_acl, no_timeout = [], []
        for b in vtys:
            ac = b.has(r"^access-class\s+\S+\s+in\b")
            acl_all = acl_all and bool(ac)
            acl_ln = acl_ln or ac
            if not ac:
                no_acl.append({"name": _line_name(b)})
            et = b.find(r"^exec-timeout\s+(\d+)(?:\s+(\d+))?")
            if et:   # absent = platform default of 10 minutes, which is non-zero
                ok = int(et[1].group(1)) + int(et[1].group(2) or 0) > 0
                timeout_all = timeout_all and ok
                if not ok:
                    no_timeout.append({"name": _line_name(b)})
        f.put("VTY.ACL_APPLIED", acl_all, acl_ln or vtys[0].line_no, targets=no_acl)
        f.put("ACL.MGMT_RESTRICTED", acl_all, acl_ln or vtys[0].line_no, targets=no_acl)
        f.put("VTY.TIMEOUT_SET", timeout_all, vtys[0].line_no, targets=no_timeout)
        f.put("MGMT.SESSION_TIMEOUT", timeout_all, vtys[0].line_no, targets=no_timeout)

    def _telnet_http(self) -> None:
        f = self.f
        vtys = self.top(r"^line vty")
        if self.eos:
            mt = self.first(r"^management telnet$")
            if mt:
                f.put("TELNET.ENABLED", not mt.has(r"^shutdown$"), mt.line_no)
            else:
                f.default("TELNET.ENABLED", False, "EOS telnet server is shut down unless 'management telnet' is enabled")
            api = self.first(r"^management api http-commands$")
            if api:
                off = bool(api.has(r"^shutdown$"))
                http = api.has(r"^protocol http\b(?!s)") is not None
                f.put("HTTP.ENABLED", http and not off, api.line_no)
                f.put("HTTPS.ENABLED", api.has(r"^protocol https\b") is not None and not off, api.line_no)
            else:
                f.default("HTTP.ENABLED", False, "EOS eAPI is disabled unless configured")
                f.default("HTTPS.ENABLED", False, "EOS eAPI is disabled unless configured")
            return
        if self.nxos:
            ft = self.first(r"^feature telnet")
            if ft:
                f.put("TELNET.ENABLED", True, ft.line_no)
            else:
                f.default("TELNET.ENABLED", False, "NX-OS telnet feature is off unless 'feature telnet'")
            nx = self.first(r"^feature nxapi")
            if nx:
                h = self.first(r"^nxapi http port")
                f.put("HTTPS.ENABLED", True, nx.line_no)
                f.put("HTTP.ENABLED", bool(h), h.line_no if h else nx.line_no)
            else:
                f.default("HTTP.ENABLED", False, "NX-API disabled unless 'feature nxapi'")
                f.default("HTTPS.ENABLED", False, "NX-API disabled unless 'feature nxapi'")
            return
        # classic IOS / IOS-XE: telnet reachability is decided per vty block
        telnet_ln, explicit_ssh_only, implicit = None, [], False
        telnet_targets = []
        for b in vtys:
            tr = b.find(r"^transport input (.+)$")
            if not tr:
                implicit = True
                telnet_targets.append({"name": _line_name(b)})
            elif re.search(r"\b(telnet|all)\b", tr[1].group(1), re.I):
                telnet_ln = telnet_ln or tr[0]
                telnet_targets.append({"name": _line_name(b)})
            else:
                explicit_ssh_only.append(tr[0])
        if telnet_ln:
            f.put("TELNET.ENABLED", True, telnet_ln, targets=telnet_targets)
        elif implicit:
            f.default("TELNET.ENABLED", True, "line vty without 'transport input' accepts all protocols incl. telnet",
                      targets=telnet_targets)
        elif explicit_ssh_only:
            f.put("TELNET.ENABLED", False, explicit_ssh_only[0])
        h, nh = self.first(r"^ip http server$"), self.negated(r"ip http server$")
        if h:
            f.put("HTTP.ENABLED", True, h.line_no)
        elif nh:
            f.put("HTTP.ENABLED", False, nh.line_no)
        else:
            f.default("HTTP.ENABLED", False, "'ip http server' absent from running-config means disabled")
        hs, nhs = self.first(r"^ip http secure-server$"), self.negated(r"ip http secure-server$")
        if hs:
            f.put("HTTPS.ENABLED", True, hs.line_no)
        elif nhs:
            f.put("HTTPS.ENABLED", False, nhs.line_no)
        else:
            f.default("HTTPS.ENABLED", False, "'ip http secure-server' absent means disabled")
        tls = self.first(r"^ip http tls-version\s+(\S+)")
        if tls:
            f.put("CRYPTO.TLS_MIN", tls.header.split()[-1], tls.line_no)

    @staticmethod
    def _community_acl(tokens: List[str]) -> Optional[str]:
        """ACL name/number of `snmp-server community NAME [view V] [ro|rw] [ipv6 ACL] [ACL]`."""
        rest, i, acl = tokens[3:], 0, None
        while i < len(rest):
            tk = rest[i].lower()
            if tk in ("ro", "rw"):
                i += 1
            elif tk in ("view", "ipv6", "group"):
                i += 2
            elif tk in ("use-ipv4acl", "use-ipv6acl"):
                acl = rest[i + 1] if i + 1 < len(rest) else acl
                i += 2
            else:
                acl = rest[i]
                i += 1
        return acl

    def _snmp(self) -> None:
        f = self.f
        comms = self.top(r"^snmp-server community\s+\S+")
        users = self.top(r"^snmp-server user\s+")
        groups = self.top(r"^snmp-server group\s+")
        hosts = self.top(r"^snmp-server host\s+")
        enable = self.first(r"^snmp-server enable")
        if not (comms or users or groups or hosts or enable):
            f.default("SNMP.ENABLED", False, "no snmp-server statements configured")
            return
        anchor = (comms or users or groups or hosts or [enable])[0]
        f.put("SNMP.ENABLED", True, anchor.line_no)
        if comms:
            parsed = [(b, _tok(b.header)) for b in comms]
            pub = next((b for b, t in parsed if t[2].lower() in ("public", "private")), None)
            rw = next((b for b, t in parsed if any(x.lower() == "rw" for x in t[3:])
                       or (len(t) > 4 and t[3].lower() == "group" and "admin" in t[4].lower())), None)
            no_acl = next((b for b, t in parsed if not self._community_acl(t)), None)
            f.put("SNMP.COMMUNITY_PUBLIC", bool(pub), (pub or comms[0]).line_no,
                  targets=[{"name": community_ref(t[2], b.line_no)} for b, t in parsed if t[2].lower() in ("public", "private")])
            f.put("SNMP.READWRITE", bool(rw), (rw or comms[0]).line_no,
                  targets=[{"name": community_ref(t[2], b.line_no)} for b, t in parsed if any(x.lower() == "rw" for x in t[3:])
                           or (len(t) > 4 and t[3].lower() == "group" and "admin" in t[4].lower())])
            f.put("SNMP.ACL_RESTRICTED", no_acl is None, (no_acl or comms[0]).line_no,
                  targets=[{"name": community_ref(t[2], b.line_no),
                            "mode": "RW" if any(x.lower() == "rw" for x in t[3:]) else "RO",
                            "mode_lc": "rw" if any(x.lower() == "rw" for x in t[3:]) else "ro"}
                           for b, t in parsed if not self._community_acl(t)])
            f.put("SNMP.VERSION", 2, comms[0].line_no)           # v1/v2c communities present: worst case
        else:
            f.put("SNMP.COMMUNITY_PUBLIC", False, anchor.line_no)
            f.put("SNMP.READWRITE", False, anchor.line_no)
        v3 = [b for b in users + groups if re.search(r"\bv3\b|\bauth\b", b.header, re.I)]
        priv = [b for b in users + groups if re.search(r"\bpriv\b", b.header, re.I)]
        if v3 and not comms:
            f.put("SNMP.VERSION", 3, v3[0].line_no)
        if users or groups:
            f.put("SNMP.V3_PRIV", bool(priv), (priv or v3 or users or groups)[0].line_no)
        elif comms:
            f.put("SNMP.V3_PRIV", False, comms[0].line_no)

    def _aaa(self) -> None:
        f = self.f
        no_newm = self.negated(r"aaa new-model$")
        authn = self.top(r"^aaa authentication\b")
        authz = self.top(r"^aaa authorization\b")
        acct = self.top(r"^aaa accounting\b")
        if authn and not no_newm:
            f.put("AAA.AUTHENTICATION", True, authn[0].line_no)
        elif no_newm:
            f.put("AAA.AUTHENTICATION", False, no_newm.line_no)
        else:
            f.default("AAA.AUTHENTICATION", False, "'aaa new-model' / 'aaa authentication' not configured: local passwords only")
        f.put("AAA.AUTHORIZATION", True, authz[0].line_no) if authz else f.default(
            "AAA.AUTHORIZATION", False, "no 'aaa authorization' statements")
        f.put("AAA.ACCOUNTING", True, acct[0].line_no) if acct else f.default(
            "AAA.ACCOUNTING", False, "no 'aaa accounting' statements")
        tac = self.top(r"^(tacacs-server host|tacacs server|aaa group server tacacs\+?|tacacs-server key)\b")
        tac_hosts = self.top(r"^(tacacs-server host|tacacs server\s+\S+|tacacs host)\b")
        rad = self.top(r"^(radius-server host|radius server|aaa group server radius|radius-server key)\b")
        rad_hosts = self.top(r"^(radius-server host|radius server\s+\S+|radius host)\b")
        f.put("AAA.TACACS_CONFIGURED", True, tac[0].line_no) if tac else f.default(
            "AAA.TACACS_CONFIGURED", False, "no TACACS+ server configured")
        f.put("AAA.RADIUS_CONFIGURED", True, rad[0].line_no) if rad else f.default(
            "AAA.RADIUS_CONFIGURED", False, "no RADIUS server configured")
        servers = len(tac_hosts) + len(rad_hosts)
        if tac or rad:
            f.put("AAA.SERVER_REDUNDANT", servers >= 2, (tac_hosts + rad_hosts or tac or rad)[0].line_no)
        lock = (self.first(r"^aaa local authentication attempts max-fail\s+\d+")
                or self.first(r"^login block-for\s+\d+\s+attempts\s+\d+")
                or self.first(r"^aaa authentication policy lockout failure\s+\d+"))
        f.put("AAA.LOCKOUT_ENABLED", True, lock.line_no) if lock else f.default(
            "AAA.LOCKOUT_ENABLED", False, "no login lockout/block-for policy configured")
        # accounts
        users = self.top(r"^username\s+\S+")
        if users:
            bad = [b for b in users if self._is_default_account(b.header)]
            f.put("USER.DEFAULT_ACCOUNTS", bool(bad), (bad or users)[0].line_no,
                  note="well-known account name with no/cleartext/default credential" if bad else "",
                  targets=[{"name": _tok(b.header)[1]} for b in bad])
            maxp = 0
            for b in users:
                m = re.search(r"privilege\s+(\d+)", b.header)
                if m:
                    maxp = max(maxp, int(m.group(1)))
            if maxp:
                f.put("USER.PRIVILEGE_MAX", maxp, users[0].line_no)
        else:
            f.default("USER.DEFAULT_ACCOUNTS", False, "no local 'username' entries")

    @staticmethod
    def _is_default_account(header: str) -> bool:
        """Default account = well-known name AND a credential that is missing, cleartext or default.
        `username admin ... secret 9 <hash>` is an operator-set credential, not a default one."""
        t = header.split()
        name = t[1].lower()
        if name not in DEFAULT_USERS:
            return False
        if re.search(r"\bnopassword\b", header, re.I):
            return True
        m = re.search(r"\b(password|secret)\s+(?:(\d|sha512|sha256|scrypt|md5)\s+)?(\S+)", header, re.I)
        if not m:
            return True                      # no credential statement at all
        typ, val = (m.group(2) or "").lower(), m.group(3)
        if typ in ("", "0") and m.group(1).lower() == "password":
            return True                      # cleartext password
        return val.lower() in (name, "cisco", "admin", "password", "default")

    # -------------------------------------------------------------- passwords
    def _passwords(self) -> None:
        f = self.f
        spe, nspe = self.first(r"^service password-encryption$"), self.negated(r"service password-encryption$")
        if spe:
            f.put("SERVICE.PASSWORD_ENCRYPTION", True, spe.line_no)
        elif nspe:
            f.put("SERVICE.PASSWORD_ENCRYPTION", False, nspe.line_no)
        elif not (self.eos or self.nxos):
            f.default("SERVICE.PASSWORD_ENCRYPTION", False, "'service password-encryption' absent (off by default)")
        cleartext: List[int] = []
        weak_hash: List[int] = []
        credentials = 0
        creds = [(b.line_no, b.header) for b in self.top(r"^enable\s+(password|secret)\b|^username\s+\S+")]
        for b in self.top(r"^line\s+(con|aux|vty)"):
            creds += [(ln, t) for ln, t in b.children if re.match(r"^password\b", t, re.I)]
        for ln, text in creds:
            m = re.search(r"\b(password|secret)\s+(?:(\d|sha512|sha256|scrypt|md5)\s+)?(\S+)", text, re.I)
            if not m:
                continue
            credentials += 1
            kind, typ, val = m.group(1).lower(), (m.group(2) or "").lower(), m.group(3)
            if typ in ("", "0"):
                if kind == "password" or typ == "0":
                    cleartext.append(ln)           # `password X`, `password 0 X`, `secret 0 X`
                elif val.startswith("$1$"):
                    weak_hash.append(ln)           # bare `secret $1$...` is MD5-crypt
            elif typ in ("4", "5") and kind == "secret":
                weak_hash.append(ln)               # type 4 (broken) / type 5 (MD5-crypt)
        self._weak_hash, self._cleartext = weak_hash, cleartext
        if cleartext:
            f.put("PASSWORD.ENCRYPTED", False, cleartext[0], note="cleartext password in configuration")
        elif credentials or spe:
            f.put("PASSWORD.ENCRYPTED", True, spe.line_no if spe else creds[0][0] if creds else None)
        pl = self.first(r"^security passwords min-length\s+(\d+)")
        if pl:
            n = int(pl.header.split()[-1])
            f.put("PASSWORD.MIN_LENGTH", n, pl.line_no)
            f.put("PASSWORD.POLICY_STRONG", n >= 8, pl.line_no)
        elif self.nxos:
            ns = self.first(r"^no password strength-check$")
            if ns:
                f.put("PASSWORD.POLICY_STRONG", False, ns.line_no)
            else:
                f.default("PASSWORD.POLICY_STRONG", True, "NX-OS enforces password strength checking by default")
        else:
            f.default("PASSWORD.POLICY_STRONG", False, "no minimum password length policy configured")

    def _logging(self) -> None:
        f = self.f
        off = self.negated(r"logging on$")
        buf = self.first(r"^logging buffered") or self.first(r"^logging (file|console|monitor|logfile|level)\b")
        hosts = [b for b in self.top(r"^logging\b") if re.match(r"^logging\s+(host\s+\S+|server\s+\S+|\d{1,3}(\.\d{1,3}){3}|[a-z0-9-]+\.[a-z0-9.-]+)", b.header, re.I)
                 and not re.match(r"^logging\s+(buffered|console|monitor|trap|source|facility|origin|format|rate)", b.header, re.I)]
        on = self.first(r"^logging on$")
        if off:
            f.put("LOGGING.ENABLED", False, off.line_no)
        elif on or buf or hosts:
            f.put("LOGGING.ENABLED", True, (on or buf or hosts[0]).line_no)
        else:
            f.default("LOGGING.ENABLED", False, "no logging destination configured")
        f.put("LOGGING.REMOTE_SERVER", True, hosts[0].line_no) if hosts else f.default(
            "LOGGING.REMOTE_SERVER", False, "no remote syslog host configured")
        bb = self.first(r"^logging buffered")
        if bb:
            f.put("LOGGING.BUFFERED", True, bb.line_no)
        else:
            f.default("LOGGING.BUFFERED", False, "no 'logging buffered' configured")
        tr = self.first(r"^logging trap\s+(\S+)")
        if tr:
            f.put("LOGGING.TRAP_LEVEL", tr.header.split()[-1], tr.line_no)
        ts = self.first(r"^service timestamps log\b")
        nts = self.negated(r"service timestamps log")
        if ts:
            f.put("LOGGING.TIMESTAMPS", True, ts.line_no)
        elif nts:
            f.put("LOGGING.TIMESTAMPS", False, nts.line_no)
        elif self.first(r"^logging (format )?timestamp\b"):
            f.put("LOGGING.TIMESTAMPS", True, self.first(r"^logging (format )?timestamp\b").line_no)
        elif not self.eos:
            f.default("LOGGING.TIMESTAMPS", False, "no 'service timestamps log' / 'logging timestamp' configured")
        ar = self.first(r"^archive$")
        f.put("AUDIT.CONFIG_ARCHIVED", True, ar.line_no) if ar and ar.has(r"^(path|log config)") else f.default(
            "AUDIT.CONFIG_ARCHIVED", False, "no 'archive' configuration")
        tz = self.first(r"^clock timezone")
        f.put("CLOCK.TIMEZONE_SET", True, tz.line_no) if tz else f.default(
            "CLOCK.TIMEZONE_SET", False, "no 'clock timezone' configured")

    # -------------------------------------------------------------------- NTP
    def _ntp(self) -> None:
        f = self.f
        srv = self.top(r"^ntp\s+(server|peer|master)\b")
        f.put("NTP.ENABLED", True, srv[0].line_no) if srv else f.default(
            "NTP.ENABLED", False, "no NTP server/peer configured")
        auth = self.first(r"^ntp authenticate$")
        keys = self.first(r"^ntp (authentication-key|trusted-key)\b")
        if srv:
            f.put("NTP.AUTHENTICATED", bool(auth and keys), (auth or keys or srv[0]).line_no)
        src = self.first(r"^ntp (source|source-interface)\b")
        f.put("NTP.SOURCE_SET", True, src.line_no) if src else (
            f.default("NTP.SOURCE_SET", False, "no NTP source interface configured") if srv else None)

    # ---------------------------------------------------------------- banners
    def _banners(self) -> None:
        f = self.f
        for prop, kind in (("BANNER.MOTD_SET", "motd"), ("BANNER.LOGIN_SET", "login"), ("BANNER.EXEC_SET", "exec")):
            b = self.first(rf"^banner {kind}$")
            if b:
                f.put(prop, True, b.line_no)
            else:
                f.default(prop, False, f"no '{kind}' banner configured")

    def _services(self) -> None:
        f = self.f
        if self.eos or self.nxos:
            return
        pad, spad = self.negated(r"service pad$"), self.first(r"^service pad$")
        if pad:
            f.put("SERVICE.PAD_DISABLED", True, pad.line_no)
        elif spad:
            f.put("SERVICE.PAD_DISABLED", False, spad.line_no)
        else:
            f.default("SERVICE.PAD_DISABLED", False, "'no service pad' not configured")
        fin = self.negated(r"(ip finger|service finger)$")
        if fin:
            f.put("SERVICE.FINGER_DISABLED", True, fin.line_no)
        else:
            f.default("SERVICE.FINGER_DISABLED", True, "finger service is disabled by default since IOS 12.1(5)")
        sr, ssr = self.negated(r"ip source-route$"), self.first(r"^ip source-route$")
        if sr:
            f.put("IP.SOURCE_ROUTE_DISABLED", True, sr.line_no)
        elif ssr:
            f.put("IP.SOURCE_ROUTE_DISABLED", False, ssr.line_no)
        else:
            f.default("IP.SOURCE_ROUTE_DISABLED", False, "IP source routing is on by default ('no ip source-route' absent)")
        dl = self.negated(r"ip domain[- ]lookup$")
        if dl:
            f.put("DNS.LOOKUP_DISABLED", True, dl.line_no)
        else:
            f.default("DNS.LOOKUP_DISABLED", False, "'no ip domain-lookup' absent (DNS lookup on by default)")

    def _interfaces(self) -> None:
        f = self.f
        ifs = [b for b in self.blocks if re.match(r"^interface\s+", b.header, re.I)]
        l3 = [b for b in ifs if b.has(r"^ip address\s+\d") and not b.has(r"^shutdown$")
              and not re.match(r"^interface\s+(loopback|lo\d|tunnel|null|mgmt|management)", b.header, re.I)]
        f.consume(*(b.line_no for b in ifs))
        for b in ifs:
            f.consume(*(n for n, _ in b.children))
        if l3 and not self.eos:
            red_bad = [b for b in l3 if not b.has(r"^no ip redirects$")]
            arp_bad = [b for b in l3 if not b.has(r"^no ip proxy-arp$")]
            db_bad = [b for b in l3 if b.has(r"^ip directed-broadcast")]
            if self.nxos:     # NX-OS shows `ip proxy-arp` only when enabled; there is no directed-broadcast knob
                arp_on = [b for b in l3 if b.has(r"^ip proxy-arp$")]
                arp_bad = arp_on
                db_bad = []
            f.put("IP.REDIRECTS_DISABLED", not red_bad, (red_bad or l3)[0].line_no,
                  note=("missing on: " + ", ".join(b.header for b in red_bad)) if red_bad else "",
                  targets=[{"name": _iface_name(b)} for b in red_bad])
            f.put("PROXY_ARP.DISABLED", not arp_bad, (arp_bad or l3)[0].line_no,
                  note=("missing on: " + ", ".join(b.header for b in arp_bad)) if arp_bad else "",
                  targets=[{"name": _iface_name(b)} for b in arp_bad])
            if db_bad:
                f.put("IP.DIRECTED_BROADCAST_DISABLED", False, db_bad[0].line_no,
                      targets=[{"name": _iface_name(b)} for b in db_bad])
            elif not self.nxos:
                f.default("IP.DIRECTED_BROADCAST_DISABLED", True, "'ip directed-broadcast' is disabled by default since IOS 12.0")
            rpf = [b for b in l3 if b.has(r"^ip verify unicast")]
            f.put("URPF.ENABLED", bool(rpf), (rpf or l3)[0].line_no) if rpf else f.default(
                "URPF.ENABLED", False, "no 'ip verify unicast' (uRPF) on any L3 interface",
                targets=[{"name": _iface_name(b)} for b in l3])
        elif l3 and self.eos:
            rpf = [b for b in l3 if b.has(r"^ip verify unicast")]
            f.put("URPF.ENABLED", bool(rpf), (rpf or l3)[0].line_no) if rpf else f.default(
                "URPF.ENABLED", False, "no 'ip verify unicast' (uRPF) on any L3 interface")
        # CDP / LLDP
        if self.eos:
            nl = self.negated(r"lldp run$")
            f.put("CDP.DISABLED_EDGE", True, nl.line_no) if nl else f.default(
                "CDP.DISABLED_EDGE", False, "LLDP runs by default on EOS ('no lldp run' absent)")
        else:
            nc = self.negated(r"cdp run$") or self.negated(r"feature cdp$")
            f.put("CDP.DISABLED_EDGE", True, nc.line_no) if nc else f.default(
                "CDP.DISABLED_EDGE", False, "CDP runs by default ('no cdp run' absent)")
        # ACLs
        pa = None
        for b in self.top(r"^(ip|ipv6)?\s*access-list\b") + self.top(r"^access-list\b"):
            for ln, t in [(b.line_no, b.header)] + b.children:
                if re.search(r"\bpermit\s+(ip\s+)?any\s+any\b", t, re.I) and not re.search(r"\bdeny\b", t, re.I):
                    pa = ln
                    break
            if pa:
                break
        f.put("ACL.PERMIT_ANY", True, pa) if pa else (
            f.put("ACL.PERMIT_ANY", False, None) if self.top(r"access-list") else f.default(
                "ACL.PERMIT_ANY", False, "no access lists defined"))

    # ----------------------------------------------------------------- routing
    def _routing(self) -> None:
        f = self.f
        ospf = self.top(r"^router ospf")
        bgp = self.top(r"^router bgp")
        eigrp = self.top(r"^router eigrp")
        ifs = [b for b in self.blocks if re.match(r"^interface\s+", b.header, re.I)]
        any_auth = False
        if ospf:
            auth = [b for b in ifs if b.has(r"^ip ospf (message-digest-key|authentication)")] or \
                   [b for b in ospf if b.has(r"^area\s+\S+\s+authentication")]
            o_ok = bool(auth)
            f.put("ROUTING.OSPF_AUTH", o_ok, (auth or ospf)[0].line_no)
            any_auth = any_auth or o_ok
        if bgp:
            nbrs = [(ln, t) for b in bgp for ln, t in b.children if re.match(r"^neighbor\s+\S+\s+remote-as", t, re.I)]
            pws = {t.split()[1] for b in bgp for _, t in b.children if re.match(r"^neighbor\s+\S+\s+password", t, re.I)}
            for b in bgp:                       # NX-OS: `neighbor X` then indented remote-as / password lines
                cur = None
                for ln, t in b.children:
                    m = re.match(r"^neighbor\s+(\S+)$", t, re.I)
                    if m:
                        cur = m.group(1)
                        nbrs.append((ln, f"neighbor {cur} remote-as nested"))
                    elif cur and re.match(r"^password\b", t, re.I):
                        pws.add(cur)
            ips = {t.split()[1] for _, t in nbrs}
            b_ok = bool(ips) and ips <= pws
            asn = (re.search(r"router bgp\s+(\S+)", bgp[0].header, re.I) or [None, "<ASN>"])[1]
            if ips:
                f.put("ROUTING.BGP_AUTH", b_ok, nbrs[0][0], note="" if b_ok else f"no password for: {', '.join(sorted(ips - pws))}",
                      targets=[{"name": ip, "asn": asn} for ip in sorted(ips - pws)])
            any_auth = any_auth or b_ok
        if eigrp:
            e_ok = any(b.has(r"authentication mode") for b in ifs)
            any_auth = any_auth or e_ok
        if ospf or bgp or eigrp:
            f.put("ROUTING.AUTH_ENABLED", any_auth, (ospf or bgp or eigrp)[0].line_no)
        for b in ospf + bgp + eigrp:
            f.consume(b.line_no, *(n for n, _ in b.children))

    # --------------------------------------------------------------- switching
    def _switching(self) -> None:
        f = self.f
        ifs = [b for b in self.blocks if re.match(r"^interface\s+", b.header, re.I)]
        access = [b for b in ifs if b.has(r"^switchport mode access$") or (b.has(r"^switchport") and not b.has(r"^switchport mode trunk"))]
        is_switch = bool(access or self.top(r"^vlan \d+") or self.top(r"^spanning-tree"))
        if not is_switch:
            return
        ds = self.first(r"^ip dhcp snooping$")
        f.put("DHCP.SNOOPING", True, ds.line_no) if ds else f.default(
            "DHCP.SNOOPING", False, "'ip dhcp snooping' not enabled")
        ps = [b for b in access if b.has(r"^switchport port-security$")]
        f.put("PORT_SECURITY.ENABLED", True, ps[0].line_no) if ps else f.default(
            "PORT_SECURITY.ENABLED", False, "no 'switchport port-security' on access ports")
        bg = self.first(r"^spanning-tree portfast bpduguard default") or next(
            (b for b in access if b.has(r"^spanning-tree bpduguard enable")), None)
        f.put("STP.BPDU_GUARD", True, bg.line_no) if bg else f.default(
            "STP.BPDU_GUARD", False, "BPDU guard not enabled (global default or per access port)")

    # ------------------------------------------------------------------ crypto
    def _crypto(self) -> None:
        f = self.f
        weak: Optional[int] = None
        weak_note = ""
        scan = [(b.line_no, b.header) for b in self.blocks] + [(n, t) for b in self.blocks for n, t in b.children]
        for ln, t in sorted(scan):
            low = t.lower()
            if re.search(r"^(encryption|encr)\s+(des|3des)\b", low) or re.search(r"\bcipher\b.*\b(des|3des|rc4)\b", low) \
                    or re.match(r"^hash\s+md5\b", low) or re.match(r"^hash\s+sha\b$", low) \
                    or re.match(r"^group\s+(1|2|5)\b$", low) or re.search(r"\bpriv\s+des\b|\bauth\s+md5\b", low) \
                    or re.search(r"\besp-(des|3des|md5-hmac)\b", low) or re.search(r"\bssl cipher\b.*rc4", low):
                weak, weak_note = ln, "weak algorithm in crypto configuration"
                break
        if weak is None and getattr(self, "_weak_hash", None):
            weak, weak_note = self._weak_hash[0], "type 4/5 (MD5/SHA-256 unsalted) secret hash"
        if weak:
            f.put("CRYPTO.WEAK_ALGO", True, weak, note=weak_note)
        else:
            f.default("CRYPTO.WEAK_ALGO", False, "no weak algorithm found in the configuration (absence of evidence)")
        ipsec = self.first(r"^crypto (ipsec transform-set|map)\b") or self.first(r"^crypto ikev2 profile")
        f.put("CRYPTO.IPSEC_ENABLED", True, ipsec.line_no) if ipsec else f.default(
            "CRYPTO.IPSEC_ENABLED", False, "no IPsec transform-set/crypto map configured")
        v2 = self.first(r"^crypto ikev2 (proposal|policy|profile)")
        v1 = self.first(r"^crypto isakmp policy")
        if v1:
            f.put("CRYPTO.IKE_VERSION", 1, v1.line_no)
        elif v2:
            f.put("CRYPTO.IKE_VERSION", 2, v2.line_no)
        pfs = [(n, t) for b in self.blocks for n, t in b.children if re.match(r"^set pfs\b", t, re.I)]
        if ipsec:
            f.put("CRYPTO.PFS_ENABLED", bool(pfs), pfs[0][0] if pfs else ipsec.line_no)
        rsa = self.first(r"^ssh key rsa\s+(\d+)") or self.first(r"^crypto key generate rsa .*modulus\s+(\d+)")
        if rsa:
            f.put("CRYPTO.RSA_KEY_SIZE", int(re.search(r"(\d{3,5})", rsa.header).group(1)), rsa.line_no)

    # -------------------------------------------------------------------- misc
    _CLEAR_KEY_RX = [      # (?![67]\s) = the next token is an encryption-type marker, not the secret
        r"^(tacacs-server|radius-server)(\s+host\s+\S+(\s+vrf\s+\S+)?)?\s+key\s+(?:0\s+)?(?![67]\s)\S+",
        r"^key\s+(?:0\s+)?(?![67]\s)\S+$",
        r"^key-string\s+(?:0\s+)?(?![67]\s)\S+",
        r"^neighbor\s+\S+\s+password\s+(?:0\s+)?(?![67]\s)\S+",
        r"^ntp authentication-key\s+\d+\s+md5\s+\S+(?<!\s7)$",
        r"^ip ospf message-digest-key\s+\d+\s+(md5|sha1?)\s+(?:0\s+)?(?![67]\s)\S+",
        r"^ip ospf authentication-key\s+(?:0\s+)?(?![67]\s)\S+",
    ]

    def _misc(self) -> None:
        f = self.f
        nf = self.first(r"^(ip flow-export|flow exporter|ip flow ingress|sflow run|feature netflow|flow monitor)") or next(
            (b for b in self.blocks if b.has(r"^ip flow (ingress|egress)")), None)
        if nf:
            f.put("MONITORING.NETFLOW", True, nf.line_no)
        else:
            f.default("MONITORING.NETFLOW", False, "no NetFlow/sFlow/IPFIX export configured")
        dos = (self.first(r"^control-plane") or self.first(r"^system control-plane")
               or self.first(r"^policy-map type (control-plane|copp)") or self.first(r"^ip tcp intercept")
               or next((b for b in self.blocks if b.has(r"^storm-control")), None))
        if dos:
            f.put("DOS.PROTECTION", True, dos.line_no)
        else:
            f.default("DOS.PROTECTION", False, "no CoPP / TCP intercept / storm-control configured")
        # management only over encrypted protocols
        t, h = f.get("TELNET.ENABLED"), f.get("HTTP.ENABLED")
        anchor = f.res.provenance.get("TELNET.ENABLED", {}).get("line_no")
        if t is True or h is True:
            f.put("MGMT.ENCRYPTED_ONLY", False, anchor)
        elif t is False and h is False:
            f.put("MGMT.ENCRYPTED_ONLY", True, anchor)
        # key storage: any cleartext password/key statement shown in the configuration
        key_clear = [n for b in self.blocks for n, text in [(b.line_no, b.header)] + b.children
                     if any(re.search(rx, text, re.I) for rx in self._CLEAR_KEY_RX)]
        bad = list(getattr(self, "_cleartext", [])) + key_clear
        if bad:
            f.put("KEY.STORED_SECURE", False, sorted(bad)[0], note="cleartext key/password in configuration")
        else:
            f.default("KEY.STORED_SECURE", True, "no cleartext key/password statements found")
        for b in self.blocks:
            if re.match(r"^(ip|ipv6|mac)?\s*access-list|^class-map|^policy-map|^route-map|^key chain|^archive|^control-plane",
                        b.header, re.I):
                f.consume(b.line_no, *(n for n, _ in b.children))


def parse(text: str, vendor: str, platform: str = "") -> ParseResult:
    return IosLike(text, vendor.lower(), platform).parse()
