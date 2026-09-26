"""
LLM Gateway — SINGLE entry point for ALL AI/LLM API calls in the OKF project.

RULE: No other file may call Featherless AI / any LLM API directly.
      Everything (unknown-token interpretation, semantic mapping, config parsing)
      MUST go through this module. This keeps maintenance to one file.

Provider : Featherless AI (OpenAI-compatible endpoint)
Default  : gpt-oss-120b  ->  model id "openai/gpt-oss-120b"
Env      : FEATHERLESS_API_KEY (you add this to .env)
           FEATHERLESS_BASE_URL (default https://api.featherless.ai/v1)
           OKF_MODEL (default openai/gpt-oss-120b)

Usage:
    from llm_gateway import gateway, parse_config_to_ir, suggest_mapping

If no API key is set, the gateway runs in OFFLINE mode with deterministic
heuristic fallbacks so the OKF engines + tests still work.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
    load_dotenv(Path(__file__).parent.parent / ".env")
except Exception:  # pragma: no cover - defensive: dotenv is a hard dependency
    pass

FEATHERLESS_BASE_URL = os.getenv("FEATHERLESS_BASE_URL", "https://api.featherless.ai/v1").rstrip("/")
FEATHERLESS_API_KEY = os.getenv("FEATHERLESS_API_KEY", "").strip()
DEFAULT_MODEL = os.getenv("OKF_MODEL", "openai/gpt-oss-120b")

# Canonical property vocabulary (kept in sync with knowledge/properties/*.yaml).
# Full registry (~100 props). LLM/heuristic output is validated against this list.
CANONICAL_PROPERTIES = [
    "SSH.ENABLED", "SSH.VERSION", "SSH.WEAK_CIPHERS", "SSH.TIMEOUT_SET",
    "SSH.RETRIES_LIMITED", "SSH.MACS_STRONG",
    "TELNET.ENABLED", "TELNET.ABSENT",
    "HTTP.ENABLED", "HTTPS.ENABLED", "HTTP.SECURE_ONLY",
    "FTP.ENABLED", "TFTP.ENABLED", "AUX.DISABLED",
    "VTY.ACL_APPLIED", "VTY.TIMEOUT_SET", "CONSOLE.SECURED",
    "SNMP.ENABLED", "SNMP.VERSION", "SNMP.COMMUNITY_PUBLIC", "SNMP.V3_PRIV",
    "SNMP.READWRITE", "SNMP.ACL_RESTRICTED",
    "AAA.AUTHENTICATION", "AAA.AUTHORIZATION", "AAA.ACCOUNTING", "AAA.MFA",
    "AAA.LOCKOUT_ENABLED", "AAA.TACACS_CONFIGURED", "AAA.RADIUS_CONFIGURED",
    "AAA.LOCAL_FALLBACK_ONLY", "AAA.SERVER_REDUNDANT",
    "PASSWORD.POLICY_STRONG", "PASSWORD.MIN_LENGTH", "PASSWORD.COMPLEXITY",
    "PASSWORD.ENCRYPTED", "PASSWORD.REUSE_PREVENTED",
    "USER.DEFAULT_ACCOUNTS", "USER.PRIVILEGE_MAX",
    "POLICY.PASSWORD_ROTATION", "POLICY.SESSION_LOCK",
    "LOGGING.ENABLED", "LOGGING.REMOTE_SERVER", "LOGGING.BUFFERED",
    "LOGGING.TRAP_LEVEL", "LOGGING.TIMESTAMPS", "LOGGING.SERVER_REACHABLE",
    "AUDIT.CONFIG_ARCHIVED",
    "NTP.ENABLED", "NTP.AUTHENTICATED", "NTP.SOURCE_SET",
    "DNS.LOOKUP_DISABLED", "CLOCK.TIMEZONE_SET",
    "SERVICE.PASSWORD_ENCRYPTION", "SERVICE.PAD_DISABLED",
    "BANNER.MOTD_SET", "BANNER.LOGIN_SET", "BANNER.EXEC_SET",
    "BACKUP.SCHEDULED",
    "ACL.MGMT_RESTRICTED", "ACL.INGRESS_DEFINED", "ACL.EGRESS_DEFINED",
    "ACL.DEFAULT_DENY", "ACL.PERMIT_ANY",
    "FIREWALL.POLICY_SET", "ZONE.SECURED",
    "CRYPTO.WEAK_ALGO", "CRYPTO.TLS_MIN", "CRYPTO.IPSEC_ENABLED",
    "CRYPTO.IKE_VERSION", "CRYPTO.PFS_ENABLED", "CRYPTO.RSA_KEY_SIZE",
    "CRYPTO.SSL_VERSION_MIN", "ENCRYPTION.CONTROL_PLANE", "KEY.STORED_SECURE",
    "CERT.PRESENT", "CERT.SELF_SIGNED", "CERT.EXPIRED",
    "INTERFACE.UNUSED_SHUTDOWN", "INTERFACE.MGMT_ISOLATED",
    "CDP.DISABLED_EDGE", "PROXY_ARP.DISABLED",
    "IP.SOURCE_ROUTE_DISABLED", "IP.REDIRECTS_DISABLED",
    "IP.DIRECTED_BROADCAST_DISABLED",
    "ROUTING.AUTH_ENABLED", "ROUTING.OSPF_AUTH", "ROUTING.BGP_AUTH",
    "STP.BPDU_GUARD", "DHCP.SNOOPING", "PORT_SECURITY.ENABLED",
    "VLAN.NATIVE_SET", "DOS.PROTECTION", "URPF.ENABLED",
    "SOFTWARE.OS_VERSION_KNOWN", "SOFTWARE.EOL_VERSION",
    "SOFTWARE.SSH_VERSION_KNOWN", "SOFTWARE.SSL_VERSION_KNOWN",
    "MGMT.ENCRYPTED_ONLY", "MGMT.INTERNET_EXPOSED", "MGMT.SESSION_TIMEOUT",
    "MONITORING.NETFLOW",
]


@dataclass
class GatewayResponse:
    ok: bool
    model: str
    data: Any = None
    raw: str = ""
    offline: bool = False
    error: str = ""


@dataclass
class FeatherlessGateway:
    """Single gateway object. Import `gateway` singleton elsewhere."""

    api_key: str = field(default_factory=lambda: FEATHERLESS_API_KEY)
    base_url: str = field(default_factory=lambda: FEATHERLESS_BASE_URL)
    model: str = field(default_factory=lambda: DEFAULT_MODEL)
    timeout: float = 60.0

    @property
    def online(self) -> bool:
        return bool(self.api_key)

    # ---- low-level chat (OpenAI-compatible) ----
    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.1,
             max_tokens: int = 1500, model: Optional[str] = None) -> GatewayResponse:
        mdl = model or self.model
        if not self.online:
            return GatewayResponse(ok=False, model=mdl, offline=True,
                                   error="OFFLINE: FEATHERLESS_API_KEY not set")
        try:
            import httpx
            payload = {
                "model": mdl,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            r = httpx.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}",
                         "Content-Type": "application/json"},
                json=payload, timeout=self.timeout,
            )
            if r.status_code != 200:
                return GatewayResponse(ok=False, model=mdl, raw=r.text,
                                       error=f"HTTP {r.status_code}: {r.text[:500]}")
            j = r.json()
            text = j["choices"][0]["message"]["content"]
            return GatewayResponse(ok=True, model=mdl, data=j, raw=text)
        except Exception as e:  # network / dep errors -> graceful
            return GatewayResponse(ok=False, model=mdl, error=str(e))

    # ---- helpers ----
    @staticmethod
    def _extract_json(text: str) -> Optional[Any]:
        m = re.search(r"\{.*\}|\[.*\]", text, re.S)
        if not m:
            return None
        try:
            return json.loads(m.group(0))
        except Exception:
            return None

    @staticmethod
    def _coerce(value: Any) -> Any:
        """Coerce LLM string values ('2', 'true') to typed values so they
        compare equal against YAML control expectations (EQUALS is typed)."""
        if isinstance(value, str):
            s = value.strip().lower()
            if re.fullmatch(r"-?\d+", s):
                return int(s)
            if re.fullmatch(r"-?\d*\.\d+", s):
                return float(s)
            if s in ("true", "false"):
                return s == "true"
        return value


gateway = FeatherlessGateway()


# ---------------------------------------------------------------- heuristics
def _heuristic_parse_line(line: str) -> Optional[Dict[str, Any]]:
    """Deterministic offline fallback: map a raw CLI line to canonical property."""
    l = line.strip().lower()
    if not l or l.startswith(("!", "#", "hostname")):
        return None
    rules = [
        (r"ip\s+ssh\s+version\s+2|ssh.*protocol-version\s+v?2|ssh.*v2", "SSH.VERSION", 2, 0.85),
        (r"ip\s+ssh\s+version\s+1|ssh.*v1\b", "SSH.VERSION", 1, 0.85),
        (r"\bno\s+ip\s+ssh\b|ssh\s+disable|no\s+ssh", "SSH.ENABLED", False, 0.85),
        (r"\b(ip\s+ssh|ssh\s+server|system\s+services\s+ssh)\b", "SSH.ENABLED", True, 0.7),
        (r"telnet|transport\s+input\s+.*telnet|telnet\s+server\s+enable", "TELNET.ENABLED", True, 0.8),
        (r"no\s+.*telnet|transport\s+input\s+ssh\s*$", "TELNET.ENABLED", False, 0.8),
        (r"no\s+ip\s+http\s+server|http\s+disable", "HTTP.ENABLED", False, 0.85),
        (r"ip\s+http\s+server(?!.*secure)|http\s+enable", "HTTP.ENABLED", True, 0.8),
        (r"ip\s+http\s+secure-server|https?\s+.*tls|ssl\s+enable", "HTTPS.ENABLED", True, 0.75),
        (r"snmp-server\s+community\s+public|snmp.*public", "SNMP.COMMUNITY_PUBLIC", True, 0.9),
        (r"snmp|snmp-server", "SNMP.ENABLED", True, 0.7),
        (r"no\s+snmp|snmp\s+disable", "SNMP.ENABLED", False, 0.8),
        (r"logging\s+(host|server|buffered)|syslog|logging\s+enable", "LOGGING.REMOTE_SERVER", True, 0.8),
        (r"no\s+logging|logging\s+disable", "LOGGING.ENABLED", False, 0.85),
        (r"\blogging\b", "LOGGING.ENABLED", True, 0.7),
        (r"ntp\s+server|ntp\s+enable", "NTP.ENABLED", True, 0.8),
        (r"ntp\s+auth|ntp\s+authentication", "NTP.AUTHENTICATED", True, 0.8),
        (r"aaa\s+new-model|aaa\s+auth", "AAA.AUTHENTICATION", True, 0.8),
        (r"mfa|multifactor|two-factor|2fa", "AAA.MFA", True, 0.75),
        (r"des\b|3des|md5|rc4|sha1\b|dh\s+group\s*1\b", "CRYPTO.WEAK_ALGO", True, 0.8),
        (r"aes|sha-?256|sha-?512|ecdsa|ed25519", "CRYPTO.WEAK_ALGO", False, 0.7),
        (r"access-class|access-list|mgmt.*acl|transport.*acl", "ACL.MGMT_RESTRICTED", True, 0.7),
        (r"password.*(min-length|complexity|policy)|security\s+password", "PASSWORD.POLICY_STRONG", True, 0.7),
        (r"banner\s+motd|banner\s+login", "BANNER.MOTD_SET", True, 0.8),
        (r"service\s+password-encryption", "SERVICE.PASSWORD_ENCRYPTION", True, 0.95),
        (r"enable\s+secret|username\s+\S+\s+.*secret|password\s+\d+\s+\S", "PASSWORD.ENCRYPTED", True, 0.85),
        (r"enable\s+password(?!.*secret)|password\s+0\s", "PASSWORD.ENCRYPTED", False, 0.8),
        (r"login\s+block|login\s+on-failure|lockout|aaa.*lockout", "AAA.LOCKOUT_ENABLED", True, 0.8),
        (r"tacacs-server\s+host|tacacs\s+server\s", "AAA.TACACS_CONFIGURED", True, 0.9),
        (r"radius-server\s+host|radius\s+server\s", "AAA.RADIUS_CONFIGURED", True, 0.9),
        (r"ip\s+ssh\s+time-out|ssh\s+timeout", "SSH.TIMEOUT_SET", True, 0.85),
        (r"ip\s+ssh\s+authentication-retries|ssh\s+retries", "SSH.RETRIES_LIMITED", True, 0.85),
        (r"snmp-server\s+group\s+\S+\s+v3\s+priv|snmp.*authpriv|snmp.*v3.*priv", "SNMP.V3_PRIV", True, 0.85),
        (r"snmp-server\s+group\s+\S+\s+v3\b", "SNMP.VERSION", 3, 0.8),
        (r"snmp-server\s+community\s+\S+\s+rw|snmp.*read-write|\brw\b.*snmp", "SNMP.READWRITE", True, 0.8),
        (r"no\s+ip\s+source-route", "IP.SOURCE_ROUTE_DISABLED", True, 0.9),
        (r"ip\s+source-route\b(?!.*no)", "IP.SOURCE_ROUTE_DISABLED", False, 0.85),
        (r"no\s+ip\s+redirects", "IP.REDIRECTS_DISABLED", True, 0.9),
        (r"no\s+ip\s+directed-broadcast", "IP.DIRECTED_BROADCAST_DISABLED", True, 0.9),
        (r"no\s+ip\s+proxy-arp", "PROXY_ARP.DISABLED", True, 0.9),
        (r"no\s+cdp\s+run|no\s+cdp\s+enable|no\s+lldp\s+", "CDP.DISABLED_EDGE", True, 0.8),
        (r"ip\s+ospf\s+authentication|router\s+ospf.*auth|area\s+\S+\s+authentication", "ROUTING.OSPF_AUTH", True, 0.8),
        (r"neighbor\s+\S+\s+password|bgp.*password|neighbor.*auth", "ROUTING.BGP_AUTH", True, 0.8),
        (r"spanning-tree\s+portfast\s+bpduguard|bpduguard\s+enable", "STP.BPDU_GUARD", True, 0.85),
        (r"ip\s+dhcp\s+snooping", "DHCP.SNOOPING", True, 0.9),
        (r"switchport\s+port-security", "PORT_SECURITY.ENABLED", True, 0.9),
        (r"crypto\s+ikev2|ike\s+version\s+2|crypto\s+ike\s+v2", "CRYPTO.IKE_VERSION", 2, 0.8),
        (r"crypto\s+ikev1|ike\s+version\s+1\b", "CRYPTO.IKE_VERSION", 1, 0.8),
        (r"crypto\s+key\s+generate\s+rsa.*(2048|4096)|rsa.*(2048|4096)", "CRYPTO.RSA_KEY_SIZE", 2048, 0.8),
        (r"crypto\s+key\s+generate\s+rsa.*1024|rsa.*1024", "CRYPTO.RSA_KEY_SIZE", 1024, 0.85),
        (r"ip\s+http\s+secure-server|ip\s+http\s+.*tls", "HTTP.SECURE_ONLY", True, 0.7),
        (r"exec-timeout\s+\d+|session-timeout|idle\s+timeout", "MGMT.SESSION_TIMEOUT", True, 0.75),
        (r"transport\s+input\s+none", "TELNET.ABSENT", True, 0.7),
        (r"shutdown\s*$|interface\s+\S+\s*\n\s*shutdown", "INTERFACE.UNUSED_SHUTDOWN", True, 0.6),
        (r"logging\s+trap\s+\S+|logging\s+buffered", "LOGGING.BUFFERED", True, 0.7),
        (r"service\s+timestamps\s+log", "LOGGING.TIMESTAMPS", True, 0.85),
        (r"no\s+ip\s+domain-lookup|no\s+ip\s+domain\s+lookup", "DNS.LOOKUP_DISABLED", True, 0.85),
        (r"clock\s+timezone|clock\s+summer-time", "CLOCK.TIMEZONE_SET", True, 0.85),
        (r"username\s+(admin|cisco|root|guest)\b", "USER.DEFAULT_ACCOUNTS", True, 0.8),
        (r"ip\s+urpf|unicast\s+rpf|ip\s+verify\s+unicast", "URPF.ENABLED", True, 0.85),
        (r"flow\s+monitor|netflow|sflow|ip\s+flow", "MONITORING.NETFLOW", True, 0.75),
    ]
    for pat, prop, val, conf in rules:
        if re.search(pat, l):
            return {"canonical_property": prop, "canonical_value": val,
                    "confidence": conf, "evidence": line.strip(), "source": "heuristic"}
    return None


# ------------------------------------------------------- public gateway API
SYSTEM_PARSER = (
    "You are a network-config normalizer. Map vendor CLI lines to canonical "
    f"properties from this closed vocabulary: {', '.join(CANONICAL_PROPERTIES)}. "
    "Reply with ONLY a JSON array of {line, canonical_property, canonical_value, confidence}."
)


def parse_config_to_ir(config_text: str, vendor: str = "unknown",
                       model: Optional[str] = None) -> Dict[str, Any]:
    """Parse raw config text -> list of {property, value, confidence, evidence}.

    Online: calls Featherless gpt-oss-120b via chat(). Offline: heuristics.
    Deterministic values always win downstream (docs arch §7) — this only fills gaps.
    """
    lines = [l for l in config_text.splitlines() if l.strip() and not l.strip().startswith(("!", "#"))]
    if gateway.online:
        user = f"Vendor: {vendor}\nConfig lines:\n" + "\n".join(f"- {l}" for l in lines[:120])
        resp = gateway.chat(
            [{"role": "system", "content": SYSTEM_PARSER},
             {"role": "user", "content": user}],
            temperature=0.0, model=model,
        )
        parsed = gateway._extract_json(resp.raw) if resp.ok else None
        if isinstance(parsed, list) and parsed:
            norm = []
            for p in parsed:
                if isinstance(p, dict) and p.get("canonical_property") in CANONICAL_PROPERTIES:
                    norm.append({
                        "canonical_property": p["canonical_property"],
                        "canonical_value": FeatherlessGateway._coerce(p.get("canonical_value")),
                        "confidence": float(p.get("confidence", 0.8)),
                        "evidence": p.get("line", ""),
                        "source": f"llm:{resp.model}",
                    })
            if norm:
                return {"mappings": norm, "model": resp.model, "offline": False}
    # offline / fallback
    out = []
    for l in lines:
        m = _heuristic_parse_line(l)
        if m:
            out.append(m)
    return {"mappings": out, "model": gateway.model, "offline": not gateway.online}


def suggest_mapping(raw_command: str, vendor: str = "unknown",
                    context: Optional[List[str]] = None,
                    model: Optional[str] = None) -> Dict[str, Any]:
    """Suggest top-3 canonical mappings for ONE unknown command (training UI)."""
    context = context or []
    if gateway.online:
        user = (f"Vendor: {vendor}\nCommand: {raw_command}\nContext: {context}\n"
                f"Vocabulary: {', '.join(CANONICAL_PROPERTIES)}\n"
                "Return ONLY JSON: {suggestions:[{canonical_property,value,confidence}]}")
        resp = gateway.chat(
            [{"role": "system", "content": "You map network commands to canonical security properties. JSON only."},
             {"role": "user", "content": user}],
            temperature=0.0, model=model,
        )
        parsed = gateway._extract_json(resp.raw) if resp.ok else None
        if isinstance(parsed, dict) and isinstance(parsed.get("suggestions"), list):
            s = []
            for x in parsed["suggestions"]:
                if x.get("canonical_property") in CANONICAL_PROPERTIES:
                    x = dict(x)
                    x["value"] = FeatherlessGateway._coerce(x.get("value"))
                    s.append(x)
            if s:
                return {"training_suggestions": s[:3], "model": resp.model, "offline": False}
    m = _heuristic_parse_line(raw_command)
    if m:
        alt = {"canonical_property": m["canonical_property"],
               "value": m["canonical_value"], "confidence": m["confidence"]}
        return {"training_suggestions": [alt], "model": gateway.model, "offline": not gateway.online}
    return {"training_suggestions": [
        {"canonical_property": "SSH.ENABLED", "value": True, "confidence": 0.35},
        {"canonical_property": "LOGGING.ENABLED", "value": True, "confidence": 0.25},
        {"canonical_property": "TELNET.ENABLED", "value": False, "confidence": 0.20},
    ], "model": gateway.model, "offline": not gateway.online}


def interpret_unknown_token(line: str, vendor: str = "unknown") -> Dict[str, Any]:
    """Classify a line as KNOWN / UNKNOWN / UNCERTAIN (M2 detector helper)."""
    m = _heuristic_parse_line(line)
    if m and m["confidence"] >= 0.7:
        return {"status": "KNOWN", "mapping": m, "offline": not gateway.online}
    if gateway.online:
        resp = gateway.chat(
            [{"role": "system", "content": "Reply ONLY JSON {status: KNOWN|UNKNOWN|UNCERTAIN, reason}."},
             {"role": "user", "content": f"Vendor {vendor}. Known vocab: {CANONICAL_PROPERTIES}. Line: {line}"}],
            temperature=0.0,
        )
        parsed = gateway._extract_json(resp.raw) if resp.ok else None
        if isinstance(parsed, dict) and parsed.get("status") in ("KNOWN", "UNKNOWN", "UNCERTAIN"):
            return {"status": parsed["status"], "reason": parsed.get("reason", ""),
                    "model": resp.model, "offline": False}
    return {"status": "UNKNOWN" if not m else "UNCERTAIN",
            "mapping": m, "offline": True}


def list_models() -> Dict[str, Any]:
    """List Featherless models (online) — maintenance helper."""
    if not gateway.online:
        return {"offline": True, "default_model": gateway.model}
    try:
        import httpx
        r = httpx.get(f"{gateway.base_url}/models",
                      headers={"Authorization": f"Bearer {gateway.api_key}"},
                      timeout=30)
        return {"offline": False, "status": r.status_code, "data": r.json() if r.status_code == 200 else r.text[:1000]}
    except Exception as e:
        return {"offline": False, "error": str(e)}
