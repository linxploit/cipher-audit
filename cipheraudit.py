#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
  ____ ___ ____  _   _ _____ ____      _   _   _ ____ ___ _____
 / ___|_ _|  _ \\| | | | ____|  _ \\    / \\ | | | |  _ \\_ _|_   _|
| |    | || |_) | |_| |  _| | |_) |  / _ \\| | | | | | | |  | |
| |___ | ||  __/|  _  | |___|  _ <  / ___ \\ |_| | |_| | |  | |
 \\____|___|_|   |_| |_|_____|_| \\_\\/_/   \\_\\___/|____/___| |_|

CipherAudit — TLS Certificate & Protocol Security Inspector
Made by Mindless — Founder & CEO of Linxploit
https://linxploit.com | https://linxploit.com/founder
aaaaaaa
WHAT THIS TOOL DOES:
    CipherAudit connects to a host over TLS — the same handshake any
    browser performs — reads the certificate it presents, checks which
    protocol versions the connection negotiates, and reviews a handful
    of HTTP security headers over HTTPS. It performs no exploitation
    and no MITM; it only inspects what the server itself sends during
    a standard handshake.

    A NOTE ON LEGACY PROTOCOL TESTING: modern OpenSSL builds (3.0+)
    disable SSLv3/TLSv1.0/TLSv1.1 at the security-policy level, which
    can prevent the *client itself* from even attempting a legacy
    handshake — independent of whether the server would accept one.
    CipherAudit detects this and reports it as INCONCLUSIVE rather
    than a false "not supported," and documents the limitation in the
    README. For authoritative legacy-protocol testing, a dedicated
    tool such as testssl.sh or the Qualys SSL Labs service is more
    reliable than any single Python client.

    Only assess hosts you own or are explicitly authorized to test.
"""

import argparse
import concurrent.futures
import json
import os
import socket
import ssl
import sys
import time
import warnings
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import requests
from colorama import Fore, Style, init as colorama_init

# We intentionally probe deprecated TLS versions (SSLv3/TLSv1.0/TLSv1.1) as
# part of legacy-protocol testing — silence the resulting DeprecationWarning
# noise rather than let it clutter the report.
warnings.filterwarnings("ignore", category=DeprecationWarning, module="ssl")

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:  # pragma: no cover
    CRYPTOGRAPHY_AVAILABLE = False

colorama_init(autoreset=True)
requests.packages.urllib3.disable_warnings()  # noqa

TOOL_NAME = "CipherAudit"
VERSION = "1.0.0"
AUTHOR = "Mindless"
ORG = "Linxploit"
SITE = "https://linxploit.com"
PORTFOLIO = "https://linxploit.com/founder"


GRADIENT = [
    "\033[38;5;22m", "\033[38;5;28m", "\033[38;5;34m", "\033[38;5;40m",
    "\033[38;5;76m", "\033[38;5;112m", "\033[38;5;148m", "\033[38;5;184m",
    "\033[38;5;220m", "\033[38;5;226m",
]
RESET = Style.RESET_ALL
DIM = Style.DIM
BOLD = Style.BRIGHT

C_OK = Fore.GREEN + BOLD
C_GOOD = Fore.GREEN
C_MED = Fore.YELLOW + BOLD
C_HIGH = "\033[38;5;208m" + BOLD
C_CRIT = Fore.RED + BOLD
C_MUTE = Fore.WHITE + DIM
C_ACC = "\033[38;5;34m" + BOLD  # emerald accent
C_GOLD = "\033[38;5;220m" + BOLD
C_INFO = Fore.CYAN

SEVERITY_COLOR = {"CRITICAL": C_CRIT, "HIGH": C_HIGH, "MEDIUM": C_MED, "LOW": C_GOOD, "INFO": C_INFO}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def supports_unicode() -> bool:
    enc = (sys.stdout.encoding or "").lower()
    return "utf" in enc


UNICODE_OK = supports_unicode()

BOX = {
    "tl": "╔" if UNICODE_OK else "+", "tr": "╗" if UNICODE_OK else "+",
    "bl": "╚" if UNICODE_OK else "+", "br": "╝" if UNICODE_OK else "+",
    "h": "═" if UNICODE_OK else "-", "v": "║" if UNICODE_OK else "|",
    "lt": "╠" if UNICODE_OK else "+", "rt": "╣" if UNICODE_OK else "+",
    "thin": "─" if UNICODE_OK else "-",
    "check": "✔" if UNICODE_OK else "OK", "cross": "✘" if UNICODE_OK else "X",
    "warn": "⚠" if UNICODE_OK else "!", "spark": "✦" if UNICODE_OK else "*",
    "dot": "•" if UNICODE_OK else "*", "lock": "🔒" if UNICODE_OK else "[L]",
    "q": "?" if UNICODE_OK else "?",
}

BANNER_ART = r"""
  ____ ___ ____  _   _ _____ ____      _   _   _ ____ ___ _____
 / ___|_ _|  _ \| | | | ____|  _ \    / \ | | | |  _ \_ _|_   _|
| |    | || |_) | |_| |  _| | |_) |  / _ \| | | | | | | |  | |
| |___ | ||  __/|  _  | |___|  _ <  / ___ \ |_| | |_| | |  | |
 \____|___|_|   |_| |_|_____|_| \_\/_/   \_\___/|____/___| |_|
""".rstrip("\n")

BANNER_ART_ASCII = r"""
 ____ ___ ____  _  _ ____ ____    ____ _  _ ___  _ ___
/ ___ | | |___] |__| |___ |__/ __ |__| |  | |  \ |  |
|___ |_|_| |     |  | |___ |  \    |  | |__| |__/ |  |
""".rstrip("\n")

import re as _re  # noqa: E402
ANSI_RE = _re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


def gradient_line(text: str) -> str:
    out = []
    n = max(len(GRADIENT) - 1, 1)
    for i, ch in enumerate(text):
        color = GRADIENT[int((i / max(len(text) - 1, 1)) * n)]
        out.append(color + ch)
    return "".join(out) + RESET


def render_banner():
    art = BANNER_ART if UNICODE_OK else BANNER_ART_ASCII
    width = max(len(strip_ansi(line)) for line in art.splitlines()) + 6

    print()
    for line in art.splitlines():
        print(gradient_line(line))
    print()

    tagline = f"{BOX['spark']} TLS Certificate & Protocol Security Inspector {BOX['spark']}"
    print(C_ACC + tagline.center(width) + RESET)
    sub = f"v{VERSION} · Reads what the handshake reveals. No MITM, no exploitation."
    print(C_MUTE + sub.center(width) + RESET)
    print()
    info_box(
        [
            f"{BOX['dot']} Author   : {AUTHOR}  ({ORG} — Founder & CEO)",
            f"{BOX['dot']} Website  : {SITE}",
            f"{BOX['dot']} Portfolio: {PORTFOLIO}",
        ],
        title="ABOUT",
        color=Fore.MAGENTA,
    )
    if not CRYPTOGRAPHY_AVAILABLE:
        print(f"\n{C_HIGH}{BOX['warn']} The 'cryptography' package is not installed — certificate "
              f"parsing will be unavailable. Run: pip install cryptography{RESET}")


def info_box(lines: List[str], title: str = "", color: str = Fore.CYAN, width: Optional[int] = None):
    content_width = width or (max((len(strip_ansi(l)) for l in lines), default=20) + 4)
    top = f"{color}{BOX['tl']}{BOX['h'] * content_width}{BOX['tr']}{RESET}"
    bot = f"{color}{BOX['bl']}{BOX['h'] * content_width}{BOX['br']}{RESET}"
    print(top)
    if title:
        pad = content_width - len(title) - 2
        left = pad // 2
        right = pad - left
        print(f"{color}{BOX['v']}{RESET} {' ' * left}{BOLD}{title}{RESET}{' ' * right} {color}{BOX['v']}{RESET}")
        print(f"{color}{BOX['lt']}{BOX['h'] * content_width}{BOX['rt']}{RESET}")
    for line in lines:
        pad = max(content_width - len(strip_ansi(line)) - 1, 0)
        print(f"{color}{BOX['v']}{RESET} {Fore.WHITE}{line}{RESET}{' ' * pad}{color}{BOX['v']}{RESET}")
    print(bot)


def section(title: str, color: str = Fore.CYAN):
    print(f"\n{color}[ {title} ]{RESET}")
    print(color + BOX["thin"] * 60 + RESET)


def hr(color=C_MUTE, width=70):
    print(color + BOX["h"] * width + RESET)


@dataclass
class CertificateInfo:
    subject: Optional[str] = None
    issuer: Optional[str] = None
    common_name: Optional[str] = None
    san: List[str] = field(default_factory=list)
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_remaining: Optional[int] = None
    serial_number: Optional[str] = None
    signature_algorithm: Optional[str] = None
    key_type: Optional[str] = None
    key_size: Optional[int] = None
    fingerprint_sha1: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    self_signed_heuristic: bool = False
    trust_validated: Optional[bool] = None
    trust_error: Optional[str] = None
    error: Optional[str] = None


@dataclass
class ProtocolResult:
    supported: Optional[bool]  # True / False / None = inconclusive
    note: str = ""


@dataclass
class Finding:
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    issue: str


@dataclass
class ScanResult:
    host: str
    port: int
    certificate: Optional[CertificateInfo] = None
    protocols: Dict[str, ProtocolResult] = field(default_factory=dict)
    security_headers: Dict[str, Optional[str]] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    duration_s: float = 0.0
    error: Optional[str] = None

    @property
    def worst_severity(self) -> str:
        if self.error:
            return "ERROR"
        if not self.findings:
            return "INFO"
        return min(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 5)).severity


def fetch_certificate_der(host: str, port: int, timeout: int) -> bytes:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.getpeercert(binary_form=True)


def check_trust(host: str, port: int, timeout: int) -> Tuple[Optional[bool], Optional[str]]:
    """Separately verify whether the certificate is trusted by the system
    trust store and matches the hostname — this requires an actual
    verifying handshake, which is why it's kept apart from the raw
    certificate parse above (which works even for self-signed/expired certs)."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True, None
    except ssl.SSLCertVerificationError as e:
        return False, e.verify_message if hasattr(e, "verify_message") else str(e)
    except Exception as e:  # noqa
        return None, str(e)


def parse_certificate(der: bytes) -> CertificateInfo:
    info = CertificateInfo()
    if not CRYPTOGRAPHY_AVAILABLE:
        info.error = "The 'cryptography' package is required to parse certificate details."
        return info

    try:
        cert = x509.load_der_x509_certificate(der, default_backend())
    except Exception as e:  # noqa
        info.error = f"Failed to parse certificate: {e}"
        return info

    info.subject = cert.subject.rfc4514_string()
    info.issuer = cert.issuer.rfc4514_string()
    try:
        cn_attr = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        info.common_name = cn_attr[0].value if cn_attr else None
    except Exception:  # noqa
        info.common_name = None

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        info.san = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        info.san = []

    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    if not_before and not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=timezone.utc)
    if not_after and not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    info.not_before = not_before
    info.not_after = not_after
    if not_after:
        info.days_remaining = (not_after - datetime.now(timezone.utc)).days

    info.serial_number = format(cert.serial_number, "x")
    info.signature_algorithm = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"

    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        info.key_type = "RSA"
        info.key_size = pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        info.key_type = f"EC ({pub.curve.name})"
        info.key_size = pub.key_size
    else:
        info.key_type = type(pub).__name__

    info.fingerprint_sha1 = cert.fingerprint(hashes.SHA1()).hex()
    info.fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()

    issuer_cn = None
    try:
        issuer_cn_attr = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        issuer_cn = issuer_cn_attr[0].value if issuer_cn_attr else None
    except Exception:  # noqa
        pass
    info.self_signed_heuristic = bool(issuer_cn and info.common_name and issuer_cn == info.common_name)

    return info


PROTOCOL_TEST_ORDER = ["SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]

_PROTOCOL_TLS_VERSION = {
    "SSLv3": getattr(ssl.TLSVersion, "SSLv3", None),
    "TLSv1.0": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}


def test_single_protocol(host: str, port: int, label: str, timeout: int) -> ProtocolResult:
    tls_version = _PROTOCOL_TLS_VERSION.get(label)
    if tls_version is None:
        return ProtocolResult(None, "Not testable — this TLS version constant isn't available in the local OpenSSL build.")

    # Legacy protocols (SSLv3/TLSv1.0/TLSv1.1) are blocked outright by modern
    # OpenSSL's default security level (SECLEVEL) — lowering it here is what
    # actually lets the client *attempt* the handshake at all, so a rejection
    # reflects the server's choice rather than the local library's policy.
    is_legacy = label in ("SSLv3", "TLSv1.0", "TLSv1.1")

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if is_legacy:
            try:
                context.set_ciphers("DEFAULT@SECLEVEL=0")
            except ssl.SSLError:
                pass
        context.minimum_version = tls_version
        context.maximum_version = tls_version
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return ProtocolResult(True, f"Negotiated {ssock.version()}")

    except ssl.SSLError as e:
        msg = str(e)
        if "NO_PROTOCOLS_AVAILABLE" in msg or "UNSUPPORTED_PROTOCOL" in msg:
            if is_legacy:
                return ProtocolResult(None, "Inconclusive — local OpenSSL policy blocks this protocol "
                                              "regardless of server support. Use testssl.sh or SSL Labs for a definitive answer.")
            return ProtocolResult(False, "Server rejected this protocol version.")
        return ProtocolResult(False, f"Server rejected this protocol version ({msg[:80]}).")
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return ProtocolResult(None, f"Connection issue: {e}")
    except Exception as e:  # noqa
        return ProtocolResult(None, str(e))


def check_protocol_support(host: str, port: int, timeout: int, skip_legacy: bool) -> Dict[str, ProtocolResult]:
    results = {}
    for label in PROTOCOL_TEST_ORDER:
        if skip_legacy and label in ("SSLv3", "TLSv1.0", "TLSv1.1"):
            results[label] = ProtocolResult(None, "Skipped (--skip-legacy)")
            continue
        results[label] = test_single_protocol(host, port, label, timeout)
    return results


SECURITY_HEADER_NAMES = [
    "Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options",
    "X-Frame-Options", "Referrer-Policy", "Permissions-Policy",
]


def check_security_headers(host: str, port: int, timeout: int) -> Dict[str, Optional[str]]:
    url = f"https://{host}" if port == 443 else f"https://{host}:{port}"
    try:
        resp = requests.get(url, timeout=timeout, verify=False,
                             headers={"User-Agent": f"Mozilla/5.0 ({TOOL_NAME}/{VERSION})"})
        return {h: resp.headers.get(h) for h in SECURITY_HEADER_NAMES}
    except Exception as e:  # noqa
        return {"_error": str(e)}


WEAK_SIGNATURE_ALGOS = {"sha1", "md5", "md2"}


def analyze_findings(cert: Optional[CertificateInfo], protocols: Dict[str, ProtocolResult],
                      headers: Dict[str, Optional[str]]) -> List[Finding]:
    findings: List[Finding] = []

    if cert and not cert.error:
        if cert.days_remaining is not None:
            d = cert.days_remaining
            if d < 0:
                findings.append(Finding("CRITICAL", f"Certificate EXPIRED {abs(d)} day(s) ago."))
            elif d < 7:
                findings.append(Finding("CRITICAL", f"Certificate expires in {d} day(s) — urgent renewal needed."))
            elif d < 30:
                findings.append(Finding("HIGH", f"Certificate expires in {d} day(s)."))
            elif d < 90:
                findings.append(Finding("MEDIUM", f"Certificate expires in {d} day(s)."))

        if cert.self_signed_heuristic:
            findings.append(Finding("MEDIUM", "Certificate appears self-signed (issuer CN matches subject CN)."))

        if cert.trust_validated is False:
            findings.append(Finding("HIGH", f"Certificate failed system trust validation"
                                             f"{': ' + cert.trust_error if cert.trust_error else '.'}"))

        if cert.signature_algorithm and cert.signature_algorithm.lower() in WEAK_SIGNATURE_ALGOS:
            findings.append(Finding("HIGH", f"Certificate uses a weak signature algorithm ({cert.signature_algorithm.upper()})."))

        if cert.key_type == "RSA" and cert.key_size and cert.key_size < 2048:
            findings.append(Finding("HIGH", f"RSA key size is only {cert.key_size} bits (2048+ recommended)."))

    for label, result in protocols.items():
        if result.supported is True:
            if label == "SSLv3":
                findings.append(Finding("CRITICAL", "SSLv3 is supported — critically insecure, disable immediately."))
            elif label == "TLSv1.0":
                findings.append(Finding("HIGH", "TLSv1.0 is supported — deprecated, disable it."))
            elif label == "TLSv1.1":
                findings.append(Finding("HIGH", "TLSv1.1 is supported — deprecated, disable it."))

    if protocols.get("TLSv1.3") and protocols["TLSv1.3"].supported is False:
        findings.append(Finding("LOW", "TLSv1.3 is not supported — consider enabling it for best performance/security."))

    if headers and "_error" not in headers:
        if not headers.get("Strict-Transport-Security"):
            findings.append(Finding("MEDIUM", "HSTS (Strict-Transport-Security) header is missing."))
        if not headers.get("Content-Security-Policy"):
            findings.append(Finding("LOW", "Content-Security-Policy header is missing."))
        if not headers.get("X-Frame-Options"):
            findings.append(Finding("LOW", "X-Frame-Options header is missing (clickjacking protection)."))

    return findings


def scan_target(host: str, port: int, timeout: int, skip_legacy: bool, check_headers: bool) -> ScanResult:
    result = ScanResult(host=host, port=port)
    start = time.perf_counter()

    try:
        socket.gethostbyname(host)
    except socket.gaierror:
        result.error = f"Could not resolve hostname: {host}"
        return result

    try:
        der = fetch_certificate_der(host, port, timeout)
        cert = parse_certificate(der) if der else CertificateInfo(error="No certificate returned.")
        trusted, trust_err = check_trust(host, port, timeout)
        cert.trust_validated = trusted
        cert.trust_error = trust_err
        result.certificate = cert
    except Exception as e:  # noqa
        result.certificate = CertificateInfo(error=str(e))

    result.protocols = check_protocol_support(host, port, timeout, skip_legacy)

    if check_headers:
        result.security_headers = check_security_headers(host, port, timeout)

    result.findings = analyze_findings(result.certificate, result.protocols, result.security_headers)
    result.duration_s = round(time.perf_counter() - start, 2)
    return result


def format_date(dt: Optional[datetime]) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if isinstance(dt, datetime) else "—"


def print_result(result: ScanResult, verbose: bool):
    section(f"TARGET: {result.host}:{result.port}", Fore.CYAN)

    if result.error:
        print(f"  {C_CRIT}{BOX['cross']} {result.error}{RESET}")
        return

    print(f"  {C_MUTE}Scan time: {result.duration_s}s{RESET}")

    cert = result.certificate
    if cert and cert.error:
        print(f"\n  {C_CRIT}{BOX['cross']} {cert.error}{RESET}")
    elif cert:
        print(f"\n  {C_ACC}Certificate{RESET}")
        print(f"    {BOX['dot']} Subject : {cert.common_name or cert.subject}")
        print(f"    {BOX['dot']} Issuer  : {cert.issuer}")
        if cert.san:
            shown = ", ".join(cert.san[:6]) + (f" (+{len(cert.san) - 6} more)" if len(cert.san) > 6 else "")
            print(f"    {BOX['dot']} SAN     : {shown}")
        print(f"    {BOX['dot']} Valid   : {format_date(cert.not_before)} → {format_date(cert.not_after)}", end="")
        if cert.days_remaining is not None:
            d = cert.days_remaining
            dcolor = C_CRIT if d < 7 else C_HIGH if d < 30 else C_MED if d < 90 else C_GOOD
            label = f"EXPIRED {abs(d)}d ago" if d < 0 else f"{d}d remaining"
            print(f"  {dcolor}[{label}]{RESET}")
        else:
            print()
        print(f"    {BOX['dot']} Key     : {cert.key_type} {cert.key_size or ''}-bit, "
              f"signature {cert.signature_algorithm}")
        trust_color = C_GOOD if cert.trust_validated else (C_HIGH if cert.trust_validated is False else C_MUTE)
        trust_label = "trusted by system store" if cert.trust_validated else \
            ("NOT trusted by system store" if cert.trust_validated is False else "trust check inconclusive")
        print(f"    {BOX['dot']} Trust   : {trust_color}{trust_label}{RESET}")
        if verbose:
            print(f"    {BOX['dot']} SHA-256 : {cert.fingerprint_sha256}")
            print(f"    {BOX['dot']} Serial  : {cert.serial_number}")

    print(f"\n  {C_ACC}Protocol Support{RESET}")
    for label in PROTOCOL_TEST_ORDER:
        r = result.protocols.get(label)
        if not r:
            continue
        if r.supported is True:
            bad = label in ("SSLv3", "TLSv1.0", "TLSv1.1")
            color = C_CRIT if label == "SSLv3" else (C_HIGH if bad else (C_GOOD if label == "TLSv1.2" else C_INFO))
            icon = BOX["cross"] if bad else BOX["check"]
            print(f"    {color}{icon} {label:<9}{RESET} supported  {C_MUTE}{r.note}{RESET}")
        elif r.supported is False:
            print(f"    {C_MUTE}{BOX['dot']} {label:<9}{RESET} not supported  {C_MUTE}{r.note}{RESET}")
        else:
            print(f"    {C_MED}{BOX['q']} {label:<9}{RESET} inconclusive  {C_MUTE}{r.note}{RESET}")

    if result.security_headers and "_error" not in result.security_headers:
        print(f"\n  {C_ACC}HTTPS Security Headers{RESET}")
        for h in SECURITY_HEADER_NAMES:
            value = result.security_headers.get(h)
            if value:
                shown = value if len(value) <= 60 else value[:60] + "..."
                print(f"    {C_GOOD}{BOX['check']} {h}{RESET}: {C_MUTE}{shown}{RESET}")
            else:
                print(f"    {C_MUTE}{BOX['cross']} {h} — missing{RESET}")

    if result.findings:
        print(f"\n  {C_ACC}Findings{RESET}")
        for f in sorted(result.findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 5)):
            color = SEVERITY_COLOR.get(f.severity, C_MUTE)
            print(f"    {color}[{f.severity}]{RESET} {f.issue}")
    else:
        print(f"\n  {C_OK}{BOX['check']} No issues found.{RESET}")


def print_summary(results: List[ScanResult]):
    section("SCAN SUMMARY", Fore.MAGENTA)
    scanned = [r for r in results if not r.error]
    errored = [r for r in results if r.error]

    counts = {}
    for r in scanned:
        counts[r.worst_severity] = counts.get(r.worst_severity, 0) + 1

    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if level in counts:
            color = SEVERITY_COLOR.get(level, C_MUTE)
            dots = (BOX["dot"] * counts[level]) if UNICODE_OK else ("*" * counts[level])
            print(f"  {color}{level:<9}{RESET} : {color}{counts[level]:>3}{RESET}  {color}{dots}{RESET}")

    if errored:
        print(f"\n  {C_MUTE}{len(errored)} target(s) could not be scanned.{RESET}")
    print(f"\n  {BOLD}Total targets scanned:{RESET} {len(results)}")
    print()


def save_json(results: List[ScanResult], path: str):
    data = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "author": AUTHOR,
        "organization": ORG,
        "results": [
            {
                "host": r.host,
                "port": r.port,
                "error": r.error,
                "duration_s": r.duration_s,
                "certificate": asdict(r.certificate) if r.certificate else None,
                "protocols": {k: asdict(v) for k, v in r.protocols.items()},
                "security_headers": r.security_headers,
                "findings": [asdict(f) for f in r.findings],
            }
            for r in results
        ],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)

def parse_target(raw: str) -> Tuple[str, int]:
    raw = raw.strip()
    if raw.startswith(("http://", "https://")):
        raw = raw.split("://", 1)[1]
    raw = raw.split("/")[0]
    if ":" in raw:
        host, port_str = raw.rsplit(":", 1)
        try:
            return host, int(port_str)
        except ValueError:
            return host, 443
    return raw, 443


def load_targets(args) -> List[Tuple[str, int]]:
    targets = []
    if args.host:
        targets.append(parse_target(args.host))
    if args.list:
        if not os.path.isfile(args.list):
            print(C_CRIT + f"[!] File not found: {args.list}" + RESET)
            sys.exit(1)
        with open(args.list, "r", encoding="utf-8") as f:
            targets.extend(parse_target(line) for line in f if line.strip() and not line.startswith("#"))
    return targets


def confirm_authorization(skip: bool) -> bool:
    if skip:
        return True
    print()
    print(f"{C_MED}{BOX['warn']} CipherAudit opens several TLS connections per target to test "
          f"protocol support, plus one HTTPS request for headers.{RESET}")
    print(f"{C_MED}{BOX['warn']} Only assess hosts you OWN or are AUTHORIZED to test.{RESET}")
    try:
        answer = input(f"\n{BOLD}Type 'yes' to confirm you are authorized: {RESET}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer == "yes"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cipheraudit",
        description=f"{TOOL_NAME} — TLS Certificate & Protocol Security Inspector by {AUTHOR} ({ORG})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  cipheraudit.py -H example.com\n"
            "  cipheraudit.py -H example.com:8443 -v\n"
            "  cipheraudit.py -l hosts.txt --skip-legacy -o report.json\n"
        ),
    )
    parser.add_argument("-H", "--host", help="Target host, optionally 'host:port' (default port 443)")
    parser.add_argument("-l", "--list", help="File containing a list of hosts (one per line)")
    parser.add_argument("-p", "--port", type=int, default=443, help="Default port when not specified inline (default: 443)")
    parser.add_argument("-t", "--timeout", type=int, default=8, help="Per-connection timeout in seconds (default: 8)")
    parser.add_argument("--threads", type=int, default=3, help="Concurrent targets scanned in parallel (default: 3)")
    parser.add_argument("--skip-legacy", action="store_true",
                         help="Skip SSLv3/TLSv1.0/TLSv1.1 probing entirely (faster, avoids inconclusive results)")
    parser.add_argument("--no-headers", action="store_true", help="Skip the HTTPS security header check")
    parser.add_argument("-o", "--output", help="Save results to a JSON file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show fingerprint and serial number")
    parser.add_argument("--yes", action="store_true", help="Skip the authorization confirmation prompt")
    parser.add_argument("--no-banner", action="store_true", help="Suppress the ASCII banner")
    parser.add_argument("--version", action="store_true", help="Show version information and exit")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        print(f"{TOOL_NAME} v{VERSION} — by {AUTHOR} ({ORG})")
        return

    if not args.no_banner:
        render_banner()

    targets = load_targets(args)
    if not targets:
        parser.print_help()
        print(C_CRIT + "\n[!] No target provided. Use -H/--host or -l/--list.\n" + RESET)
        sys.exit(1)

    if not confirm_authorization(args.yes):
        print(C_CRIT + "\n[!] Authorization not confirmed. Aborting.\n" + RESET)
        sys.exit(1)

    section(f"INSPECTING {len(targets)} TARGET(S)", Fore.CYAN)
    print(f"  {C_MUTE}timeout={args.timeout}s  threads={args.threads}  "
          f"legacy-probe={'off' if args.skip_legacy else 'on'}{RESET}")

    results: List[ScanResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {
            pool.submit(scan_target, host, port, args.timeout, args.skip_legacy, not args.no_headers): (host, port)
            for host, port in targets
        }
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    order = {(h, p): i for i, (h, p) in enumerate(targets)}
    results.sort(key=lambda r: order.get((r.host, r.port), 0))

    for result in results:
        print_result(result, args.verbose)

    print()
    print_summary(results)

    if args.output:
        save_json(results, args.output)
        print(C_OK + f"{BOX['check']} Report saved to: {args.output}\n" + RESET)

    hr(C_MUTE, 70)
    print(C_ACC + f"  {TOOL_NAME} · Made by {AUTHOR} — Founder & CEO of {ORG}" + RESET)
    print(C_MUTE + f"  {SITE}  |  {PORTFOLIO}" + RESET)
    hr(C_MUTE, 70)
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(C_MED + "\n\n[!] Interrupted by user. Exiting.\n" + RESET)
        sys.exit(130)
