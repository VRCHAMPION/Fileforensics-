"""Indicator-of-compromise extraction from recovered strings, with defanging.

Network indicators (URLs, IPs, domains, emails) are only ever returned defanged,
so pasting the report into a chat or ticket can't produce a live link.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re

MAX_PER_TYPE = 100

# Deliberately excludes TLDs that collide with file extensions (.py, .sh, .pl, .so, .md, .js, .rs, .ps).
_TLDS = (
    "com|net|org|info|biz|io|co|me|us|uk|de|fr|nl|it|es|eu|ru|su|cn|jp|kr|in|br|au|ca|ir|kp|ua|pw|cc|tk|ml|ga|"
    "cf|gq|xyz|top|online|site|club|app|dev|gov|edu|mil|int|tech|live|shop|store|icu|buzz|cloud|link|click|"
    "work|onion|ly|to|ws|cyou|rest|monster"
)

URL_RE = re.compile(r"\b(?:https?|ftp|hxxps?)://[^\s\"'<>\\^`{|}]{2,2000}", re.IGNORECASE)
IPV4_RE = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d)(?!\.\d)"
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,24}\b")
DOMAIN_RE = re.compile(
    rf"(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.){{1,8}}(?:{_TLDS})\b(?![.-]\w)", re.IGNORECASE
)
# A path component may contain spaces ("Program Files") or dots ("x.exe"), but not both,
# which stops a path from swallowing the rest of a sentence. The last component has no spaces.
_SEG = r"(?:[^\\/:*?\"<>|\r\n\t ]{1,128}|[^\\/:*?\"<>|\r\n\t.]{1,128})\\"
_LAST = r"[^\\/:*?\"<>|\s]{0,128}"
WINPATH_RE = re.compile(
    r"(?:\b[A-Za-z]:\\|%[A-Za-z_]{2,30}%\\|\\\\[A-Za-z0-9.$_-]{1,63}\\)(?:" + _SEG + r"){0,24}" + _LAST
)
REGISTRY_RE = re.compile(
    r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU)"
    r"\\(?:" + _SEG + r"){0,30}" + _LAST,
    re.IGNORECASE,
)
BTC_LEGACY_RE = re.compile(r"(?<![A-Za-z0-9])[13][a-km-zA-HJ-NP-Z1-9]{25,34}(?![A-Za-z0-9])")
BTC_BECH32_RE = re.compile(r"(?<![A-Za-z0-9])bc1[ac-hj-np-z02-9]{11,71}(?![A-Za-z0-9])", re.IGNORECASE)

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def valid_base58check(addr: str) -> bool:
    num = 0
    for ch in addr:
        idx = _B58.find(ch)
        if idx < 0:
            return False
        num = num * 58 + idx
    raw = num.to_bytes(25, "big") if num.bit_length() <= 200 else b""
    if len(raw) != 25:
        return False
    payload, checksum = raw[:-4], raw[-4:]
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum


def valid_bech32(addr: str) -> bool:
    addr = addr.lower()
    hrp, _, data = addr.rpartition("1")
    if hrp != "bc" or len(data) < 6:
        return False
    values = [_BECH32.find(c) for c in data]
    if min(values) < 0:
        return False
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk in (1, 0x2BC830A3)  # bech32, bech32m


# ---------------------------------------------------------------- defanging


def defang_domain(d: str) -> str:
    return d.replace(".", "[.]")


def defang_ip(ip: str) -> str:
    return ip.replace(".", "[.]")


def defang_email(e: str) -> str:
    local, _, dom = e.partition("@")
    return f"{local}[@]{defang_domain(dom)}"


def defang_url(u: str) -> str:
    scheme, sep, rest = u.partition("://")
    if not sep:
        return defang_domain(u)
    s = scheme.lower()
    scheme = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}.get(s, scheme)
    host, slash, path = rest.partition("/")
    return f"{scheme}[://]{defang_domain(host)}{slash}{path}"


def _uniq(items, limit=MAX_PER_TYPE):
    seen: dict[str, None] = {}
    for it in items:
        if it not in seen:
            seen[it] = None
            if len(seen) >= limit:
                break
    return list(seen)


def _ip_scope(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback:
        return "loopback"
    if addr.is_private:
        return "private"
    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return "reserved"
    return "public"


def extract_iocs(text: str) -> dict:
    urls = _uniq(u.rstrip(".,;:)]}'\"") for u in URL_RE.findall(text))
    emails = _uniq(EMAIL_RE.findall(text))
    email_domains = {e.partition("@")[2].lower() for e in emails}
    url_hosts = {u.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0].lower() for u in urls}
    domains = _uniq(
        d for d in (m.lower() for m in DOMAIN_RE.findall(text)) if d not in email_domains and d not in url_hosts
    )
    ips = _uniq(IPV4_RE.findall(text))
    paths = _uniq(p.rstrip(" .") for p in WINPATH_RE.findall(text))
    reg = _uniq(r.rstrip(" .") for r in REGISTRY_RE.findall(text))
    btc = _uniq(
        [a for a in BTC_LEGACY_RE.findall(text) if valid_base58check(a)]
        + [a for a in BTC_BECH32_RE.findall(text) if valid_bech32(a)]
    )
    result = {
        "urls": [defang_url(u) for u in urls],
        "domains": [defang_domain(d) for d in domains],
        "ipv4": [{"value": defang_ip(ip), "scope": _ip_scope(ip)} for ip in ips],
        "emails": [defang_email(e) for e in emails],
        "windows_paths": paths,
        "registry_keys": reg,
        "bitcoin_addresses": btc,
    }
    result["counts"] = {k: len(v) for k, v in result.items()}
    return result
