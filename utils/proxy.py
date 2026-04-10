"""
utils/proxy.py
Proxy detection, origin infrastructure discovery, ASN analysis.
HostTrace AI v4.0
"""

import socket
import ipaddress
from utils.constants import (
    CLOUDFLARE_RANGES, AKAMAI_RANGES, FASTLY_RANGES,
    ASN_PROVIDER_MAP, ORIGIN_SUBDOMAINS, CF_NS_PATTERNS,
    HOSTING_NS_PATTERNS, POPULAR_CF,
)


# ══════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════
def ip_in_cidr(ip_str: str, cidr_list: list) -> bool:
    """Return True if ip_str falls within any CIDR in cidr_list."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for cidr in cidr_list:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
    except Exception:
        pass
    return False


# ══════════════════════════════════════════════════════════════
# ASN / PROVIDER DETECTION
# ══════════════════════════════════════════════════════════════
def detect_asn_provider(ip: str) -> dict:
    """
    Identify the hosting/ASN provider for a given IP by
    checking it against known CIDR ranges.
    Returns provider name and whether a match was found.
    """
    for provider, ranges in ASN_PROVIDER_MAP.items():
        if ip_in_cidr(ip, ranges):
            return {"asn_provider": provider, "matched": True, "ip": ip}
    return {"asn_provider": "Unknown / Shared Hosting", "matched": False, "ip": ip}


# ══════════════════════════════════════════════════════════════
# ORIGIN INFRASTRUCTURE DISCOVERY  (CORE FEATURE 🔥)
# ══════════════════════════════════════════════════════════════
def discover_origin_infrastructure(domain: str, proxy_ips: list) -> dict:
    """
    Enumerate common subdomains (mail, ftp, api, dev, origin…) looking
    for DNS records that resolve to IPs NOT behind a proxy/CDN.
    Such IPs are likely the real origin server.

    Returns:
        possible_origin_ips  — list of non-proxy IPs found
        confidence           — Low / Medium / High
        subdomain_leaks      — list of {subdomain, ip, is_proxy, note}
        origin_suspected     — bool
        subdomains_checked   — int
    """
    possible_origin_ips: list = []
    subdomain_leaks:     list = []
    leak_signals:        list = []
    checked:             int  = 0

    PROXY_RANGES = CLOUDFLARE_RANGES + AKAMAI_RANGES + FASTLY_RANGES

    for sub in ORIGIN_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        try:
            result        = socket.getaddrinfo(fqdn, None)
            resolved_ips  = list({r[4][0] for r in result})
            for ip in resolved_ips:
                is_proxy = ip_in_cidr(ip, PROXY_RANGES)
                if not is_proxy and ip not in proxy_ips:
                    subdomain_leaks.append({
                        "subdomain": fqdn,
                        "ip":        ip,
                        "is_proxy":  False,
                        "note":      "⚠ Possible origin IP — NOT behind proxy",
                    })
                    leak_signals.append(f"Subdomain {fqdn} exposes IP {ip}")
                    if ip not in possible_origin_ips:
                        possible_origin_ips.append(ip)
                else:
                    subdomain_leaks.append({
                        "subdomain": fqdn,
                        "ip":        ip,
                        "is_proxy":  True,
                        "note":      "✓ Proxy-routed subdomain",
                    })
            checked += 1
        except Exception:
            checked += 1
            continue

    n = len(possible_origin_ips)
    confidence = "High" if n >= 2 else ("Medium" if n == 1 else "Low")

    if n == 0:
        leak_signals.append("Origin IP not publicly exposed due to CDN/Proxy protection")

    return {
        "possible_origin_ips": possible_origin_ips,
        "confidence":          confidence,
        "subdomain_leaks":     subdomain_leaks[:12],
        "leak_signals":        leak_signals,
        "origin_suspected":    n > 0,
        "subdomains_checked":  checked,
    }


# ══════════════════════════════════════════════════════════════
# ASN MISMATCH ANALYSIS
# ══════════════════════════════════════════════════════════════
def analyze_asn_mismatch(proxy_info: dict, origin_discovery: dict) -> dict:
    """
    Compare the visible proxy provider (e.g. Cloudflare) with the
    inferred origin ASN provider.  Flag any mismatch.

    Example output:
        "Cloudflare detected, but origin may be hosted on DigitalOcean"
    """
    proxy_provider   = (proxy_info.get("proxy_provider")
                        or proxy_info.get("cdn_provider")
                        or "Unknown")
    origin_ips       = origin_discovery.get("possible_origin_ips", [])
    origin_providers = []

    for ip in origin_ips[:3]:
        asn  = detect_asn_provider(ip)
        prov = asn["asn_provider"]
        if prov not in origin_providers:
            origin_providers.append(prov)

    mismatch      = False
    mismatch_note = None

    if origin_providers and proxy_info.get("proxy_detected"):
        origin_prov = origin_providers[0]
        if origin_prov != proxy_provider and origin_prov != "Unknown / Shared Hosting":
            mismatch      = True
            mismatch_note = (
                f"{proxy_provider} detected as proxy layer, "
                f"but origin server may be hosted on {origin_prov}"
            )

    return {
        "proxy_provider":       proxy_provider,
        "origin_asn_providers": origin_providers,
        "origin_asn_provider":  origin_providers[0] if origin_providers else "Unknown",
        "mismatch_detected":    mismatch,
        "mismatch_note":        mismatch_note,
    }


# ══════════════════════════════════════════════════════════════
# PROXY / CDN DETECTION  (preserved from v3.0, enhanced)
# ══════════════════════════════════════════════════════════════
def detect_proxy(dns_info: dict, whois_info: dict, http_info: dict = None) -> dict:
    """Full proxy/CDN detection using CIDR, NS, and domain pattern checks."""
    result = {
        "proxy_detected":    False,
        "proxy_provider":    None,
        "cdn_detected":      False,
        "cdn_provider":      None,
        "detection_method":  [],
        "masking_level":     "None",
        "waf_suspected":     False,
        "origin_hidden":     False,
        "proxy_indicators":  [],
    }
    ips    = dns_info.get("ip_addresses", [])
    nss    = [n.lower() for n in whois_info.get("name_servers", [])]
    domain = dns_info.get("hostname", "").lower()

    # ── Cloudflare IP ──
    for ip in ips:
        if ip_in_cidr(ip, CLOUDFLARE_RANGES):
            result.update({
                "proxy_detected": True, "proxy_provider": "Cloudflare",
                "cdn_detected":   True, "cdn_provider":   "Cloudflare",
                "waf_suspected":  True, "masking_level":  "HIGH — Full origin IP suppression",
            })
            result["detection_method"].append(
                f"IP {ip} matches Cloudflare CIDR block (AS13335)")
            break

    # ── Akamai ──
    if not result["proxy_detected"]:
        for ip in ips:
            if ip_in_cidr(ip, AKAMAI_RANGES):
                result.update({
                    "cdn_detected": True, "cdn_provider": "Akamai CDN",
                    "masking_level": "MEDIUM — CDN edge layer active",
                })
                result["detection_method"].append(f"IP {ip} matches Akamai CIDR range")
                break

    # ── Fastly ──
    if not result["proxy_detected"] and not result["cdn_detected"]:
        for ip in ips:
            if ip_in_cidr(ip, FASTLY_RANGES):
                result.update({
                    "cdn_detected": True, "cdn_provider": "Fastly CDN",
                    "masking_level": "MEDIUM — CDN edge layer active",
                })
                result["detection_method"].append(f"IP {ip} matches Fastly CIDR range")
                break

    # ── Cloudflare NS ──
    for ns in nss:
        if any(cf in ns for cf in CF_NS_PATTERNS):
            result.update({
                "proxy_detected": True, "proxy_provider": "Cloudflare",
                "cdn_detected":   True, "cdn_provider":   "Cloudflare",
                "waf_suspected":  True,
            })
            if "HIGH" not in result["masking_level"]:
                result["masking_level"] = "HIGH — Full origin IP suppression"
            result["detection_method"].append(
                f"Name server '{ns}' is a Cloudflare NS record")

    # ── Known Cloudflare enterprise customers ──
    if not result["proxy_detected"] and not result["cdn_detected"]:
        if any(p in domain for p in POPULAR_CF):
            result.update({
                "proxy_detected": True, "proxy_provider": "Cloudflare",
                "cdn_detected":   True, "cdn_provider":   "Cloudflare",
                "waf_suspected":  True, "masking_level":  "HIGH — Full origin IP suppression",
            })
            result["detection_method"].append(
                "Domain matches known Cloudflare Enterprise customer pattern")

    if http_info and http_info.get("proxy_headers"):
        ph = http_info.get("proxy_headers")
        result["proxy_indicators"].extend(ph)
        if not result["proxy_detected"] and not result["cdn_detected"]:
            if http_info.get("cdn_via_header"):
                via_prov = http_info.get("cdn_via_header")
                result.update({
                    "cdn_detected": True, "cdn_provider": via_prov,
                    "masking_level": "MEDIUM — HTTP Proxy/CDN layer active",
                })
                result["detection_method"].append(f"HTTP header indicator: {via_prov}")

    if result["proxy_detected"] or result["cdn_detected"]:
        result["origin_hidden"] = True

    if not result["proxy_detected"] and not result["cdn_detected"]:
        result["masking_level"] = "NONE — Direct host exposure"

    return result
