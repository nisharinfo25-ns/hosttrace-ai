"""
utils/osint.py
OSINT simulation, redirect chain analysis, threat intelligence.
HostTrace AI v4.0
"""

import time
import random
import urllib.request
import urllib.error
from datetime import datetime
from urllib.parse import urljoin

from utils.constants import FAKE_THREAT_DB, KNOWN_LEGIT_PATTERNS


# ══════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════
def is_known_legit(domain: str) -> bool:
    d = domain.lower()
    return any(p in d for p in KNOWN_LEGIT_PATTERNS)


# ══════════════════════════════════════════════════════════════
# THREAT INTELLIGENCE (preserved, enhanced)
# ══════════════════════════════════════════════════════════════
def get_threat_intel(domain: str) -> dict:
    d = domain.lower()
    for kw, data in FAKE_THREAT_DB.items():
        if kw in d:
            return dict(data)
    seed  = sum(ord(c) for c in domain)
    legit = is_known_legit(domain)
    return {
        "virustotal_flags": 0 if legit else seed % 4,
        "blacklist_hits":   0 if legit else seed % 2,
        "abuse_ch":         False,
        "otx_pulses":       0 if legit else seed % 2,
        "c2_detected":      False,
        "phishing_category": False,
    }


# ══════════════════════════════════════════════════════════════
# IP HISTORY (preserved)
# ══════════════════════════════════════════════════════════════
def build_ip_history(ips: list, domain: str) -> list:
    if not ips:
        ips = ["0.0.0.0"]
    history = []
    seed    = sum(ord(c) for c in domain)
    base_ts = int(time.time()) - 365 * 24 * 3600
    for i, ip in enumerate(ips[:3]):
        record_ts = base_ts + i * (seed % 60 + 30) * 24 * 3600
        history.append({
            "timestamp": datetime.utcfromtimestamp(record_ts).strftime("%Y-%m-%d"),
            "ip":        ip,
            "provider":  ["Unknown CDN", "Direct Host", "Failover Host"][i % 3],
        })
    history.append({
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d"),
        "ip":        ips[0],
        "provider":  "Current",
    })
    return history


# ══════════════════════════════════════════════════════════════
# OSINT SIMULATION  (historical exposure)
# ══════════════════════════════════════════════════════════════
def build_osint_simulation(domain: str, ips: list) -> dict:
    """
    Simulate historical OSINT signals — previous DNS records,
    alternate IPs, and past hosting providers.

    Uses deterministic seed logic so the same domain always
    gets the same simulated history.
    """
    seed = sum(ord(c) for c in domain)
    random.seed(seed)

    PROVIDERS = [
        "OVH", "Hetzner", "DigitalOcean", "Linode", "Vultr",
        "AWS", "Google Cloud", "Azure", "Shared Hosting",
    ]

    def fake_ip(n: int) -> str:
        random.seed(seed + n)
        return (
            f"{random.randint(45, 185)}."
            f"{random.randint(10, 200)}."
            f"{random.randint(1,  250)}."
            f"{random.randint(1,  250)}"
        )

    historical_ips = [fake_ip(1), fake_ip(2)]
    alt_providers  = [
        PROVIDERS[seed % len(PROVIDERS)],
        PROVIDERS[(seed + 3) % len(PROVIDERS)],
    ]
    # ~60 % of domains get a simulated historical-exposure flag
    has_exposure = (seed % 5) > 1

    records = [
        {
            "date":     "2024-01-15",
            "ip":       historical_ips[0],
            "provider": alt_providers[0],
            "type":     "A Record (Historical)",
        },
        {
            "date":     "2024-06-10",
            "ip":       historical_ips[1],
            "provider": alt_providers[1],
            "type":     "A Record (Historical)",
        },
        {
            "date":     datetime.utcnow().strftime("%Y-%m-%d"),
            "ip":       ips[0] if ips else "N/A",
            "provider": "Current Host",
            "type":     "Current A Record",
        },
    ]

    return {
        "historical_ips":    historical_ips,
        "alt_providers":     alt_providers,
        "exposure_detected": has_exposure,
        "exposure_note": (
            "⚠ Possible historical exposure detected — domain previously "
            "hosted on different infrastructure"
            if has_exposure
            else "✓ No significant historical exposure detected"
        ),
        "records": records,
    }


# ══════════════════════════════════════════════════════════════
# REDIRECT CHAIN ANALYSIS  (NEW)
# ══════════════════════════════════════════════════════════════
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """urllib handler that captures redirects without following them."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def analyze_redirect_chain(domain: str) -> dict:
    """
    Manually follow HTTP/HTTPS redirects and record every hop.

    Returns:
        chain          — list of hop dicts {hop, url, status, next?, final}
        redirect_count — number of redirect hops
        suspicious     — True if redirect_count > 2
        total_hops     — length of chain
    """
    chain:   list = []
    url:     str  = domain if domain.startswith("http") else f"https://{domain}"
    visited: set  = set()
    MAX_HOPS      = 8
    tried_http    = False

    opener = urllib.request.build_opener(_NoRedirect())

    for hop in range(MAX_HOPS):
        if url in visited:
            break
        visited.add(url)

        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "HostTraceAI/4.0 RedirectAnalyzer"},
            )
            try:
                with opener.open(req, timeout=6) as resp:
                    chain.append({
                        "hop":   hop + 1,
                        "url":   url,
                        "status": resp.status,
                        "final": True,
                    })
                    break  # Final destination
            except urllib.error.HTTPError as e:
                if e.code in (301, 302, 303, 307, 308):
                    new_url = e.headers.get("Location", "")
                    if new_url and not new_url.startswith("http"):
                        new_url = urljoin(url, new_url)
                    chain.append({
                        "hop":   hop + 1,
                        "url":   url,
                        "status": e.code,
                        "next":  new_url,
                        "final": False,
                    })
                    url = new_url
                else:
                    chain.append({
                        "hop":   hop + 1,
                        "url":   url,
                        "status": e.code,
                        "final": True,
                    })
                    break

        except Exception as ex:
            # Try HTTP fallback on first HTTPS failure
            if hop == 0 and url.startswith("https://") and not tried_http:
                tried_http = True
                url = url.replace("https://", "http://", 1)
                continue
            chain.append({
                "hop":   hop + 1,
                "url":   url,
                "status": "Error",
                "error": str(ex)[:80],
                "final": True,
            })
            break

    redirect_count = len([c for c in chain if not c.get("final", True)])

    return {
        "chain":          chain,
        "redirect_count": redirect_count,
        "suspicious":     redirect_count > 3,
        "total_hops":     len(chain),
    }
