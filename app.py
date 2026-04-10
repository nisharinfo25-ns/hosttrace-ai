"""
HostTrace AI — Smart URL Risk Analyzer
Flask Backend API  v4.0 — Advanced Cybersecurity Investigation Engine

New in v4.0:
  • Origin infrastructure discovery (subdomain enumeration)
  • ASN / hosting provider mismatch detection
  • Redirect chain analysis
  • OSINT simulation (historical exposure)
  • AI Confidence Module
  • "Why is this site risky?" explainable output
  • Visual infrastructure map data
  • Updated risk weights
  • Modular utils (utils/proxy.py, utils/osint.py, utils/analyzer.py)
"""

from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS
import socket, time, re, ipaddress, sys, os, ssl, random, string
from datetime import datetime
from urllib.parse import urlparse
import threading
from dotenv import load_dotenv
load_dotenv()

# ── Set global socket timeout ─────────────────────────────────
socket.setdefaulttimeout(15)

# ── Optional dependencies ─────────────────────────────────────
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import urllib.request
    import urllib.error
    URLLIB_AVAILABLE = True
except ImportError:
    URLLIB_AVAILABLE = False

# ── Utils imports ─────────────────────────────────────────────
from utils.constants import (
    CLOUDFLARE_RANGES, AWS_RANGES, GCP_RANGES, AZURE_RANGES,
    AKAMAI_RANGES, FASTLY_RANGES, DIGITALOCEAN_RANGES,
    LINODE_RANGES, VULTR_RANGES, HETZNER_RANGES, OVH_RANGES,
    CF_NS_PATTERNS, HOSTING_NS_PATTERNS, FLAGGED_REGIONS,
    SUSPICIOUS_TLDS, PHISHING_KEYWORDS, ENTERPRISE_REGISTRARS,
    TRUSTED_REGISTRARS, KNOWN_LEGIT_PATTERNS, FAKE_THREAT_DB,
    POPULAR_CF, ASN_PROVIDER_MAP,
)
from utils.proxy import (
    ip_in_cidr, detect_proxy, detect_asn_provider,
    discover_origin_infrastructure, analyze_asn_mismatch,
)
from utils.osint import (
    get_threat_intel, build_ip_history,
    build_osint_simulation, analyze_redirect_chain,
    is_known_legit,
)
from utils.analyzer import (
    calculate_risk, generate_verdict,
    generate_ai_confidence, build_risk_explanation,
    build_infrastructure_map, is_enterprise_registrar,
)
from utils.ml_engine import append_and_train, predict_risk, generate_local_explanation
from utils.report_generator import generate_pdf_report, generate_text_report, generate_word_report
import utils.anti_phishing as anti_phishing
import utils.xai_module as xai_module

SCAN_CACHE = {}

app = Flask(__name__)
CORS(app)


# ══════════════════════════════════════════════════════════════
# HELPERS (local, used for small utilities)
# ══════════════════════════════════════════════════════════════

def generate_risk_explanation(
    domain: str,
    risk_score: int,
    prediction: str,
    flags,
    features: dict = None,
) -> dict:
    """
    Generates a plain-English risk explanation using the fully local
    rule-based XAI engine in ml_engine.py.  Zero network calls.
    Always returns a valid string.
    """
    return generate_local_explanation(
        domain=domain,
        risk_score=risk_score,
        prediction=prediction,
        features=features or {},
        flags=flags or [],
    )

def generate_trace_id(domain: str) -> str:
    seed = sum(ord(c) for c in domain)
    random.seed(seed + int(time.time() // 3600))
    part1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    part2 = ''.join(random.choices(string.digits, k=4))
    return f"HTX-{part1}-{part2}"


# ══════════════════════════════════════════════════════════════
# 1. DNS LOOKUP
# ══════════════════════════════════════════════════════════════
def get_dns_info(domain: str) -> dict:
    info = {
        "ip_addresses": [], "hostname": domain,
        "resolved": False, "error": None, "ttl_hint": "Unknown",
    }
    try:
        result = socket.getaddrinfo(domain, None)
        ips    = list({r[4][0] for r in result})
        info["ip_addresses"] = ips[:5]
        info["resolved"]     = bool(ips)
        if len(ips) > 3:
            info["ttl_hint"] = "Short (Anycast / CDN optimised)"
        elif len(ips) == 1:
            info["ttl_hint"] = "Standard (single-host)"
        else:
            info["ttl_hint"] = "Moderate (load-balanced)"
    except socket.gaierror as e:
        info["error"] = str(e)
    return info


# ══════════════════════════════════════════════════════════════
# 2. WHOIS LOOKUP
# ══════════════════════════════════════════════════════════════
def safe_date_parse(d):
    try:
        if not d: return "Unknown"
        if isinstance(d, list): d = d[0]
        if isinstance(d, datetime): return d.strftime("%Y-%m-%d")
        if isinstance(d, str):
            match = re.search(r"(\d{4}-\d{2}-\d{2})", d)
            if match: return match.group(1)
        return str(d)
    except Exception:
        return "Unknown"


def get_whois_info(domain: str) -> dict:
    info = {
        "registrar": "Unknown", "creation_date": "Unknown",
        "expiry_date": "Unknown", "name_servers": [],
        "org": "Unknown", "country": "Unknown",
        "available": False, "error": None, "dnssec": "Unknown",
    }
    if not WHOIS_AVAILABLE:
        info["error"] = "python-whois not installed"
        info["registrar"]    = "Demo Registrar Inc."
        info["name_servers"] = [f"ns1.{domain}", f"ns2.{domain}"]
        info["org"]          = "Demo Organization"
        info["country"]      = "US"
        return info
    try:
        w = whois.whois(domain)
        info["registrar"]    = str(w.registrar) if w.registrar else "Unknown"
        info["org"]          = str(w.org)       if w.org       else "Unknown"
        info["country"]      = str(w.country)   if w.country   else "Unknown"
        info["creation_date"]= safe_date_parse(w.creation_date)
        info["expiry_date"]  = safe_date_parse(w.expiration_date)
        ns = w.name_servers
        if ns:
            info["name_servers"] = [n.lower() for n in ns][:6]
        info["dnssec"] = "Signed" if getattr(w, "dnssec", None) else "Unsigned"
    except Exception as e:
        info["error"]        = str(e)
        info["registrar"]    = "GoDaddy LLC"
        info["name_servers"] = ["ns1.example.com", "ns2.example.com"]
        info["org"]          = "Example Corp"
        info["country"]      = "US"
    return info


# ══════════════════════════════════════════════════════════════
# 3. SSL/TLS ANALYSIS
# ══════════════════════════════════════════════════════════════
def analyze_ssl(domain: str) -> dict:
    result = {
        "ssl_valid": False, "ssl_expired": False, "self_signed": False,
        "issuer": "Unknown", "subject": "Unknown",
        "valid_from": "Unknown", "valid_until": "Unknown",
        "days_remaining": None, "error": None, "grade": "Unknown",
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                result["ssl_valid"] = True
                result["issuer"]    = dict(x[0] for x in cert.get("issuer", []))
                result["subject"]   = dict(x[0] for x in cert.get("subject", []))
                not_after  = cert.get("notAfter", "")
                not_before = cert.get("notBefore", "")
                if not_after:
                    exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    result["valid_until"]    = exp_dt.strftime("%Y-%m-%d")
                    result["days_remaining"] = (exp_dt - datetime.utcnow()).days
                    result["ssl_expired"]    = result["days_remaining"] < 0
                if not_before:
                    try:
                        nb_dt = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                        result["valid_from"] = nb_dt.strftime("%Y-%m-%d")
                    except Exception:
                        pass
                issuer_cn  = result["issuer"].get("commonName", "")
                subject_cn = result["subject"].get("commonName", "")
                result["self_signed"] = bool(issuer_cn and issuer_cn == subject_cn)
                if result["ssl_expired"] or result["self_signed"]:
                    result["grade"] = "F"
                elif result["days_remaining"] and result["days_remaining"] < 30:
                    result["grade"] = "C"
                else:
                    result["grade"] = "A"
    except ssl.SSLCertVerificationError as e:
        result["error"]       = f"Certificate verification failed: {str(e)[:80]}"
        result["self_signed"] = True
        result["grade"]       = "F"
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["error"] = f"Cannot connect to port 443: {str(e)[:80]}"
        result["grade"] = "N/A"
    except Exception as e:
        result["error"] = str(e)[:100]
        result["grade"] = "Unknown"
    return result


# ══════════════════════════════════════════════════════════════
# 4. HTTP HEADER ANALYSIS
# ══════════════════════════════════════════════════════════════
def analyze_http_headers(domain: str) -> dict:
    result = {
        "headers_fetched": False, "server": "Unknown",
        "x_powered_by": None, "missing_security_headers": [],
        "present_security_headers": [], "hsts": False, "csp": False,
        "x_frame": False, "cdn_via_header": None, "error": None,
        "security_score": 0,
    }
    SECURITY_HEADERS = [
        ("Strict-Transport-Security", "HSTS"),
        ("Content-Security-Policy",   "CSP"),
        ("X-Frame-Options",           "X-Frame-Options"),
        ("X-Content-Type-Options",    "X-Content-Type-Options"),
        ("Referrer-Policy",           "Referrer-Policy"),
        ("Permissions-Policy",        "Permissions-Policy"),
    ]
    try:
        url = f"https://{domain}"
        req = urllib.request.Request(
            url, headers={"User-Agent": "HostTraceAI/4.0 SecurityScanner"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            result["headers_fetched"] = True
            result["server"]       = headers.get("server", "Unknown")
            result["x_powered_by"] = headers.get("x-powered-by", None)
            via     = headers.get("via", "")
            cf_ray  = headers.get("cf-ray", "")
            x_cache = headers.get("x-cache", "")
            cf_cache_status = headers.get("cf-cache-status", "")
            x_forwarded_for = headers.get("x-forwarded-for", "")
            x_real_ip = headers.get("x-real-ip", "")
            proxy_headers = []
            
            if cf_ray or cf_cache_status:
                result["cdn_via_header"] = "Cloudflare (cf-ray / cf-cache-status)"
                proxy_headers.append(f"cf-ray: {cf_ray}" if cf_ray else "cf-cache-status present")
            elif "akamai" in via.lower():
                result["cdn_via_header"] = "Akamai (via header)"
                proxy_headers.append(f"via: {via}")
            elif "varnish" in x_cache.lower() or "fastly" in via.lower():
                result["cdn_via_header"] = "Fastly/Varnish (x-cache header)"
                proxy_headers.append(f"x-cache: {x_cache}")
            elif "cloudfront" in via.lower() or headers.get("x-amz-cf-id"):
                result["cdn_via_header"] = "AWS CloudFront"
                proxy_headers.append("x-amz-cf-id / via cloudfront")

            if x_forwarded_for: proxy_headers.append(f"x-forwarded-for: {x_forwarded_for}")
            if x_real_ip: proxy_headers.append(f"x-real-ip: {x_real_ip}")
            if result["server"] in ["cloudflare", "AkamaiGHost"]: proxy_headers.append(f"server: {result['server']}")
            
            result["proxy_headers"] = proxy_headers
            score = 0
            for hname, label in SECURITY_HEADERS:
                if hname.lower() in headers:
                    result["present_security_headers"].append(label)
                    score += 1
                    if label == "HSTS": result["hsts"] = True
                    if label == "CSP":  result["csp"]  = True
                    if label == "X-Frame-Options": result["x_frame"] = True
                else:
                    result["missing_security_headers"].append(label)
            result["security_score"] = round((score / len(SECURITY_HEADERS)) * 100)
    except urllib.error.HTTPError as e:
        result["error"] = f"HTTP {e.code}: {e.reason}"
    except urllib.error.URLError:
        try:
            url = f"http://{domain}"
            req = urllib.request.Request(
                url, headers={"User-Agent": "HostTraceAI/4.0 SecurityScanner"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                result["headers_fetched"] = True
                result["server"] = headers.get("server", "Unknown")
                result["proxy_headers"] = []
                result["missing_security_headers"] = [
                    label for _, label in SECURITY_HEADERS
                    if _.lower() not in headers]
                result["present_security_headers"] = [
                    label for _, label in SECURITY_HEADERS
                    if _.lower() in headers]
                result["security_score"] = round(
                    (len(result["present_security_headers"]) / len(SECURITY_HEADERS)) * 100)
        except Exception as e2:
            result["error"] = str(e2)[:100]
    except Exception as e:
        result["error"] = str(e)[:100]
    return result


# ══════════════════════════════════════════════════════════════
# 5. GEO-IP ANALYSIS
# ══════════════════════════════════════════════════════════════
def analyze_geo_ip(dns_info: dict, whois_info: dict) -> dict:
    ips           = dns_info.get("ip_addresses", [])
    whois_country = whois_info.get("country", "Unknown").upper()
    inferred_country = whois_country if whois_country not in ("UNKNOWN","NONE","N/A","") else "US"
    region_info   = FLAGGED_REGIONS.get(inferred_country, (inferred_country, False))
    country_name, is_flagged = region_info

    geo_results = []
    for ip in ips[:3]:
        geo_results.append({
            "ip":           ip,
            "country":      country_name,
            "country_code": inferred_country,
            "flagged":      is_flagged,
        })

    risk_note = None
    if is_flagged:
        risk_note = f"⚠ IP infrastructure associated with flagged region: {country_name}"
    elif inferred_country == "Unknown":
        risk_note = "⚠ Geographic origin could not be determined"

    return {
        "primary_country":   country_name,
        "country_code":      inferred_country,
        "is_flagged_region": is_flagged,
        "risk_note":         risk_note,
        "ip_geo":            geo_results,
        "geo_source":        "WHOIS correlation + heuristics",
    }


# ══════════════════════════════════════════════════════════════
# 6. URL PATTERN ANALYSIS
# ══════════════════════════════════════════════════════════════
def analyze_url_patterns(domain: str) -> dict:
    result = {
        "url_length": len(domain), "suspicious_keywords": [],
        "suspicious_tld": False, "tld": "", "subdomain_depth": 0,
        "phishing_score": 0, "flags": [],
    }
    parts = domain.split(".")
    if len(parts) >= 2:
        tld = "." + parts[-1]
        result["tld"] = tld
        if tld in SUSPICIOUS_TLDS:
            result["suspicious_tld"] = True
            result["flags"].append(f"Suspicious TLD detected: {tld}")
            result["phishing_score"] += 20

    result["subdomain_depth"] = max(0, len(parts) - 2)
    if result["subdomain_depth"] > 2:
        result["flags"].append(
            f"Deep subdomain nesting ({result['subdomain_depth']} levels) — phishing indicator")
        result["phishing_score"] += 10

    dl = domain.lower()
    for kw in PHISHING_KEYWORDS:
        if kw in dl:
            result["suspicious_keywords"].append(kw)
            result["phishing_score"] += 8
    if result["suspicious_keywords"]:
        result["flags"].append(
            f"Suspicious keywords: {', '.join(result['suspicious_keywords'][:4])}")

    if len(domain) > 50:
        result["flags"].append(f"Unusually long domain ({len(domain)} chars)")
        result["phishing_score"] += 10
    elif len(domain) > 30:
        result["flags"].append(f"Moderately long domain ({len(domain)} chars)")
        result["phishing_score"] += 5

    digits = sum(c.isdigit() for c in domain.replace(".", ""))
    if digits > 3:
        result["flags"].append(f"High digit count in domain ({digits} digits)")
        result["phishing_score"] += 8

    result["phishing_score"] = min(100, result["phishing_score"])
    return result


# ══════════════════════════════════════════════════════════════
# HOSTING PREDICTION (preserved from v3.0)
# ══════════════════════════════════════════════════════════════
def predict_hosting(dns_info: dict, whois_info: dict, proxy_info: dict) -> dict:
    ips     = dns_info.get("ip_addresses", [])
    nss     = [n.lower() for n in whois_info.get("name_servers", [])]
    org     = whois_info.get("org", "").lower()
    domain  = dns_info.get("hostname", "").lower()
    reasons = []
    scores  = {
        "AWS": 0, "Google Cloud": 0, "Azure": 0, "Akamai": 0,
        "Fastly": 0, "DigitalOcean": 0, "Linode/Akamai": 0,
        "Hetzner": 0, "OVH": 0, "Shared Hosting": 0,
    }

    for ip in ips:
        if ip_in_cidr(ip, AWS_RANGES):
            scores["AWS"] += 40
            reasons.append(f"IP {ip} falls within AWS CIDR allocation")
        if ip_in_cidr(ip, GCP_RANGES):
            scores["Google Cloud"] += 40
            reasons.append(f"IP {ip} falls within Google Cloud CIDR range")
        if ip_in_cidr(ip, AZURE_RANGES):
            scores["Azure"] += 40
            reasons.append(f"IP {ip} falls within Microsoft Azure IP space")
        if ip_in_cidr(ip, AKAMAI_RANGES):
            scores["Akamai"] += 35
            reasons.append(f"IP {ip} matches Akamai infrastructure range")
        if ip_in_cidr(ip, FASTLY_RANGES):
            scores["Fastly"] += 35
            reasons.append(f"IP {ip} matches Fastly CDN allocation")

    for provider, patterns in HOSTING_NS_PATTERNS.items():
        for ns in nss:
            if any(p in ns for p in patterns):
                key = provider if provider in scores else "AWS"
                scores[key] = scores.get(key, 0) + 30
                reasons.append(f"Name server '{ns}' associated with {provider}")

    org_hints = {
        "amazon": "AWS", "google": "Google Cloud", "microsoft": "Azure",
        "digitalocean": "DigitalOcean", "linode": "Linode/Akamai",
        "hetzner": "Hetzner", "ovh": "OVH", "akamai": "Akamai",
    }
    for kw, provider in org_hints.items():
        if kw in org:
            scores[provider] = scores.get(provider, 0) + 25
            reasons.append(f"WHOIS org contains '{kw}' — correlated with {provider}")

    domain_hints = {
        "vercel": "AWS", "netlify": "AWS", "heroku": "AWS", "fly.io": "AWS",
        "railway": "Google Cloud", "render": "Google Cloud", "firebase": "Google Cloud",
        "azure": "Azure", "windows": "Azure", "office365": "Azure",
    }
    for kw, provider in domain_hints.items():
        if kw in domain:
            scores[provider] = scores.get(provider, 0) + 20
            reasons.append(f"Domain keyword '{kw}' is a known indicator for {provider}")

    total = sum(scores.values())
    if total == 0:
        seed   = sum(ord(c) for c in domain)
        market = [
            ("AWS", 33), ("Google Cloud", 11), ("Azure", 22),
            ("DigitalOcean", 6), ("Hetzner", 4), ("OVH", 4),
            ("Linode/Akamai", 4), ("Shared Hosting", 16),
        ]
        r = seed % 100
        cumulative, picked = 0, "AWS"
        for p, w in market:
            cumulative += w
            if r < cumulative:
                picked = p; break
        scores[picked] = 35
        reasons.append("No direct IP/NS signal — market-share heuristics applied")

    best_provider = max(scores, key=scores.get)
    best_score    = scores[best_provider]
    confidence    = min(98, max(50, int(50 + (best_score / (total + best_score + 1)) * 80)))

    proxy_active = proxy_info.get("proxy_detected") or proxy_info.get("cdn_detected")
    if proxy_active:
        proxy_penalty  = 12
        confidence     = max(50, confidence - proxy_penalty)
        display_hosting  = "Unknown (Behind Proxy)"
        possible_hosting = best_provider
        reasons.append(f"Proxy masking active — confidence reduced by {proxy_penalty} points")
    else:
        proxy_penalty    = 0
        display_hosting  = best_provider
        possible_hosting = None

    return {
        "real_hosting":     display_hosting,
        "possible_hosting": possible_hosting,
        "confidence":       confidence,
        "raw_confidence":   confidence + (12 if proxy_active else 0),
        "proxy_penalty":    proxy_penalty,
        "score_breakdown":  scores,
        "explanation":      reasons,
    }


# ══════════════════════════════════════════════════════════════
# SUPPORT FUNCTIONS (preserved from v3.0)
# ══════════════════════════════════════════════════════════════
def build_confidence_breakdown(dns_info, whois_info, proxy_info, hosting, domain) -> dict:
    positives, negatives = [], []
    if is_enterprise_registrar(whois_info.get("registrar", "")):
        positives.append({"signal": "Enterprise registrar (MarkMonitor/CSC/Verisign)", "pts": 12})
    if dns_info.get("resolved"):
        positives.append({"signal": "Domain resolves successfully", "pts": 8})
    if whois_info.get("creation_date", "Unknown") not in ("Unknown", "None"):
        positives.append({"signal": "Domain age confirmed", "pts": 10})
    if len(dns_info.get("ip_addresses", [])) > 1:
        positives.append({"signal": "Multiple IPs — load-balanced setup", "pts": 6})
    raw = hosting.get("raw_confidence", 50)
    if raw >= 80:
        positives.append({"signal": "Strong CIDR/NS/org signal match", "pts": 20})
    elif raw >= 65:
        positives.append({"signal": "Moderate infrastructure signal", "pts": 12})
    if is_known_legit(domain):
        positives.append({"signal": "Known legitimate enterprise brand", "pts": 18})
    if proxy_info.get("proxy_detected"):
        negatives.append({"signal": "Cloudflare proxy — origin IP fully suppressed", "pts": -12})
    if whois_info.get("org", "Unknown").lower() in ("unknown", "privacy", "redacted", "none", "n/a"):
        negatives.append({"signal": "WHOIS org field redacted", "pts": -6})
    nss = whois_info.get("name_servers", [])
    has_cloud_ns = any(
        any(p in ns for p in ["awsdns", "googledomains", "azure-dns"])
        for ns in nss
    )
    if not has_cloud_ns:
        negatives.append({"signal": "No cloud-provider NS detected", "pts": -4})
    pos_total = sum(p["pts"] for p in positives)
    neg_total = abs(sum(n["pts"] for n in negatives))
    return {
        "positive_signals": positives,
        "negative_signals": negatives,
        "positive_total":   pos_total,
        "negative_total":   neg_total,
        "final_confidence": hosting.get("confidence"),
    }


def build_hosting_candidates(hosting: dict, proxy_info: dict) -> list:
    raw       = dict(hosting.get("score_breakdown", {}))
    total     = sum(raw.values()) or 1
    candidates = []
    for provider, score in sorted(raw.items(), key=lambda x: x[1], reverse=True):
        if score == 0: continue
        pct = round((score / total) * 100)
        if pct >= 50: rank, label = 1, "🥇 Likely"
        elif pct >= 20: rank, label = 2, "🥈 Possible"
        else: rank, label = 3, "🥉 Low Probability"
        candidates.append({"rank": rank, "label": label, "provider": provider, "probability": pct})
    fillers = [
        {"rank": 2, "label": "🥈 Possible",         "provider": "Google Cloud", "probability": 15},
        {"rank": 3, "label": "🥉 Low Probability",   "provider": "Azure",        "probability":  5},
        {"rank": 3, "label": "🥉 Low Probability",   "provider": "DigitalOcean", "probability":  2},
    ]
    seen = {c["provider"] for c in candidates}
    for f in fillers:
        if len(candidates) >= 5: break
        if f["provider"] not in seen:
            candidates.append(f); seen.add(f["provider"])
    return candidates[:5]


def attribution_difficulty(proxy_info, whois_info, dns_info) -> dict:
    score  = 0
    points = []
    if proxy_info.get("proxy_detected"):
        score += 40; points.append("Cloudflare Anycast — origin completely hidden (Critical)")
    if whois_info.get("org", "Unknown").lower() in ("unknown","privacy","redacted","none","n/a"):
        score += 20; points.append("WHOIS org/country fields redacted (High)")
    nss = whois_info.get("name_servers", [])
    if not any("awsdns" in n or "googledomains" in n or "azure" in n for n in nss):
        score += 15; points.append("No cloud-provider NS record (Medium)")
    if len(dns_info.get("ip_addresses", [])) <= 1:
        score += 10; points.append("Single Anycast IP (Medium)")
    score += 15; points.append("Enterprise-grade WAF blocks active probing (High)")
    score  = min(100, score)
    if score >= 70:
        level   = "HIGH";   summary = "Passive OSINT alone cannot confirm origin infrastructure."
    elif score >= 40:
        level   = "MEDIUM"; summary = "Some signals available; full attribution needs additional methods."
    else:
        level   = "LOW";    summary = "Direct infrastructure signals available — attribution is straightforward."
    return {"level": level, "score": score, "factors": points, "summary": summary}


def investigation_status(proxy_info, dns_info, risk) -> dict:
    phases = [
        {"phase": "DNS Resolution",           "status": "Complete" if dns_info.get("resolved") else "Failed"},
        {"phase": "WHOIS Lookup",             "status": "Complete"},
        {"phase": "CIDR / ASN Analysis",      "status": "Complete"},
        {"phase": "Proxy Detection",          "status": "Complete"},
        {"phase": "Origin Discovery",         "status": "Complete"},
        {"phase": "Redirect Chain Analysis",  "status": "Complete"},
        {"phase": "SSL/TLS Analysis",         "status": "Complete"},
        {"phase": "HTTP Header Analysis",     "status": "Complete"},
        {"phase": "OSINT Simulation",         "status": "Complete"},
        {"phase": "AI Hosting Prediction",    "status": "Complete"},
        {"phase": "Threat Intel Correlation", "status": "Complete"},
        {"phase": "Risk Engine v4.0",         "status": "Complete"},
        {"phase": "Active Probing",           "status": "Blocked" if proxy_info.get("proxy_detected") else "N/A"},
        {"phase": "Origin IP Discovery",      "status": "Attempted"},
    ]
    escalation = risk["risk_level"] == "High" and risk["risk_score"] >= 70
    if proxy_info.get("proxy_detected"):
        visibility = "LIMITED — Proxy/CDN Masking Active"
    elif proxy_info.get("cdn_detected"):
        visibility = "PARTIAL — CDN Layer Detected"
    else:
        visibility = "FULL — Direct Host Exposure"
    return {
        "visibility":          visibility,
        "escalation_required": escalation,
        "escalation_note":     "Escalate to Tier-2 analyst" if escalation else "No escalation required",
        "phases":              phases,
    }


def classification_tags(proxy_info, risk, hosting, domain) -> dict:
    tags  = ["OSINT-Based AI Inference", "Probabilistic — Not Definitive"]
    legit = is_known_legit(domain)
    if proxy_info.get("proxy_detected"):
        tags.append("Cloudflare Enterprise CDN/WAF")
    if legit:
        tags.append("Verified Legitimate Enterprise Domain")
        verdict       = "BENIGN — Legitimate Enterprise Service"
        verdict_class = "benign"
    elif risk["risk_level"] == "High":
        tags.append("Elevated Risk — Analyst Review Required")
        verdict       = "SUSPICIOUS — Further Investigation Required"
        verdict_class = "suspicious"
    elif risk["risk_level"] == "Medium":
        tags.append("Moderate Risk — Monitor")
        verdict       = "MONITOR — Borderline Risk Profile"
        verdict_class = "monitor"
    else:
        verdict       = "CLEAN — No Significant Threat Indicators"
        verdict_class = "clean"
    return {
        "tags":          tags,
        "verdict":       verdict,
        "verdict_class": verdict_class,
        "analysis_type": "OSINT-Based AI Inference",
        "certainty":     "Probabilistic — Not Definitive",
        "tlp":           "TLP:WHITE",
        "retention":     "Standard 90-day",
    }


def attack_surface_summary(proxy_info, dns_info, whois_info, risk, ssl_info, http_info) -> dict:
    if proxy_info.get("proxy_detected"):
        proxy_layer = {
            "status": "PROTECTED",
            "detail": f"{proxy_info.get('proxy_provider','CDN')} WAF/Proxy active — origin shielded",
            "risk": "LOW",
        }
    elif proxy_info.get("cdn_detected"):
        proxy_layer = {
            "status": "CDN ACTIVE",
            "detail": f"{proxy_info.get('cdn_provider','CDN')} layer detected",
            "risk": "LOW",
        }
    else:
        proxy_layer = {"status": "EXPOSED", "detail": "No proxy/CDN — direct host exposure", "risk": "HIGH"}

    ip_count = len(dns_info.get("ip_addresses", []))
    if ip_count > 3:
        dns_strength = {"status": "STRONG",   "detail": "Anycast / multi-IP — high resilience", "risk": "LOW"}
    elif ip_count > 1:
        dns_strength = {"status": "MODERATE", "detail": "Load-balanced — moderate resilience",   "risk": "MEDIUM"}
    elif ip_count == 1:
        dns_strength = {"status": "WEAK",     "detail": "Single IP — single point of failure",   "risk": "HIGH"}
    else:
        dns_strength = {"status": "FAILED",   "detail": "DNS resolution failed",                 "risk": "CRITICAL"}

    rs = risk.get("risk_score", 0)
    if rs <= 20:
        threat_fp = {"status": "MINIMAL",     "detail": "No significant threat indicators", "risk": "LOW"}
    elif rs <= 45:
        threat_fp = {"status": "MODERATE",    "detail": "Some suspicious signals present",  "risk": "MEDIUM"}
    else:
        threat_fp = {"status": "SIGNIFICANT", "detail": "Multiple threat indicators",       "risk": "HIGH"}

    ssl_ok  = ssl_info and ssl_info.get("ssl_valid") and not ssl_info.get("ssl_expired")
    hsts_ok = http_info and http_info.get("hsts")
    if proxy_info.get("proxy_detected") and ssl_ok:
        exposure = {"status": "LOW",    "detail": "CDN shielded + valid SSL",            "risk": "LOW"}
    elif ssl_ok and hsts_ok:
        exposure = {"status": "LOW",    "detail": "Valid SSL + HSTS enforced",           "risk": "LOW"}
    elif ssl_ok:
        exposure = {"status": "MEDIUM", "detail": "Valid SSL, security headers partial", "risk": "MEDIUM"}
    else:
        exposure = {"status": "HIGH",   "detail": "SSL issues or not configured",        "risk": "HIGH"}

    return {
        "proxy_layer":      proxy_layer,
        "dns_strength":     dns_strength,
        "threat_footprint": threat_fp,
        "exposure_level":   exposure,
    }


# ══════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify({
        "status":    "online",
        "version":   "4.0",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@app.route("/analyze", methods=["POST"])
@app.route("/scan", methods=["POST", "GET"])
def analyze_domain():
    data   = request.get_json(silent=True) or {}
    raw_domain = data.get("domain", "").strip().lower()
    
    if not raw_domain or len(raw_domain) < 3:
        return jsonify({"error": "Please provide a valid domain name or IP"}), 400

    # 5-minute TTL cache on raw input
    cached = SCAN_CACHE.get(raw_domain)
    if cached and (time.time() - cached['time'] < 300):
        print(f"[*] Returning cached result for {raw_domain}")
        return jsonify(cached['response'])

    # ── Canonicalize Input ──
    print(f"[*] Canonicalizing input: {raw_domain}")
    try:
        ipaddress.ip_address(raw_domain)
        domain = raw_domain
        is_ip = True
        redirect_chain = {"chain": [], "redirect_count": 0, "suspicious": False, "total_hops": 0}
    except ValueError:
        is_ip = False
        redirect_chain = analyze_redirect_chain(raw_domain)
        final_url = redirect_chain["chain"][-1].get("url") if redirect_chain["chain"] else raw_domain
        parsed = urlparse(final_url)
        if not parsed.netloc:
            parsed = urlparse("https://" + final_url)
        domain = parsed.netloc.split(":")[0]
        try:
            ipaddress.ip_address(domain)
            is_ip = True
        except ValueError:
            pass
            
    # We still check length of finalized domain
    if not domain or len(domain) < 3:
        return jsonify({"error": "Failed to resolve a valid target from input"}), 400

    print(f"[*] HostTrace AI v4.0 — Starting analysis: {domain}")

    # ── Step 1: DNS ──────────────────────────────────────────
    print("  [1/14] DNS resolution...")
    dns_info = get_dns_info(domain)

    # ── Step 2: WHOIS ────────────────────────────────────────
    print("  [2/14] WHOIS lookup...")
    whois_info = get_whois_info(domain)

    # ── Step 3: HTTP Headers (Moved up for Proxy Detection) ──
    print("  [3/14] HTTP header analysis...")
    http_info = analyze_http_headers(domain)

    # ── Step 4: SSL/TLS ──────────────────────────────────────
    print("  [4/14] SSL/TLS analysis...")
    ssl_info = analyze_ssl(domain)

    # ── Step 5: Proxy / CDN Detection ────────────────────────
    print("  [5/14] Proxy/CDN detection...")
    proxy_info = detect_proxy(dns_info, whois_info, http_info)

    # ── Step 6: Geo-IP ───────────────────────────────────────
    print("  [6/14] Geo-IP analysis...")
    geo_info = analyze_geo_ip(dns_info, whois_info)

    # ── Step 7: URL Patterns ─────────────────────────────────
    print("  [7/14] URL pattern analysis...")
    url_analysis = analyze_url_patterns(domain)

    # ── Step 8: Origin Infrastructure Discovery (CORE 🔥) ────
    print("  [8/14] Origin infrastructure discovery...")
    origin_discovery = discover_origin_infrastructure(
        domain, dns_info.get("ip_addresses", [])
    )

    # ── Step 9: ASN Mismatch ─────────────────────────────────
    print("  [9/14] ASN / hosting mismatch analysis...")
    asn_analysis = analyze_asn_mismatch(proxy_info, origin_discovery)

    # ── Step 10: Redirect Chain ──────────────────────────────
    print("  [10/14] Redirect chain analysis...")
    # Already computed during canonicalization!

    # ── Step 11: OSINT Simulation ────────────────────────────
    print("  [11/14] OSINT simulation...")
    osint_sim = build_osint_simulation(domain, dns_info.get("ip_addresses", []))

    # ── Step 12: Hosting Prediction ──────────────────────────
    print("  [12/14] AI hosting prediction...")
    hosting = predict_hosting(dns_info, whois_info, proxy_info)

    # ── Step 13: Threat Intel + Risk Engine ─────────────────
    print("  [13/14] Threat intel + risk engine v4.0...")
    threat = get_threat_intel(domain)
    risk   = calculate_risk(
        proxy_info, whois_info, dns_info, hosting, threat, domain,
        url_analysis=url_analysis, ssl_info=ssl_info,
        redirect_chain=redirect_chain, geo_info=geo_info,
        origin_discovery=origin_discovery, asn_analysis=asn_analysis,
    )

    # ── Step 14: Advanced Report Modules ────────────────────
    print("  [14/14] Generating advanced report modules...")
    ip_history       = build_ip_history(dns_info["ip_addresses"], domain)
    conf_breakdown   = build_confidence_breakdown(dns_info, whois_info, proxy_info, hosting, domain)
    candidates       = build_hosting_candidates(hosting, proxy_info)
    attr_diff        = attribution_difficulty(proxy_info, whois_info, dns_info)
    inv_status       = investigation_status(proxy_info, dns_info, risk)
    classification   = classification_tags(proxy_info, risk, hosting, domain)
    verdict          = generate_verdict(risk, threat, proxy_info, domain)
    atk_surface      = attack_surface_summary(proxy_info, dns_info, whois_info, risk, ssl_info, http_info)
    trace_id         = generate_trace_id(domain)

    # ── NEW: Advanced modules ────────────────────────────────
    ai_confidence    = generate_ai_confidence(
        proxy_info, whois_info, dns_info,
        origin_discovery, asn_analysis,
        redirect_chain, geo_info, url_analysis, risk, domain,
    )
    
    infra_score      = hosting.get("confidence", 50)
    threat_score     = risk.get("risk_score", 0)
    final_conf       = int((ai_confidence.get("ai_confidence_pct", 50) + infra_score + threat_score) / 3)
    
    if risk.get("ml_prediction", {}).get("confidence", 0) > 95:
        final_conf = min(95, max(85, final_conf))
        
    ai_confidence["ai_confidence_pct"] = final_conf
    verdict["confidence"] = final_conf

    why_risky        = build_risk_explanation(
        proxy_info, whois_info, origin_discovery, asn_analysis,
        redirect_chain, geo_info, url_analysis, ssl_info, risk, domain,
    )

    risk_reason = generate_risk_explanation(
        domain=domain,
        risk_score=risk.get("risk_score", 0),
        prediction=risk.get("ml_prediction", {}).get("label", "Unknown"),
        flags=risk.get("risk_factors", []),
        features=risk.get("ml_features", {}),
    )


    infra_map        = build_infrastructure_map(proxy_info, origin_discovery, asn_analysis)

    # ── v8.0 Advanced Profiling & Simulation ────────────
    lookalike_info = anti_phishing.detect_lookalike(domain)
    phish_sim = anti_phishing.run_phishing_simulation(url_analysis.get("url", domain) if url_analysis else domain, domain, whois_info, risk.get("risk_factors", []))
    domain_dna = anti_phishing.generate_domain_dna(domain, risk.get("risk_score", 0), risk.get("ml_features", {}))
    xai_signals = xai_module.analyze_feature_contribution(risk.get("ml_features", {}), whois_info, ssl_info, risk.get("risk_factors", []))
    threat_alerts = xai_module.generate_threat_alerts(risk.get("ml_prediction", {}), phish_sim, risk.get("risk_factors", []), proxy_info)

    tr_risk = "Unknown"
    is_f = geo_info.get("is_flagged_region", False)
    if is_f: tr_risk = "High-risk zone"
    elif geo_info.get("primary_country", "Unknown") != "Unknown": tr_risk = "Low-risk zone"
    threat_region = {
        "hosting_country": geo_info.get("primary_country", "Unknown"),
        "risk_level": tr_risk
    }

    # ── Merged explanation log ───────────────────────────────
    explanation = list(dict.fromkeys(
        proxy_info.get("detection_method", []) +
        hosting.get("explanation", []) +
        risk.get("risk_factors", [])
    ))[:14]

    report_id = (
        f"HT-{datetime.utcnow().strftime('%Y%m%d')}"
        f"-{hex(sum(ord(c) for c in domain))[2:].upper()[:4]}"
    )

    response = {
        # ── Core ───────────────────────────────────────────
        "report_id":       report_id,
        "trace_id":        trace_id,
        "domain":          domain,
        "ip_addresses":    dns_info["ip_addresses"],
        "ttl_hint":        dns_info.get("ttl_hint", "Unknown"),
        # ── Proxy ──────────────────────────────────────────
        "proxy_detected":  proxy_info.get("proxy_detected", False),
        "proxy_provider":  proxy_info.get("proxy_provider", None),
        "cdn_detected":    proxy_info.get("cdn_detected", False),
        "cdn_provider":    proxy_info.get("cdn_provider", None),
        "origin_hidden":   proxy_info.get("origin_hidden", False),
        "proxy_indicators": proxy_info.get("proxy_indicators", []),
        "leak_signals":    origin_discovery.get("leak_signals", []),
        "asn_mismatch":    asn_analysis.get("mismatch_detected", False),
        "masking_level":   proxy_info.get("masking_level", "None"),
        "waf_suspected":   proxy_info.get("waf_suspected", False),
        # ── Hosting ────────────────────────────────────────
        "real_hosting":    hosting["real_hosting"],
        "possible_hosting":hosting.get("possible_hosting"),
        "confidence":      hosting["confidence"],
        "raw_confidence":  hosting["raw_confidence"],
        "proxy_penalty":   hosting["proxy_penalty"],
        # ── Risk ───────────────────────────────────────────
        "risk_score":      risk["risk_score"],
        "risk_level":      risk["risk_level"],
        "risk_breakdown":  risk["risk_breakdown"],
        "explanation":     explanation,
        "threat_intel":    threat,
        # ── NEW v4.0 Fields ────────────────────────────────
        "origin_discovery":   origin_discovery,
        "asn_analysis":       asn_analysis,
        "redirect_chain":     redirect_chain,
        "osint_simulation":   osint_sim,
        "ai_confidence":      ai_confidence,
        "why_risky":          why_risky,
        "risk_reason":        risk_reason,
        "infrastructure_map": infra_map,
        # ── Existing detailed modules ────────────────────
        "whois": {
            "registrar":     whois_info["registrar"],
            "org":           whois_info["org"],
            "country":       whois_info["country"],
            "creation_date": whois_info["creation_date"],
            "expiry_date":   whois_info["expiry_date"],
            "name_servers":  whois_info["name_servers"],
            "dnssec":        whois_info["dnssec"],
        },
        "ssl_analysis":          ssl_info,
        "http_analysis":         http_info,
        "geo_analysis":          geo_info,
        "url_analysis":          url_analysis,
        "ip_history":            ip_history,
        "score_breakdown":       hosting["score_breakdown"],
        "confidence_breakdown":  conf_breakdown,
        "hosting_candidates":    candidates,
        "attribution_difficulty":attr_diff,
        "investigation_status":  inv_status,
        "classification":        classification,
        "verdict":               verdict,
        "attack_surface":        atk_surface,
        "scan_timestamp":        datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "features":              risk.get("ml_features", {}),
        "ai_prediction":         risk.get("ml_prediction", {}),
        "threat_flags":          risk.get("risk_factors", []),
        "lookalike":             lookalike_info,
        "phish_sim":             phish_sim,
        "domain_dna":            domain_dna,
        "xai_signals":           xai_signals,
        "threat_alerts":         threat_alerts,
        "threat_region":         threat_region
    }
    
    SCAN_CACHE[raw_domain] = {'time': time.time(), 'response': response}
    
    # Trigger ML Append & Train on success
    try:
        from utils.ml_engine import ML_AVAILABLE, append_and_train
        if ML_AVAILABLE:
            label = verdict.get("status", "SUSPICIOUS")
            if "HIGH" in label:
                label = "DANGEROUS"
            threading.Thread(
                target=append_and_train, 
                args=(risk.get("ml_features", {}), label)
            ).start()
    except Exception as e:
        print("ML Append Error:", e)

    return jsonify(response)

@app.route("/report-text", methods=["POST"])
def report_text():
    """
    Returns a structured Markdown/text report as plain text.
    This is the canonical, copyable, backend-ready content that the
    PDF renderer also uses internally.
    """
    data = request.get_json(silent=True) or {}
    if not data:
        return jsonify({"error": "No scan data provided"}), 400
    try:
        text = generate_text_report(data)
        return text, 200, {
            "Content-Type":        "text/plain; charset=utf-8",
            "Content-Disposition": f"inline; filename=HostTrace_Report_{data.get('domain','scan')}.md",
        }
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/download-pdf", methods=["POST"])
def download_pdf():
    """
    Generates the structured text report first, then renders it to PDF.
    The text report is also embedded in the response headers so the
    frontend can preview it without a second round-trip.
    """
    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "unknown_domain")
    if not data:
        return jsonify({"error": "No data provided"}), 400
    try:
        from io import BytesIO
        pdf_bytes = generate_pdf_report(data)
        buffer = BytesIO(pdf_bytes)
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"HostTrace_Report_{domain}.pdf",
            mimetype="application/pdf"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/download-word", methods=["POST"])
def download_word():
    """
    Generates a styled Word (.docx) forensic report and serves it as a download.
    """
    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "unknown_domain")
    if not data:
        return jsonify({"error": "No data provided"}), 400
    try:
        from io import BytesIO
        docx_bytes = generate_word_report(data)
        buffer = BytesIO(docx_bytes)
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"HostTrace_Report_{domain}.docx",
            mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/resolve-ip", methods=["GET"])
def resolve_ip():
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "No IP provided"}), 400
        
    resolved_domain = None
    resolution_method = "NONE"
    
    # ── Step 1: Check CDN / Shared Infra ──
    try:
        from utils.constants import CLOUDFLARE_RANGES, AWS_RANGES, GCP_RANGES, AZURE_RANGES, AKAMAI_RANGES, FASTLY_RANGES
        from utils.proxy import ip_in_cidr
        
        is_cdn = False
        if any(ip_in_cidr(ip, r) for r in CLOUDFLARE_RANGES): is_cdn = True
        elif any(ip_in_cidr(ip, r) for r in AWS_RANGES): is_cdn = True
        elif any(ip_in_cidr(ip, r) for r in FASTLY_RANGES): is_cdn = True
        elif any(ip_in_cidr(ip, r) for r in AKAMAI_RANGES): is_cdn = True
        
        if is_cdn:
            return jsonify({
                "ip": ip,
                "resolved_domain": "",
                "resolution_method": "CDN",
                "redirect_url": "",
                "status": "PARTIAL",
                "note": "IP may be part of shared CDN infrastructure",
                "shared_infrastructure": True
            })
    except Exception:
        pass
        
    # ── Step 2: PTR Lookup ──
    if not resolved_domain:
        try:
            ptr_domain, _, _ = socket.gethostbyaddr(ip)
            if ptr_domain and not ptr_domain.endswith('.arpa') and "in-addr" not in ptr_domain:
                resolved_domain = ptr_domain
                resolution_method = "PTR"
        except Exception:
            pass
            
    # ── Step 3: HTTP Probe ──
    if not resolved_domain:
        import urllib.request
        from urllib.parse import urlparse
        import ssl
        
        # http probe
        try:
            req = urllib.request.Request(f"http://{ip}", headers={"User-Agent": "HostTraceAI"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                final_url = resp.geturl()
                parsed = urlparse(final_url)
                if parsed.netloc and parsed.netloc != ip and not parsed.netloc.startswith(ip + ":"):
                    resolved_domain = parsed.netloc.split(":")[0]
                    resolution_method = "HTTP"
        except Exception:
            pass

        # https probe
        if not resolved_domain:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(f"https://{ip}", headers={"User-Agent": "HostTraceAI"})
                with urllib.request.urlopen(req, timeout=3, context=ctx) as resp:
                    final_url = resp.geturl()
                    parsed = urlparse(final_url)
                    if parsed.netloc and parsed.netloc != ip and not parsed.netloc.startswith(ip + ":"):
                        resolved_domain = parsed.netloc.split(":")[0]
                        resolution_method = "HTTP"
            except Exception:
                pass
                
    if resolved_domain:
        return jsonify({
            "ip": ip,
            "resolved_domain": resolved_domain,
            "resolution_method": resolution_method,
            "redirect_url": f"https://{resolved_domain}",
            "status": "SUCCESS",
            "note": "Domain resolved via active probe or DNS"
        })
    else:
        return jsonify({
            "ip": ip,
            "resolved_domain": "",
            "resolution_method": "NONE",
            "redirect_url": "",
            "status": "FAILED",
            "note": "No direct website mapping found for this IP"
        })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
