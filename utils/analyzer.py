"""
utils/analyzer.py
Advanced risk engine, verdict, AI confidence module, and explainable output.
HostTrace AI v4.0
"""

import re
from datetime import datetime
from utils.constants import (
    SUSPICIOUS_TLDS, TRUSTED_REGISTRARS, ENTERPRISE_REGISTRARS,
    KNOWN_LEGIT_PATTERNS, PHISHING_KEYWORDS,
)
import utils.ml_engine as ml_engine


# ══════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════
def is_known_legit(domain: str) -> bool:
    d = domain.lower()
    return any(p in d for p in KNOWN_LEGIT_PATTERNS)


def is_enterprise_registrar(registrar: str) -> bool:
    r = registrar.lower()
    return any(e in r for e in ENTERPRISE_REGISTRARS)


# ══════════════════════════════════════════════════════════════
# ADVANCED RISK ENGINE  (updated weights v4.0)
# ══════════════════════════════════════════════════════════════
def calculate_risk(
    proxy_info,    whois_info,   dns_info,     hosting,
    threat,        domain,       url_analysis=None, ssl_info=None,
    redirect_chain=None, geo_info=None,
    origin_discovery=None, asn_analysis=None,
) -> dict:
    """
    Updated risk scoring with new v4.0 weights:
        Proxy detected         → +10
        Hidden origin          → +20
        Domain age < 30 days   → +30  (< 90d → +15, < 365d → +8)
        Login page keywords    → +15
        Suspicious keywords    → +8
        Redirect chain > 2     → +10  (NEW)
        Geo mismatch           → +10  (NEW)
        Hosting mismatch       → +15  (NEW)
    Score normalised to 0–100.
    """
    risk    = 0
    factors = []
    legit   = is_known_legit(domain)
    ent_reg = is_enterprise_registrar(whois_info.get("registrar", ""))

    trusted_domains = ["google.com", "amazon.com", "microsoft.com", "cloudflare.com", "github.com", "discord.com"]
    domain_lower = domain.lower()
    is_trusted = any(domain_lower == td or domain_lower.endswith("." + td) for td in trusted_domains)

    rb = {
        "proxy_risk":         0,
        "cdn_risk":           0,
        "proxy_headers":      0,
        "hidden_origin":      0,
        "blacklist_hits":     0,
        "suspicious_tld":     0,
        "new_domain":         0,
        "login_keywords":     0,
        "redirect_chain":     0,
        "suspicious_dns":     0,
        "geo_mismatch":       0,
        "hosting_mismatch":   0,
        "trusted_registrar":  0,
        "clean_threat_intel": 0,
        "ssl_risk":           0,
        "url_pattern_risk":   0,
    }

    # ── 1. Proxy Risk ───────────────────────────────────
    if proxy_info.get("cdn_detected"):
        pts = 20; risk += pts; rb["cdn_risk"] = pts
        factors.append(f"CDN protection detected (+{pts})")
    elif proxy_info.get("proxy_detected"):
        pts = 20; risk += pts; rb["proxy_risk"] = pts
        factors.append(f"Reverse proxy detected (+{pts})")
        
    if proxy_info.get("proxy_indicators"):
        pts = 20; risk += pts; rb["proxy_headers"] = pts
        factors.append(f"Proxy indicators in HTTP headers (+{pts})")
        
    # ── 2. Hidden Origin (+20) ── NEW ───────────────────────────
    if origin_discovery and origin_discovery.get("origin_suspected"):
        n = len(origin_discovery.get("possible_origin_ips", []))
        if legit or is_trusted:
            factors.append("INFO: Multiple backend IPs detected (normal for distributed infrastructure)")
        else:
            factors.append(
                f"Backend infrastructure mapping (informational) — {n} possible IP(s) detected"
            )
    
    if proxy_info.get("origin_hidden"):
        pts = 20; risk += pts; rb["hidden_origin"] = pts
        factors.append(f"Hidden origin signals — origin IP shielded (+{pts})")

    # ── 3. Blacklist / VT hits ─────────────────────────────────
    blk = threat.get("blacklist_hits", 0)
    vt  = threat.get("virustotal_flags", 0)
    if blk > 3:
        pts = 40; risk += pts; rb["blacklist_hits"] = pts
        factors.append(f"Multiple blacklist hits: {blk} (+{pts})")
    elif blk > 0:
        pts = blk * 8; risk += pts; rb["blacklist_hits"] = pts
        factors.append(f"Blacklist hits: {blk} (+{pts})")
    if vt > 5:
        risk += 20; factors.append(f"High VirusTotal detection: {vt} engines (+20)")
    elif vt > 0:
        pts = min(vt * 2, 8); risk += pts
        factors.append(f"VirusTotal: {vt} flags (+{pts})")

    # ── 4. Suspicious TLD (+20) ───────────────────────────────
    if url_analysis and url_analysis.get("suspicious_tld"):
        risk += 20; rb["suspicious_tld"] = 20
        factors.append(
            f"Suspicious TLD '{url_analysis.get('tld')}' — high-abuse domain (+20)"
        )

    # ── 5. Domain Age (< 180 days -> +25 points)
    creation_date = whois_info.get("creation_date", "Unknown")
    if creation_date not in ("Unknown", "None"):
        try:
            cd_dt    = datetime.strptime(creation_date, "%Y-%m-%d")
            age_days = (datetime.utcnow() - cd_dt).days
            if age_days < 180:
                risk += 25; rb["new_domain"] = 25
                factors.append(f"Recent domain registration ({age_days}d old) (+25)")
        except Exception:
            pass

    # ── 6. Phishing Indicators
    if url_analysis:
        kws      = url_analysis.get("suspicious_keywords", [])
        login_kw = [
            k for k in kws
            if k in ("login", "verify", "secure", "update", "bank", "free", "gift")
        ]
        if login_kw:
            pts = 15; risk += pts; rb["login_keywords"] = pts
            factors.append(
                f"Phishing keywords detected: {', '.join(login_kw[:3])} (+{pts})"
            )
            
    # ── Real Threat URL Structure
    if len(domain) > 75:
        risk += 10; rb["url_pattern_risk"] += 10
        factors.append("Suspiciously long URL length (>75 chars) (+10)")
    if domain.count('-') > 1:
        risk += 10; rb["url_pattern_risk"] += 10
        factors.append("Multiple hyphens in domain string (+10)")
    if re.search(r'[0-9]{4,}|[a-zA-Z0-9]{15,}', domain.split('.')[0]):
        risk += 15; rb["url_pattern_risk"] += 15
        factors.append("Random string patterns detected (+15)")

    # ── 7. Redirect Chain (+10) ── NEW ─────────────────────────
    if redirect_chain and redirect_chain.get("suspicious"):
        pts = 10; risk += pts; rb["redirect_chain"] = pts
        cnt = redirect_chain.get("redirect_count", 0)
        factors.append(f"Suspicious redirect chain — {cnt} redirects detected (>3 hops) (+{pts})")

    # ── 8. Geo Mismatch (+10) ── NEW ───────────────────────────
    if geo_info and geo_info.get("is_flagged_region"):
        pts = 10; risk += pts; rb["geo_mismatch"] = pts
        factors.append(
            f"IP geo-location in flagged region: {geo_info.get('primary_country','?')} (+{pts})"
        )

    # ── 9. Hosting Mismatch (+15) ── NEW ───────────────────────
    if asn_analysis and asn_analysis.get("mismatch_detected"):
        pts = 15; risk += pts; rb["hosting_mismatch"] = pts
        factors.append(
            f"Hosting provider/ASN mismatch detected (+{pts})"
        )

    # ── 10. WHOIS org redacted ─────────────────────────────────
    org = whois_info.get("org", "Unknown").lower()
    if org in ("unknown", "privacy", "redacted", "none", "n/a", "domains by proxy"):
        pts = 10
        risk += pts
        factors.append(
            f"Hidden registrant / WHOIS privacy active (+{pts})"
        )

    # ── 11. Trusted Registrar (−10) ───────────────────────────
    registrar = whois_info.get("registrar", "").lower()
    if any(tr in registrar for tr in TRUSTED_REGISTRARS):
        risk = max(0, risk - 10); rb["trusted_registrar"] = -10
        factors.append("Trusted registrar detected — risk reduced (−10)")

    # ── 12. Clean Threat Intel (−20) ──────────────────────────
    if blk == 0 and vt == 0 and not threat.get("abuse_ch"):
        risk = max(0, risk - 20); rb["clean_threat_intel"] = -20
        factors.append("Clean threat intelligence — no malicious signatures (−20)")

    # ── 13. SSL Risk ───────────────────────────────────────────
    if ssl_info:
        if not ssl_info.get("ssl_valid"):
            if ssl_info.get("ssl_expired"):
                risk += 20; rb["ssl_risk"] += 20
                factors.append("SSL certificate EXPIRED (+20)")
            else:
                risk += 30; rb["ssl_risk"] += 30
                factors.append("No valid SSL detected (+30)")

    # ── 14. DNS failures & Suspicious Patterns ─────────────────
    if len(dns_info.get("ip_addresses", [])) == 0:
        risk += 20; factors.append("DNS resolution failed (+20)")
    elif dns_info.get("ttl_hint") == "Short (Anycast / CDN optimised)" and not proxy_info.get("cdn_detected"):
        pts = 15; risk += pts; rb["suspicious_dns"] = pts
        factors.append(f"Suspicious DNS pattern without known CDN (+{pts})")

    # ── 15. Known-legit correction ─────────────────────────────
    if legit and risk > 30:
        reduction = min(risk - 18, 20)
        risk -= reduction
        factors.append(f"Known legitimate enterprise domain — risk corrected (−{reduction})")

    # ── 16. ML PREDICTION & HYBRID SCORE ───────────────────────
    ml_features = ml_engine.extract_features(domain, domain, whois_info, dict(ssl_info) if ssl_info else {})
    ml_pred = ml_engine.predict_risk(ml_features)
    
    ai_score = ml_pred.get("probabilities", {}).get("DANGEROUS", 0) + (ml_pred.get("probabilities", {}).get("SUSPICIOUS", 0) * 0.5)
    
    final_risk = (risk + ai_score) / 2

    if is_trusted:
        final_risk = min(final_risk, 10)
        factors = ["Trusted enterprise domain. No significant threats detected."]

    final_risk = min(100, max(0, final_risk))
    risk = final_risk
    
    if final_risk >= 61:
        severity = "HIGH"
    elif risk >= 31:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    level = "Low Risk" if risk <= 30 else ("Medium Risk" if risk <= 60 else "High Risk")

    return {
        "risk_score":     int(risk),
        "risk_level":     level,
        "severity":       severity,
        "risk_factors":   factors,
        "risk_breakdown": rb,
        "ml_features":    ml_features,
        "ml_prediction":  ml_pred,
    }


# ══════════════════════════════════════════════════════════════
# VERDICT GENERATOR (preserved from v3.0)
# ══════════════════════════════════════════════════════════════
def generate_verdict(risk: dict, threat: dict, proxy_info: dict, domain: str) -> dict:
    score = risk["risk_score"]
    legit = is_known_legit(domain)

    if score <= 20 or legit:
        status, color, badge = "SAFE", "#00ff9f", "✅ SAFE"
        note = "No significant threat indicators detected. Domain appears legitimate."
    elif score <= 45:
        status, color, badge = "SUSPICIOUS", "#ffd166", "⚠ SUSPICIOUS"
        note = "Moderate risk signals detected. Further investigation recommended."
    else:
        status, color, badge = "HIGH RISK", "#ff4f6d", "🚨 HIGH RISK"
        note = "Multiple high-risk indicators detected. Treat with extreme caution."

    return {
        "status":     status,
        "badge":      badge,
        "color":      color,
        "note":       note,
    }


# ══════════════════════════════════════════════════════════════
# AI CONFIDENCE MODULE  (NEW)
# ══════════════════════════════════════════════════════════════
def generate_ai_confidence(
    proxy_info, whois_info, dns_info,
    origin_discovery, asn_analysis, redirect_chain,
    geo_info, url_analysis, risk, domain,
) -> dict:
    """
    Intelligent AI confidence module that weighs all investigation
    signals to predict whether the site exhibits suspicious
    infrastructure patterns.

    Returns:
        ai_confidence_pct      — 0–100%
        infrastructure_pattern — human-readable pattern label
        ai_explanation         — list of signal strings
        summary                — one-sentence verdict
    """
    score = risk.get("risk_score", 0)
    trusted = 10 if (is_known_legit(domain) or any(domain.lower() == td or domain.lower().endswith("." + td) for td in ["google.com", "amazon.com", "microsoft.com", "cloudflare.com", "github.com", "discord.com"])) else 0
    flag_count = len([f for f in risk.get("risk_factors", []) if "(+" in f])
    
    # AI CONFIDENCE OVERRIDE:
    # 100 - risk_score + (trusted_domain_bonus) - (suspicious_flags.count * 5)
    calc_conf = 100 - score + trusted - (flag_count * 5)

    if score == 0:
        confidence = min(95, max(80, calc_conf))
        summary = "No active attack patterns detected"
        pattern = "Normal operation"
    elif score <= 30:
        confidence = min(95, max(70, calc_conf))
        summary = "No active attack patterns detected"
        pattern = "Normal operation"
    elif score <= 70:
        confidence = min(70, max(40, calc_conf))
        summary = "Suspicious infrastructure characteristics observed"
        pattern = "Potential risk patterns"
    else:
        confidence = min(40, max(5, calc_conf))
        summary = "Potential phishing characteristics observed"
        pattern = "High-risk infrastructure"
        
    signals = risk.get("risk_factors", [])[:5]

    return {
        "ai_confidence_pct":      confidence,
        "infrastructure_pattern": pattern,
        "ai_explanation":         signals,
        "summary":                summary,
    }


# ══════════════════════════════════════════════════════════════
# EXPLAINABLE OUTPUT — "Why is this site risky?"  (NEW)
# ══════════════════════════════════════════════════════════════
def build_risk_explanation(
    proxy_info, whois_info, origin_discovery, asn_analysis,
    redirect_chain, geo_info, url_analysis, ssl_info, risk, domain="",
) -> list:
    """
    Generate natural-language bullet points explaining why
    the investigated domain is (or isn't) risky.
    """
    reasons = []

    if proxy_info.get("proxy_detected") or proxy_info.get("cdn_detected"):
        prov = proxy_info.get('proxy_provider') or proxy_info.get('cdn_provider') or 'Proxy'
        if "cloudflare" in prov.lower() or proxy_info.get("cdn_detected"):
            reasons.append(f"INFO: {prov} CDN detected — used for security, performance optimization, and DDoS protection.")
        else:
            reasons.append(f"🛡 {prov} is actively hiding the real origin server")

    if origin_discovery and origin_discovery.get("origin_suspected"):
        n = len(origin_discovery.get("possible_origin_ips", []))
        reasons.append(
            f"🔍 Origin server leaked via subdomain enumeration — {n} possible origin IP(s) found"
        )

    if asn_analysis and asn_analysis.get("mismatch_detected"):
        reasons.append(f"⚡ {asn_analysis.get('mismatch_note', 'Hosting provider mismatch')}")

    creation_date = whois_info.get("creation_date", "Unknown")
    if creation_date not in ("Unknown", "None"):
        try:
            age_days = (
                datetime.utcnow()
                - datetime.strptime(creation_date, "%Y-%m-%d")
            ).days
            if age_days < 90:
                reasons.append(
                    f"📅 Domain registered only {age_days} days ago — very recently created"
                )
        except Exception:
            pass

    if redirect_chain and redirect_chain.get("suspicious"):
        reasons.append(
            f"↩ Multiple redirects detected ({redirect_chain.get('redirect_count',0)} hops) "
            f"— possible evasion or phishing redirect chain"
        )

    if geo_info and geo_info.get("is_flagged_region"):
        reasons.append(
            f"🌍 Server geo-location in flagged region: {geo_info.get('primary_country','?')}"
        )

    if url_analysis and url_analysis.get("suspicious_keywords"):
        kws = url_analysis.get("suspicious_keywords", [])
        reasons.append(f"🔑 Suspicious keywords in domain URL: {', '.join(kws[:3])}")

    if url_analysis and url_analysis.get("suspicious_tld"):
        reasons.append(f"🏷 High-risk TLD detected: {url_analysis.get('tld','')}")

    if ssl_info:
        if ssl_info.get("ssl_expired"):
            reasons.append("🔐 SSL certificate is EXPIRED — insecure connection")
        elif ssl_info.get("self_signed"):
            reasons.append("🔐 Self-signed SSL certificate — not issued by a trusted CA")

    org = whois_info.get("org", "Unknown").lower()
    if org in ("unknown", "privacy", "redacted", "none", "n/a"):
        reasons.append("📋 WHOIS organization field is redacted — domain owner identity concealed")

    if not reasons:
        reasons.append("✅ No significant risk indicators detected — domain appears legitimate")

    return reasons


# ══════════════════════════════════════════════════════════════
# VISUAL INFRASTRUCTURE MAP DATA  (NEW)
# ══════════════════════════════════════════════════════════════
def build_infrastructure_map(
    proxy_info:       dict,
    origin_discovery: dict,
    asn_analysis:     dict,
) -> list:
    """
    Build a structured list of nodes for the visual infrastructure diagram.

    Flow:  User → [Proxy/CDN] → [Origin Server]
    """
    nodes = [{"node": "👤 User", "type": "user", "note": "Request origin"}]

    if proxy_info.get("proxy_detected"):
        prov = proxy_info.get("proxy_provider", "Proxy")
        nodes.append({
            "node":     f"🛡 {prov}",
            "type":     "proxy",
            "note":     "Proxy / WAF — origin IP hidden",
            "provider": prov,
        })
    elif proxy_info.get("cdn_detected"):
        prov = proxy_info.get("cdn_provider", "CDN")
        nodes.append({
            "node":     f"⚡ {prov}",
            "type":     "cdn",
            "note":     "CDN layer active",
            "provider": prov,
        })

    if origin_discovery and origin_discovery.get("origin_suspected"):
        ips        = origin_discovery.get("possible_origin_ips", [])
        conf       = origin_discovery.get("confidence", "Low")
        origin_prov = (asn_analysis or {}).get("origin_asn_provider", "Unknown Provider")
        nodes.append({
            "node":     "🖥 Origin Server",
            "type":     "origin_leaked",
            "note":     f"Possible origin: {', '.join(ips[:2])} ({origin_prov})",
            "ips":      ips[:2],
            "provider": origin_prov,
            "confidence": conf,
        })
    elif proxy_info.get("proxy_detected"):
        nodes.append({
            "node": "❓ Origin Server",
            "type": "origin_hidden",
            "note": "Origin concealed — IP unknown",
        })
    else:
        nodes.append({
            "node": "🖥 Direct Server",
            "type": "direct",
            "note": "No proxy — direct host exposure",
        })

    return nodes
