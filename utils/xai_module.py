"""
HostTrace AI — XAI Module  v2.0
=================================
Fully local, rule-based Explainable AI.
No external API calls. Instant response.
"""


# ══════════════════════════════════════════════════════════════
# 1. FEATURE CONTRIBUTION ANALYSIS
# ══════════════════════════════════════════════════════════════
def analyze_feature_contribution(
    features: dict,
    whois_info: dict,
    ssl_info: dict,
    risk_factors: list,
) -> list:
    """
    Calculates the weighted contribution of each extracted feature
    and returns a structured list of signals for the XAI panel.
    """
    f = features or {}
    contributions = []

    # ── SSL Validation ────────────────────────────────────────
    if f.get("ssl_valid", 0) == 1:
        contributions.append({
            "signal": "Positive", "feature": "SSL Certificate Valid",
            "impact": -20,
            "desc": "A valid SSL certificate confirms cryptographic identity and encrypts traffic.",
        })
    else:
        contributions.append({
            "signal": "Negative", "feature": "SSL Missing / Invalid",
            "impact": +25,
            "desc": "Absence of a valid SSL certificate removes basic trust guarantees.",
        })

    # ── Domain Age ────────────────────────────────────────────
    age = f.get("age_days", 0)
    if age > 730:
        contributions.append({
            "signal": "Positive",
            "feature": f"Domain Age: {round(age/365,1)} years",
            "impact": -25,
            "desc": "Long-standing domains have strong historical legitimacy signals.",
        })
    elif age > 180:
        contributions.append({
            "signal": "Neutral",
            "feature": f"Domain Age: {age} days",
            "impact": 0,
            "desc": "Domain is moderately established — not new, not yet long-lived.",
        })
    elif age < 30:
        contributions.append({
            "signal": "Negative",
            "feature": f"Very New Domain: {age} days old",
            "impact": +35,
            "desc": "Newly registered domains are frequently used for short-lived attacks.",
        })
    else:
        contributions.append({
            "signal": "Negative",
            "feature": f"New Domain: {age} days old",
            "impact": +20,
            "desc": "Short domain lifetime is a moderate phishing indicator.",
        })

    # ── Phishing Keywords ─────────────────────────────────────
    if f.get("has_suspicious_kw", 0) == 1:
        contributions.append({
            "signal": "Negative", "feature": "Suspicious Keywords Detected",
            "impact": +30,
            "desc": "Domain or URL path contains words commonly used in credential-harvesting attacks.",
        })
    else:
        contributions.append({
            "signal": "Positive", "feature": "No Phishing Keywords",
            "impact": -10,
            "desc": "No known phishing vocabulary found in the domain or URL structure.",
        })

    # ── WHOIS Visibility ──────────────────────────────────────
    if f.get("whois_hidden", 0) == 1:
        contributions.append({
            "signal": "Negative", "feature": "WHOIS Identity Hidden",
            "impact": +15,
            "desc": "Registration information is obscured by a privacy proxy — increases anonymity risk.",
        })
    else:
        contributions.append({
            "signal": "Positive", "feature": "WHOIS Identity Visible",
            "impact": -10,
            "desc": "Domain owner details are publicly registered — increases accountability.",
        })

    # ── Bare IP URL ───────────────────────────────────────────
    if f.get("is_ip", 0) == 1:
        contributions.append({
            "signal": "Negative", "feature": "Raw IP Address Used as Host",
            "impact": +40,
            "desc": "Bypassing DNS with a bare IP is a strong evasion tactic used by attackers.",
        })

    # ── Registrar Trust ───────────────────────────────────────
    if f.get("registrar_trust", 0) == 1:
        contributions.append({
            "signal": "Positive", "feature": "Trusted Enterprise Registrar",
            "impact": -15,
            "desc": "Registered through a top-tier enterprise registrar with verified KYC processes.",
        })
    else:
        contributions.append({
            "signal": "Negative", "feature": "Unknown / Untrusted Registrar",
            "impact": +10,
            "desc": "Registrar is not among commonly trusted enterprise-class providers.",
        })

    # ── Entropy ───────────────────────────────────────────────
    entropy = f.get("entropy", 0.0)
    if entropy > 4.2:
        contributions.append({
            "signal": "Negative",
            "feature": f"High Entropy: {entropy}",
            "impact": +20,
            "desc": "Randomised character distribution suggests algorithmically generated domain (DGA).",
        })
    elif entropy < 2.5:
        contributions.append({
            "signal": "Positive",
            "feature": f"Low Entropy: {entropy}",
            "impact": -5,
            "desc": "Simple character structure is typical of human-chosen, legitimate domain names.",
        })

    # ── URL Length ────────────────────────────────────────────
    url_len = f.get("url_len", 0)
    if url_len > 75:
        contributions.append({
            "signal": "Negative",
            "feature": f"Very Long URL: {url_len} chars",
            "impact": +15,
            "desc": "Excessively long URLs are often used to hide malicious path segments.",
        })
    elif url_len > 50:
        contributions.append({
            "signal": "Negative",
            "feature": f"Long URL: {url_len} chars",
            "impact": +8,
            "desc": "Above-average URL length is a minor phishing indicator.",
        })

    # ── Hyphen count ─────────────────────────────────────────
    hyphens = f.get("num_hyphens", 0)
    if hyphens >= 3:
        contributions.append({
            "signal": "Negative",
            "feature": f"Excessive Hyphens: {hyphens}",
            "impact": +12,
            "desc": "Multiple hyphens in a domain name are a known phishing construction pattern.",
        })

    # ── HTTPS ────────────────────────────────────────────────
    if f.get("has_https", 0) == 1:
        contributions.append({
            "signal": "Positive", "feature": "HTTPS Enabled",
            "impact": -8,
            "desc": "Traffic is encrypted. Note: HTTPS alone does not guarantee safety.",
        })
    else:
        contributions.append({
            "signal": "Negative", "feature": "HTTP Only (No Encryption)",
            "impact": +12,
            "desc": "Unencrypted connection exposes data in transit and is absent on modern safe sites.",
        })

    return contributions


# ══════════════════════════════════════════════════════════════
# 2. STRUCTURED THREAT ALERTS
# ══════════════════════════════════════════════════════════════
def generate_threat_alerts(
    ai_pred: dict,
    phishing_sim: dict,
    risk_factors: list,
    proxy_info: dict,
) -> list:
    """
    Returns categorised alerts: CRITICAL / WARNING / INFO.
    Purely rule-based, no network calls.
    """
    alerts = []
    pred_label = (ai_pred.get("prediction") or ai_pred.get("label") or "").upper()

    # ── CRITICAL ─────────────────────────────────────────────
    if pred_label == "DANGEROUS":
        alerts.append({
            "level": "CRITICAL",
            "msg": "🔴 AI model classified this domain as DANGEROUS — avoid interaction.",
        })
    if phishing_sim.get("behavior_classification") == "HIGH RISK PHISHING":
        alerts.append({
            "level": "CRITICAL",
            "msg": "🔴 Active credential harvesting or phishing behaviour modelled.",
        })

    # ── WARNING ───────────────────────────────────────────────
    if pred_label == "SUSPICIOUS":
        alerts.append({
            "level": "WARNING",
            "msg": "⚠️ AI model flagged suspicious structural patterns — proceed with caution.",
        })
    for factor in (risk_factors or [])[:5]:
        fac = str(factor).lower()
        if "keyword" in fac:
            alerts.append({
                "level": "WARNING",
                "msg": "⚠️ Suspicious phishing keyword detected in domain or URL path.",
            })
            break
    for factor in (risk_factors or [])[:5]:
        fac = str(factor).lower()
        if "expired" in fac or "self-signed" in fac or "ssl" in fac:
            alerts.append({
                "level": "WARNING",
                "msg": "⚠️ SSL certificate issue detected — cryptographic trust is broken.",
            })
            break
    for factor in (risk_factors or [])[:5]:
        fac = str(factor).lower()
        if "new domain" in fac or "registered" in fac or "days old" in fac:
            alerts.append({
                "level": "WARNING",
                "msg": "⚠️ Newly registered domain — short lifetime is a phishing indicator.",
            })
            break
    for factor in (risk_factors or [])[:5]:
        fac = str(factor).lower()
        if "redirect" in fac:
            alerts.append({
                "level": "WARNING",
                "msg": "⚠️ Suspicious redirect chain detected — final destination may differ.",
            })
            break

    # ── INFO ─────────────────────────────────────────────────
    if proxy_info.get("proxy_detected") or proxy_info.get("cdn_detected"):
        prov = (
            proxy_info.get("proxy_provider")
            or proxy_info.get("cdn_provider")
            or "CDN"
        )
        alerts.append({
            "level": "INFO",
            "msg": f"🟢 Traffic is routed through {prov} — origin IP is shielded.",
        })

    if pred_label == "SAFE":
        alerts.append({
            "level": "INFO",
            "msg": "🟢 AI model classified this domain as SAFE with no significant threat indicators.",
        })

    # Ensure there is always at least one entry
    if not alerts:
        alerts.append({
            "level": "INFO",
            "msg": "🟢 No critical threat indicators detected by real-time simulation engines.",
        })

    # Deduplicate by message
    seen, unique = set(), []
    for a in alerts:
        if a["msg"] not in seen:
            seen.add(a["msg"])
            unique.append(a)

    return unique
