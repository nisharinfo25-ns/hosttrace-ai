def analyze_feature_contribution(features: dict, whois_info: dict, ssl_info: dict, risk_factors: list) -> list:
    """
    Shows WHY the AI made its decision by calculating the weighted impact 
    of each feature and presenting it naturally.
    """
    contributions = []
    
    # 1. SSL Validation
    if features.get("ssl_valid", 0) == 1:
        contributions.append({"signal": "Positive", "feature": "SSL Valid", "impact": -20, "desc": "Valid SSL certificate verified cryptographic identity."})
    else:
        contributions.append({"signal": "Negative", "feature": "SSL Missing/Invalid", "impact": +25, "desc": "Lack of valid SSL prevents cryptography guarantees."})
        
    # 2. Domain Age
    age = features.get("age_days", 0)
    if age > 730:
        contributions.append({"signal": "Positive", "feature": f"Domain Age > 2 years ({age} days)", "impact": -25, "desc": "Long-standing domains are statistically much safer."})
    elif age < 30:
        contributions.append({"signal": "Negative", "feature": f"Domain Age < 30 days ({age} days)", "impact": +30, "desc": "Newly registered domains are frequently used for transient attacks."})
        
    # 3. Phishing Keywords
    if features.get("has_suspicious_kw", 0) == 1:
        contributions.append({"signal": "Negative", "feature": "Suspicious Keyword Detected", "impact": +30, "desc": "Path or domain contains keywords often associated with credential harvesting."})
    
    # 4. Hidden WHOIS
    if features.get("whois_hidden", 0) == 1:
        contributions.append({"signal": "Negative", "feature": "WHOIS Redacted", "impact": +10, "desc": "Domain registry details are actively hidden by proxy."})
        
    # 5. IP Host
    if features.get("is_ip", 0) == 1:
        contributions.append({"signal": "Negative", "feature": "Bare IP URL", "impact": +40, "desc": "Bypassing DNS lookup is a strong evasion characteristic."})
        
    # 6. Registrar Trust
    if features.get("registrar_trust", 0) == 1:
        contributions.append({"signal": "Positive", "feature": "Enterprise Registrar", "impact": -15, "desc": "Registered with a trusted tier-1 enterprise registrar."})
        
    # 7. Entropy
    entropy = features.get("entropy", 0.0)
    if entropy > 4.2:
        contributions.append({"signal": "Negative", "feature": f"High Entropy ({entropy})", "impact": +15, "desc": "Randomized character distribution indicates potential DGA."})
        
    return contributions

def generate_threat_alerts(ai_pred, phishing_sim, risk_factors, proxy_info) -> list:
    """
    Generates structured categorized alerts (INFO, WARNING, CRITICAL)
    """
    alerts = []
    
    # CRITICAL triggers
    if ai_pred.get("prediction") == "DANGEROUS":
        alerts.append({"level": "CRITICAL", "msg": "🔴 High-confidence dangerous infrastructure detected by AI."})
    if phishing_sim.get("behavior_classification") == "HIGH RISK PHISHING":
        alerts.append({"level": "CRITICAL", "msg": "🔴 Active credential harvesting or phishing behavior modeled."})
        
    # WARNING triggers
    if ai_pred.get("prediction") == "SUSPICIOUS":
        alerts.append({"level": "WARNING", "msg": "⚠️ Suspicious underlying structural patterns noticed during AI evaluation."})
    for factor in risk_factors[:3]:
        if "keyword" in factor.lower():
            alerts.append({"level": "WARNING", "msg": "⚠️ Suspicious keyword detected in target string."})
        if "expired" in factor.lower() or "self-signed" in factor.lower():
            alerts.append({"level": "WARNING", "msg": "⚠️ Missing or broken cryptographic trust."})
            
    # INFO triggers
    if proxy_info.get("proxy_detected") or proxy_info.get("cdn_detected"):
        prov = proxy_info.get('proxy_provider') or proxy_info.get('cdn_provider') or 'CDN'
        alerts.append({"level": "INFO", "msg": f"🟢 Traffic is routing through {prov}."})
        
    if not alerts or all(a["level"] == "INFO" for a in alerts):
        alerts.append({"level": "INFO", "msg": "🟢 No immediate threat indicators observed by active simulation engines."})
        
    return alerts
