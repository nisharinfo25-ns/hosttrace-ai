import re
import math

POPULAR_DOMAINS = [
    "google.com", "facebook.com", "amazon.com", "paypal.com",
    "microsoft.com", "apple.com", "instagram.com", "netflix.com",
    "linkedin.com", "twitter.com", "github.com", "cloudflare.com"
]

def _levenshtein(s1, s2):
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def _normalize_homoglyphs(domain):
    # Common substitutions
    replacements = {
        '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', 
        '7': 't', '8': 'b', 'rn': 'm', 'vv': 'w'
    }
    norm = domain.lower()
    for k, v in replacements.items():
        norm = norm.replace(k, v)
    return norm

def detect_lookalike(domain: str) -> dict:
    domain_base = domain.lower().split(':')[0]
    
    # Exact match of a popular domain isn't an impersonation, it's the real thing.
    if domain_base in POPULAR_DOMAINS:
        return {
            "matched_domain": domain_base,
            "similarity_score": 100,
            "risk_classification": "LOW (Exact Match)",
            "is_lookalike": False
        }
        
    normalized = _normalize_homoglyphs(domain_base)
    
    best_match = None
    min_dist = 999
    
    for pop in POPULAR_DOMAINS:
        dist = _levenshtein(normalized.split('.')[0], pop.split('.')[0])
        # If lengths match exactly but 1-2 chars differ, it's highly suspicious
        if dist < min_dist:
            min_dist = dist
            best_match = pop
            
    # Calculate a percent similarity (rough approximation)
    max_len = max(len(normalized.split('.')[0]), len(best_match.split('.')[0])) if best_match else 10
    sim_percent = max(0, 100 - int((min_dist / max_len) * 100))
    
    if min_dist > 0 and min_dist <= 2 and sim_percent >= 70:
        return {
            "matched_domain": best_match,
            "similarity_score": sim_percent,
            "risk_classification": "HIGH RISK (Impersonation)",
            "is_lookalike": True
        }
    elif min_dist <= 3 and sim_percent >= 50:
        return {
            "matched_domain": best_match,
            "similarity_score": sim_percent,
            "risk_classification": "MEDIUM RISK",
            "is_lookalike": False
        }
        
    return {
        "matched_domain": "None",
        "similarity_score": 0,
        "risk_classification": "LOW RISK",
        "is_lookalike": False
    }

def run_phishing_simulation(url, domain, whois_info, risk_factors):
    url_str = (url if url else domain).lower()
    suspicious_kws = ["login", "verify", "secure", "update", "bank", "free", "gift", "account", "support", "auth"]
    
    kw_count = sum(1 for kw in suspicious_kws if kw in url_str)
    
    # Check domain age
    age_days = 365
    creation_date = whois_info.get("creation_date", "Unknown")
    if creation_date not in ("Unknown", "None"):
        try:
            from datetime import datetime
            cd_dt = datetime.strptime(creation_date, "%Y-%m-%d")
            age_days = max(0, (datetime.utcnow() - cd_dt).days)
        except Exception:
            pass
            
    probability = 5.0
    
    # Heuristics
    if kw_count > 0: probability += 35 * kw_count
    if age_days < 30: probability += 40
    elif age_days < 90: probability += 20
    
    # If the rule engine flagged IP usage or long urls, add probability
    if any("ip address" in f.lower() for f in risk_factors): probability += 25
    if any("long" in f.lower() for f in risk_factors): probability += 15
    if any("multiple redirects" in f.lower() for f in risk_factors): probability += 20

    probability = min(99.9, probability)
    
    if probability > 75:
        classification = "HIGH RISK PHISHING"
    elif probability > 35:
        classification = "POSSIBLE PHISHING"
    else:
        classification = "SAFE"
        
    return {
        "phishing_probability": round(probability, 1),
        "behavior_classification": classification
    }

def generate_domain_dna(domain, risk_score, features):
    entropy = features.get("entropy", 0.0)
    num_hyphens = features.get("num_hyphens", 0)
    
    # Structure Type
    if features.get("is_ip") == 1:
        structure = "Raw IP Asset"
    elif num_hyphens > 1 or features.get("num_dots", 0) > 2:
        structure = "Complex Distributed"
    elif entropy > 4.2:
        structure = "Randomized DGA"
    else:
        structure = "Clean Alphanumeric"
        
    # Entropy Level
    if entropy < 3.0: ent_str = "Low"
    elif entropy < 4.0: ent_str = "Medium"
    else: ent_str = "High"
    
    # Behavioral Pattern
    if risk_score <= 30: behavior = "Legitimate Static"
    elif risk_score <= 65: behavior = "Suspicious Dynamic"
    else: behavior = "Malicious Transient"
        
    # Abstract scoring mapping 0 to 10
    dna_summary_score = round(10 - (risk_score / 10), 1)

    return {
        "structure_type": structure,
        "entropy_level": ent_str,
        "behavioral_pattern": behavior,
        "summary_score": dna_summary_score
    }
