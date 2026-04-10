"""
HostTrace AI — ML Engine  v2.0
================================
• Feature extraction from live scan data
• Prediction via pre-trained RandomForestClassifier (model.pkl)
• Local rule-based XAI explanation (NO external API required)
• Model loaded ONCE at module import for <1 s response time
"""

import os
import csv
import math
import re
import pandas as pd
from datetime import datetime
import numpy as np

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score
    from sklearn.preprocessing import LabelEncoder
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

# ── Paths ──────────────────────────────────────────────────────
BASE_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH  = os.path.join(BASE_DIR, "dataset.csv")
MODEL_PATH    = os.path.join(BASE_DIR, "model.pkl")
ENCODER_PATH  = os.path.join(BASE_DIR, "label_encoder.pkl")
ACCURACY_PATH = os.path.join(BASE_DIR, "model_accuracy.txt")

FEATURE_COLS = [
    "url_len", "num_dots", "num_hyphens", "is_ip",
    "has_suspicious_kw", "entropy", "age_days",
    "whois_hidden", "registrar_trust", "ssl_valid", "has_https",
]

SUSPICIOUS_KWS = [
    "login", "verify", "secure", "update", "bank", "free", "gift",
    "account", "password", "signin", "reset", "confirm", "wallet",
    "paypal", "amazon", "support", "invoice", "alert", "urgent",
]

# ── Load model ONCE at import ──────────────────────────────────
_MODEL   = None
_ENCODER = None

def _load_model():
    """Load model and encoder from disk exactly once."""
    global _MODEL, _ENCODER
    if not ML_AVAILABLE:
        return False
    if not os.path.exists(MODEL_PATH):
        return False
    try:
        _MODEL   = joblib.load(MODEL_PATH)
        if os.path.exists(ENCODER_PATH):
            _ENCODER = joblib.load(ENCODER_PATH)
        print(f"[ML] Model loaded — classes: {getattr(_MODEL, 'classes_', '?')}")
        return True
    except Exception as e:
        print(f"[ML] Model load failed: {e}")
        return False

_load_model()   # Execute at import time


# ══════════════════════════════════════════════════════════════
# 1. FEATURE EXTRACTION
# ══════════════════════════════════════════════════════════════
def _calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    entropy = 0.0
    length  = len(text)
    for x in range(256):
        p = text.count(chr(x)) / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_features(domain: str, url: str, whois_info: dict, ssl_info: dict) -> dict:
    url_str    = url if url else domain
    domain_str = domain.split(":")[0]          # strip port if present

    url_len        = len(url_str)
    num_dots       = domain_str.count(".")
    num_hyphens    = domain_str.count("-")
    is_ip          = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain_str) else 0
    entropy        = _calculate_entropy(domain_str)
    path_lower     = url_str.lower()
    has_suspicious = 1 if any(kw in path_lower for kw in SUSPICIOUS_KWS) else 0

    # Domain age
    age_days      = 365  # sensible default
    creation_date = whois_info.get("creation_date", "Unknown")
    if creation_date not in ("Unknown", "None", None):
        try:
            cd_dt    = datetime.strptime(creation_date, "%Y-%m-%d")
            age_days = max(0, (datetime.utcnow() - cd_dt).days)
        except Exception:
            pass

    # WHOIS quality
    org          = whois_info.get("org", "Unknown").lower()
    whois_hidden = 1 if org in (
        "unknown", "privacy", "redacted", "none", "n/a",
        "domains by proxy", "", "withheld"
    ) else 0

    # Registrar trust
    reg           = whois_info.get("registrar", "").lower()
    trusted_regs  = ["markmonitor", "godaddy", "namecheap", "cloudflare",
                     "amazon", "google", "tucows", "verisign", "csc global"]
    registrar_trust = 1 if any(tr in reg for tr in trusted_regs) else 0

    # SSL
    ssl_valid = 1 if (ssl_info and ssl_info.get("ssl_valid")) else 0
    has_https = 1 if (url_str.startswith("https") or ssl_valid) else 0

    return {
        "url_len":           url_len,
        "num_dots":          num_dots,
        "num_hyphens":       num_hyphens,
        "is_ip":             is_ip,
        "has_suspicious_kw": has_suspicious,
        "entropy":           entropy,
        "age_days":          age_days,
        "whois_hidden":      whois_hidden,
        "registrar_trust":   registrar_trust,
        "ssl_valid":         ssl_valid,
        "has_https":         has_https,
    }


# ══════════════════════════════════════════════════════════════
# 2. PREDICTION
# ══════════════════════════════════════════════════════════════
def get_model_accuracy() -> float:
    if os.path.exists(ACCURACY_PATH):
        try:
            with open(ACCURACY_PATH, "r") as f:
                return float(f.read().strip())
        except Exception:
            pass
    return 0.0


def predict_risk(features: dict) -> dict:
    """
    Returns:
        prediction   : "SAFE" | "SUSPICIOUS" | "DANGEROUS"
        confidence   : 0–100 float
        probabilities: {class: pct, …}
        accuracy     : model test-set accuracy
        label        : alias for prediction (used downstream)
    """
    default = {
        "prediction":    "SUSPICIOUS",
        "label":         "SUSPICIOUS",
        "confidence":    50.0,
        "accuracy":      0.0,
        "probabilities": {"SAFE": 33.0, "SUSPICIOUS": 34.0, "DANGEROUS": 33.0},
    }

    if not ML_AVAILABLE or _MODEL is None:
        return default

    try:
        X = pd.DataFrame([{col: float(features.get(col, 0)) for col in FEATURE_COLS}])

        probas  = _MODEL.predict_proba(X)[0]
        classes = _MODEL.classes_

        # Decode numeric classes if encoder is present
        if _ENCODER is not None:
            class_names = list(_ENCODER.inverse_transform(classes))
        else:
            class_names = [str(c) for c in classes]

        prob_dict = {cls: round(float(p) * 100, 1)
                     for cls, p in zip(class_names, probas)}

        # Ensure all three keys exist
        for k in ("SAFE", "SUSPICIOUS", "DANGEROUS"):
            prob_dict.setdefault(k, 0.0)

        best_idx  = int(np.argmax(probas))
        best_cls  = class_names[best_idx]
        best_conf = round(float(probas[best_idx]) * 100, 1)

        return {
            "prediction":    best_cls,
            "label":         best_cls,
            "confidence":    best_conf,
            "probabilities": prob_dict,
            "accuracy":      round(get_model_accuracy(), 1),
        }

    except Exception as e:
        print(f"[ML] Prediction error: {e}")
        return default


# ══════════════════════════════════════════════════════════════
# 3. LOCAL XAI EXPLANATION ENGINE  (no API calls)
# ══════════════════════════════════════════════════════════════
def generate_local_explanation(
    domain: str,
    risk_score: int,
    prediction: str,
    features: dict,
    flags: list,
) -> str:
    """
    Builds a 2–3 sentence plain-English explanation purely from
    extracted features and the ML prediction — zero network calls.
    """
    f        = features or {}
    pred     = (prediction or "SUSPICIOUS").upper()
    reasons  = []
    positives = []

    # ── Positive signals ──
    if f.get("ssl_valid") == 1:
        positives.append("it uses a secure, verified SSL connection")
    if f.get("has_https") == 1 and f.get("ssl_valid") == 1:
        positives.append("traffic is encrypted with HTTPS")
    if f.get("age_days", 0) > 730:
        age_yrs = round(f["age_days"] / 365, 1)
        positives.append(f"the domain has been active for {age_yrs} years")
    if f.get("registrar_trust") == 1:
        positives.append("it is registered with a trusted, enterprise-grade registrar")
    if f.get("is_ip") == 0 and f.get("num_dots", 0) <= 2:
        positives.append("the domain structure looks clean and professional")
    if f.get("has_suspicious_kw") == 0 and f.get("whois_hidden") == 0:
        positives.append("no suspicious keywords or hidden registration details were found")

    # ── Negative / risk signals ──
    if f.get("is_ip") == 1:
        reasons.append("the URL uses a raw IP address instead of a domain name")
    if f.get("has_suspicious_kw") == 1:
        reasons.append("the domain contains words commonly used in phishing attacks")
    if f.get("age_days", 365) < 30:
        reasons.append(f"the domain was registered very recently ({f.get('age_days', '?')} days ago)")
    elif f.get("age_days", 365) < 90:
        reasons.append("the domain is less than 3 months old")
    if f.get("whois_hidden") == 1:
        reasons.append("the owner's identity is hidden in registration records")
    if f.get("ssl_valid") == 0:
        reasons.append("the site lacks a valid SSL certificate")
    if f.get("entropy", 0) > 4.2:
        reasons.append("the domain name contains unusual random-looking characters")
    if f.get("num_hyphens", 0) >= 3:
        reasons.append("excessive hyphens in the domain are a phishing pattern")
    if f.get("num_dots", 0) >= 4:
        reasons.append("deeply nested subdomains indicate a suspicious structure")
    if f.get("url_len", 0) > 60:
        reasons.append("the URL is unusually long, which is a common disguise tactic")

    # ── Also pull from risk flags ──
    for flag in (flags or [])[:3]:
        flag_lower = str(flag).lower()
        if "blacklist" in flag_lower:
            reasons.append("the domain appears on threat blacklists")
        elif "redirect" in flag_lower:
            reasons.append("multiple redirects were detected which can mask malicious destinations")
        elif "geo" in flag_lower:
            reasons.append("the hosting location is associated with high-risk regions")

    # ── Deduplicate ──
    reasons   = list(dict.fromkeys(reasons))
    positives = list(dict.fromkeys(positives))

    # ── Compose by prediction ──
    explanation = []
    
    if pred == "SAFE":
        title = "Why it is SAFE"
    else:
        title = "Why it is RISKY"

    def format_sentence(text):
        if not text: return ""
        text = str(text).strip()
        text = text[0].upper() + text[1:]
        if not text.endswith("."):
            text += "."
        return text

    if pred == "SAFE":
        # Strictly positive reasons only
        if positives:
            for p in positives[:2]:
                explanation.append(format_sentence(p))
        if len(explanation) < 3:
            explanation.append("The site appears safe and shows normal security patterns.")
        if len(explanation) < 3:
            explanation.append("No suspicious activity was detected.")
            
    elif pred == "SUSPICIOUS":
        # Strictly negative reasons only
        if reasons:
            for r in reasons[:2]:
                explanation.append(format_sentence(r))
        if len(explanation) < 3:
            explanation.append("This site has some unusual signals that warrant caution.")
        if len(explanation) < 3:
            explanation.append("While not confirmed malicious, these patterns are suspicious.")
            
    else:  # DANGEROUS
        # Strictly negative reasons only
        explanation.append(f"Our AI classified this domain as HIGH RISK ({risk_score}/100 score).")
        if reasons:
            for r in reasons[:2]:
                explanation.append(format_sentence(r))
        if len(explanation) < 3:
            explanation.append("This site shows multiple high-risk indicators used in attacks.")

    return {
        "title": title,
        "points": explanation[:3]
    }


# ══════════════════════════════════════════════════════════════
# 4. INCREMENTAL TRAINING (background, triggered per scan)
# ══════════════════════════════════════════════════════════════
def append_and_train(features: dict, label: str):
    """Append latest scan to dataset; retrain model when enough rows grow."""
    if not ML_AVAILABLE:
        return

    fieldnames = FEATURE_COLS + ["label"]
    write_header = not os.path.exists(DATASET_PATH)

    row = {col: features.get(col, 0) for col in FEATURE_COLS}
    row["label"] = label.upper()

    try:
        with open(DATASET_PATH, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if write_header:
                writer.writeheader()
            writer.writerow(row)
    except Exception as e:
        print(f"[ML] Dataset append error: {e}")
        return

    try:
        df = pd.read_csv(DATASET_PATH)
        total = len(df)
        if not os.path.exists(MODEL_PATH) and total >= 30:
            _train_model(df)
        elif total >= 50 and total % 100 == 0:
            _train_model(df)
    except Exception as e:
        print(f"[ML] Training trigger error: {e}")


def _train_model(df: pd.DataFrame):
    """Train and persist a new RandomForest model from a DataFrame."""
    global _MODEL, _ENCODER
    try:
        df = df.dropna(subset=FEATURE_COLS + ["label"])
        if len(df["label"].unique()) < 2:
            return

        X    = df[FEATURE_COLS].astype(float)
        le   = LabelEncoder()
        y    = le.fit_transform(df["label"].str.upper().str.strip())

        split_ok = len(df) > 40
        if split_ok:
            X_tr, X_te, y_tr, y_te = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
        else:
            X_tr, X_te, y_tr, y_te = X, X, y, y

        clf = RandomForestClassifier(
            n_estimators=120, max_depth=12,
            min_samples_leaf=3, class_weight="balanced",
            random_state=42,
        )
        clf.fit(X_tr, y_tr)

        acc = accuracy_score(y_te, clf.predict(X_te)) * 100

        joblib.dump(clf, MODEL_PATH)
        joblib.dump(le,  ENCODER_PATH)
        with open(ACCURACY_PATH, "w") as f:
            f.write(str(acc))

        _MODEL   = clf
        _ENCODER = le
        print(f"[ML] Model retrained — accuracy: {acc:.1f}%  samples: {len(df)}")

    except Exception as e:
        print(f"[ML] Training failed: {e}")
