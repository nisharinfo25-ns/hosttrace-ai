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
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(BASE_DIR, "dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")
ACCURACY_PATH = os.path.join(BASE_DIR, "model_accuracy.txt")

SUSPICIOUS_KWS = ["login", "verify", "secure", "update", "bank", "free", "gift"]

def _calculate_entropy(text):
    if not text:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def extract_features(domain: str, url: str, whois_info: dict, ssl_info: dict) -> dict:
    url_str = url if url else domain
    domain_str = domain.split(':')[0]  # strip port if present

    url_len = len(url_str)
    num_dots = domain_str.count('.')
    num_hyphens = domain_str.count('-')
    
    # Check IP
    is_ip = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain_str) else 0

    # Suspicious Keywords
    path_lower = url_str.lower()
    has_suspicious_kw = 1 if any(kw in path_lower for kw in SUSPICIOUS_KWS) else 0

    # Entropy
    entropy = _calculate_entropy(domain_str)

    # WHOIS
    age_days = 365  # default
    creation_date = whois_info.get("creation_date", "Unknown")
    if creation_date not in ("Unknown", "None"):
        try:
            cd_dt = datetime.strptime(creation_date, "%Y-%m-%d")
            age_days = max(0, (datetime.utcnow() - cd_dt).days)
        except Exception:
            pass
            
    org = whois_info.get("org", "Unknown").lower()
    whois_hidden = 1 if org in ("unknown", "privacy", "redacted", "none", "n/a", "domains by proxy", "") else 0
    
    # Simple registry trust (assume known good vs unknown)
    reg = whois_info.get("registrar", "").lower()
    trusted_regs = ["markmonitor", "godaddy", "namecheap", "cloudflare", "amazon", "google", "tucows"]
    registrar_trust = 1 if any(tr in reg for tr in trusted_regs) else 0

    # SSL
    ssl_valid = 1 if (ssl_info and ssl_info.get("ssl_valid")) else 0
    has_https = 1 if url_str.startswith("https") or ssl_valid else 0

    return {
        "url_len": url_len,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "is_ip": is_ip,
        "has_suspicious_kw": has_suspicious_kw,
        "entropy": round(entropy, 3),
        "age_days": age_days,
        "whois_hidden": whois_hidden,
        "registrar_trust": registrar_trust,
        "ssl_valid": ssl_valid,
        "has_https": has_https
    }

def get_model_accuracy():
    if os.path.exists(ACCURACY_PATH):
        try:
            with open(ACCURACY_PATH, "r") as f:
                return float(f.read().strip())
        except:
            return 0.0
    return 0.0

def predict_risk(features: dict) -> dict:
    default_resp = {"prediction": "SUSPICIOUS", "confidence": 50.0, "accuracy": 0.0, "probabilities": {"SAFE": 0, "SUSPICIOUS": 1, "DANGEROUS": 0}}
    
    if not ML_AVAILABLE:
        return default_resp
        
    if not os.path.exists(MODEL_PATH):
        return default_resp
        
    try:
        model = joblib.load(MODEL_PATH)
        
        feature_order = [
            "url_len", "num_dots", "num_hyphens", "is_ip", 
            "has_suspicious_kw", "entropy", "age_days", 
            "whois_hidden", "registrar_trust", "ssl_valid", "has_https"
        ]
        X_test = pd.DataFrame([{k: features.get(k, 0) for k in feature_order}])
        
        probas = model.predict_proba(X_test)[0]
        classes = model.classes_
        
        prob_dict = {cls: float(prob)*100 for cls, prob in zip(classes, probas)}
        
        # Ensure all keys exist
        for k in ["SAFE", "SUSPICIOUS", "DANGEROUS"]:
            if k not in prob_dict:
                prob_dict[k] = 0.0
                
        pred_class = classes[np.argmax(probas)]
        pred_conf = float(np.max(probas)) * 100
        
        acc = get_model_accuracy()
        
        return {
            "prediction": pred_class,
            "confidence": round(pred_conf, 1),
            "probabilities": prob_dict,
            "accuracy": round(acc, 1)
        }
    except Exception as e:
        print(f"ML Prediction Error: {e}")
        return default_resp

def append_and_train(features: dict, label: str):
    if not ML_AVAILABLE:
        return
        
    fieldnames = [
        "url_len", "num_dots", "num_hyphens", "is_ip", 
        "has_suspicious_kw", "entropy", "age_days", 
        "whois_hidden", "registrar_trust", "ssl_valid", "has_https", "label"
    ]
    
    write_header = not os.path.exists(DATASET_PATH)
    
    row = dict(features)
    row["label"] = label
    
    try:
        with open(DATASET_PATH, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if write_header:
                writer.writeheader()
            writer.writerow(row)
    except Exception as e:
        print(f"Dataset append error: {e}")
        return

    # Check length
    try:
        df = pd.read_csv(DATASET_PATH)
        total_rows = len(df)
        
        # Boostrap fake data if too few (for new models)
        if total_rows < 10 and write_header:
            _bootstrap_fake_data()
            df = pd.read_csv(DATASET_PATH)
            total_rows = len(df)
            
        if total_rows >= 20 and total_rows % 50 == 0:
            _train_model(df)
        elif not os.path.exists(MODEL_PATH) and total_rows >= 10:
            _train_model(df)
            
    except Exception as e:
        print(f"Training check error: {e}")

def _train_model(df):
    try:
        # Require at least two classes to train
        if len(df['label'].unique()) < 2:
            return
            
        X = df.drop(columns=['label'])
        y = df['label']
        
        # Simple split, if enough data
        if len(df) > 30:
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        else:
            X_train, X_test, y_train, y_test = X, X, y, y
            
        model = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42)
        model.fit(X_train, y_train)
        
        preds = model.predict(X_test)
        acc = accuracy_score(y_test, preds) * 100
        
        joblib.dump(model, MODEL_PATH)
        
        with open(ACCURACY_PATH, "w") as f:
            f.write(str(acc))
            
        print(f"[ML] Auto-training complete! Accuracy: {acc:.1f}%. Samples: {len(df)}")
    except Exception as e:
        print(f"[ML] Training failed: {e}")

def _bootstrap_fake_data():
    """Generates initial data to allow the model to boot up."""
    fake_data = [
        {"url_len": 15, "num_dots": 1, "num_hyphens": 0, "is_ip": 0, "has_suspicious_kw": 0, "entropy": 3.1, "age_days": 3000, "whois_hidden": 0, "registrar_trust": 1, "ssl_valid": 1, "has_https": 1, "label": "SAFE"},
        {"url_len": 12, "num_dots": 1, "num_hyphens": 0, "is_ip": 0, "has_suspicious_kw": 0, "entropy": 2.9, "age_days": 5000, "whois_hidden": 0, "registrar_trust": 1, "ssl_valid": 1, "has_https": 1, "label": "SAFE"},
        {"url_len": 55, "num_dots": 3, "num_hyphens": 2, "is_ip": 0, "has_suspicious_kw": 1, "entropy": 4.5, "age_days": 10, "whois_hidden": 1, "registrar_trust": 0, "ssl_valid": 0, "has_https": 0, "label": "DANGEROUS"},
        {"url_len": 60, "num_dots": 4, "num_hyphens": 1, "is_ip": 0, "has_suspicious_kw": 1, "entropy": 4.8, "age_days": 5, "whois_hidden": 1, "registrar_trust": 0, "ssl_valid": 0, "has_https": 1, "label": "DANGEROUS"},
        {"url_len": 35, "num_dots": 2, "num_hyphens": 0, "is_ip": 0, "has_suspicious_kw": 0, "entropy": 3.9, "age_days": 60, "whois_hidden": 1, "registrar_trust": 1, "ssl_valid": 1, "has_https": 1, "label": "SUSPICIOUS"},
        {"url_len": 40, "num_dots": 2, "num_hyphens": 1, "is_ip": 0, "has_suspicious_kw": 0, "entropy": 4.0, "age_days": 120, "whois_hidden": 0, "registrar_trust": 0, "ssl_valid": 1, "has_https": 1, "label": "SUSPICIOUS"},
        {"url_len": 14, "num_dots": 3, "num_hyphens": 0, "is_ip": 1, "has_suspicious_kw": 0, "entropy": 2.5, "age_days": 0, "whois_hidden": 1, "registrar_trust": 0, "ssl_valid": 0, "has_https": 0, "label": "DANGEROUS"},
        {"url_len": 25, "num_dots": 1, "num_hyphens": 0, "is_ip": 0, "has_suspicious_kw": 0, "entropy": 3.2, "age_days": 900, "whois_hidden": 0, "registrar_trust": 1, "ssl_valid": 1, "has_https": 1, "label": "SAFE"},
        {"url_len": 45, "num_dots": 2, "num_hyphens": 3, "is_ip": 0, "has_suspicious_kw": 1, "entropy": 4.3, "age_days": 15, "whois_hidden": 1, "registrar_trust": 0, "ssl_valid": 1, "has_https": 1, "label": "DANGEROUS"},
        {"url_len": 30, "num_dots": 2, "num_hyphens": 1, "is_ip": 0, "has_suspicious_kw": 0, "entropy": 4.1, "age_days": 45, "whois_hidden": 1, "registrar_trust": 0, "ssl_valid": 0, "has_https": 0, "label": "SUSPICIOUS"},
    ]
    pd.DataFrame(fake_data).to_csv(DATASET_PATH, mode='a', header=False, index=False)
