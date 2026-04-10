import os
import sys
import math
import pandas as pd
import numpy as np

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
    from sklearn.metrics import (
        accuracy_score, classification_report, confusion_matrix
    )
    from sklearn.preprocessing import LabelEncoder
    import joblib
except ImportError:
    print("[ERROR] scikit-learn / joblib not installed.")
    print("  Run: pip install scikit-learn joblib pandas")
    sys.exit(1)

# ── Paths ─────────────────────────────────────────────────────
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH  = os.path.join(BASE_DIR, "dataset.csv")
MODEL_PATH    = os.path.join(BASE_DIR, "model.pkl")
ENCODER_PATH  = os.path.join(BASE_DIR, "label_encoder.pkl")
ACCURACY_PATH = os.path.join(BASE_DIR, "model_accuracy.txt")

FEATURE_COLS = [
    "url_len", "num_dots", "num_hyphens", "is_ip",
    "has_suspicious_kw", "entropy", "age_days",
    "whois_hidden", "registrar_trust", "ssl_valid", "has_https",
]

# ── Load & Validate ────────────────────────────────────────────
print("[1/5] Loading dataset …")
if not os.path.exists(DATASET_PATH):
    print(f"[ERROR] dataset.csv not found at {DATASET_PATH}")
    sys.exit(1)

df = pd.read_csv(DATASET_PATH)
print(f"      Rows loaded : {len(df)}")
print(f"      Columns     : {list(df.columns)}")

# Drop incomplete rows
df.dropna(subset=FEATURE_COLS + ["label"], inplace=True)
df.drop_duplicates(inplace=True)

label_counts = df["label"].value_counts().to_dict()
print(f"      Class dist  : {label_counts}")

if len(df["label"].unique()) < 2:
    print("[ERROR] Need at least 2 classes in dataset.")
    sys.exit(1)

# ── Feature / Target split ─────────────────────────────────────
X = df[FEATURE_COLS].astype(float)
y_raw = df["label"].astype(str).str.upper().str.strip()

# Encode labels
le = LabelEncoder()
y  = le.fit_transform(y_raw)
print(f"[2/5] Label classes : {list(le.classes_)}")

# ── Train / Test split ─────────────────────────────────────────
print("[3/5] Splitting & training …")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# RandomForest tuned to avoid 100 % (max_depth limits overfitting)
clf = RandomForestClassifier(
    n_estimators   = 120,
    max_depth       = 12,
    min_samples_leaf= 3,
    max_features    = "sqrt",
    class_weight    = "balanced",
    random_state    = 42,
)
clf.fit(X_train, y_train)

# ── Evaluate ───────────────────────────────────────────────────
print("[4/5] Evaluating …")
y_pred  = clf.predict(X_test)
acc     = accuracy_score(y_test, y_pred) * 100
print(f"      Test accuracy : {acc:.1f}%")

# Cross-validation (5-fold) for robust estimate
cv_scores = cross_val_score(clf, X, y, cv=5, scoring="accuracy")
cv_mean   = cv_scores.mean() * 100
print(f"      CV accuracy   : {cv_mean:.1f}% ± {cv_scores.std()*100:.1f}%")

print("\n      Classification Report:")
print(classification_report(y_test, y_pred, target_names=le.classes_))

print("      Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Feature importances
print("\n      Feature Importances:")
for fname, imp in sorted(
    zip(FEATURE_COLS, clf.feature_importances_), key=lambda x: -x[1]
):
    bar = "#" * int(imp * 40)
    print(f"      {fname:<20} {imp:.4f}  {bar}")

# ── Save ───────────────────────────────────────────────────────
print("\n[5/5] Saving artefacts …")
joblib.dump(clf, MODEL_PATH)
joblib.dump(le,  ENCODER_PATH)

with open(ACCURACY_PATH, "w") as f:
    f.write(f"{acc:.2f}")

print(f"      model.pkl        -> {MODEL_PATH}")
print(f"      label_encoder.pkl-> {ENCODER_PATH}")
print(f"      model_accuracy   -> {acc:.1f}%")
print("\n[DONE] Training complete — HostTrace AI model is ready!")
