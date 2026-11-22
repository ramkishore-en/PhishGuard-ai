import os
from pathlib import Path
import sys

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import joblib
import pandas as pd
from flask import Flask, jsonify, render_template, request

from feature_extraction import get_heuristic_flags, get_url_features
from threat_intel import check_threat_intelligence

app = Flask(__name__)

MODEL_PATH = BASE_DIR / 'models' / 'phishing_rf.joblib'
FEATURE_COLUMNS_PATH = BASE_DIR / 'models' / 'feature_columns.pkl'

if not MODEL_PATH.exists() or not FEATURE_COLUMNS_PATH.exists():
    from training import train_and_save_model
    train_and_save_model()

model = joblib.load(MODEL_PATH)
feature_columns = joblib.load(FEATURE_COLUMNS_PATH)


def classify_url(url: str) -> dict:
    url_clean = str(url or "").strip()
    if not url_clean:
        return {"error": "URL is required."}

    # 1. Feature Extraction
    features = get_url_features(url_clean)

    # 2. Rule-Based Heuristic Pre-Checks
    flags = get_heuristic_flags(url_clean)
    severe_flags = [f for f in flags if f.get("severity") == "high"]
    warning_flags = [f for f in flags if f.get("severity") == "warning"]
    reasons = [f["reason"] for f in flags]

    # 3. External Threat Intelligence Check (URLhaus / Blocklists)
    threat = check_threat_intelligence(url_clean)
    if threat.get("is_malicious"):
        threat_reason = threat.get("details") or f"Identified as malicious in {threat.get('source')}."
        combined_reasons = [threat_reason] + [r for r in reasons if r != threat_reason]
        combined_flags = [{"flag": "THREAT_INTEL", "severity": "high", "reason": threat_reason}] + flags
        return {
            "url": url_clean,
            "prediction": "Phishing",
            "risk_level": "Critical / Blocklisted",
            "confidence": 100.0,
            "raw_label": 1,
            "reasons": combined_reasons,
            "flags": combined_flags,
            "threat_intel": threat,
            "phishing_prob": 100.0,
            "features": features,
        }

    # 4. Model Scoring
    feature_df = pd.DataFrame([features]).reindex(columns=feature_columns, fill_value=0)
    probabilities = model.predict_proba(feature_df)[0]
    p_phish = float(probabilities[1]) if len(probabilities) > 1 else float(probabilities[0])

    # 5. Calibration & Multi-Level Decision Engine
    if len(severe_flags) >= 1:
        prediction = "Phishing"
        risk_level = "High Risk"
        confidence = float(max(96.0, round(max(p_phish, 0.96) * 100, 2)))
        raw_label = 1
    elif p_phish >= 0.70:
        prediction = "Phishing"
        risk_level = "High Risk"
        confidence = float(round(p_phish * 100, 2))
        raw_label = 1
    elif p_phish >= 0.35 or len(warning_flags) >= 1:
        prediction = "Suspicious"
        risk_level = "Moderate Risk / Warning"
        confidence = float(round(max(p_phish, 1.0 - p_phish) * 100, 2))
        raw_label = 2
    else:
        prediction = "Legitimate"
        risk_level = "Low Risk / Safe"
        confidence = float(round((1.0 - p_phish) * 100, 2))
        raw_label = 0
        if not reasons:
            reasons = [
                "Passed all heuristic security checks",
                "Valid HTTPS encryption present",
                "Standard domain and path structure"
            ]

    return {
        "url": url_clean,
        "prediction": prediction,
        "risk_level": risk_level,
        "confidence": confidence,
        "raw_label": raw_label,
        "reasons": reasons,
        "flags": flags,
        "threat_intel": threat,
        "phishing_prob": float(round(p_phish * 100, 2)),
        "features": features,
    }


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json(silent=True) or request.form
    url = (data or {}).get('url', '')

    if not url or not str(url).strip():
        return jsonify({'error': 'URL is required.'}), 400

    result = classify_url(str(url).strip())
    if "error" in result:
        return jsonify(result), 400

    return jsonify(result)


@app.route('/api/predict', methods=['POST'])
def api_predict():
    return predict()


@app.route('/batch_predict', methods=['POST'])
def batch_predict():
    data = request.get_json(silent=True) or {}
    urls = data.get('urls', [])
    if not isinstance(urls, list):
        return jsonify({'error': 'urls must be a list of URL strings.'}), 400

    clean_urls = [str(u).strip() for u in urls if str(u).strip()][:50]
    results = [classify_url(u) for u in clean_urls]
    return jsonify({'results': results, 'total': len(results)})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
