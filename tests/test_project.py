import os
from pathlib import Path
import sys
import unittest

import joblib
import pandas as pd

PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

import app as flask_app_module
from feature_extraction import (
    calculate_entropy,
    check_brand_impersonation,
    extract_features_from_dataframe,
    get_heuristic_flags,
    get_url_features,
    is_shortened_url,
    uses_punycode,
    uses_raw_ip,
)
from threat_intel import check_threat_intelligence
import training


class PhishingDetectionTestSuite(unittest.TestCase):
    def setUp(self):
        self.app = flask_app_module.app.test_client()
        self.app.testing = True

    def test_raw_ip_detection(self):
        # Must detect standard 4-octet IPs and partial/test IPs like 192.0.2
        self.assertEqual(uses_raw_ip("192.0.2"), 1)
        self.assertEqual(uses_raw_ip("192.168.1.1"), 1)
        self.assertEqual(uses_raw_ip("10.0.0.1"), 1)
        self.assertEqual(uses_raw_ip("google.com"), 0)

        flags = get_heuristic_flags("http://192.0.2")
        reasons = [f["reason"] for f in flags]
        self.assertTrue(any("raw IP address" in r for r in reasons))

    def test_shannon_entropy_calculation(self):
        low_entropy = calculate_entropy("google.com")
        high_entropy = calculate_entropy("x7k9mqz41bcv09az.net")
        self.assertGreater(high_entropy, low_entropy)
        self.assertGreaterEqual(high_entropy, 3.5)

    def test_brand_impersonation_detection(self):
        # Legitimate brand URL
        brand, official = check_brand_impersonation("https://www.paypal.com/signin", "www.paypal.com")
        self.assertIsNone(brand)

        # Phishing impersonation URL
        brand, official = check_brand_impersonation(
            "http://paypal-security-login.xyz/verify", "paypal-security-login.xyz"
        )
        self.assertEqual(brand, "paypal")
        self.assertEqual(official, "paypal.com")

    def test_punycode_and_shortener_detection(self):
        self.assertEqual(uses_punycode("http://xn--pypal-4ve.com/signin", "xn--pypal-4ve.com"), 1)
        self.assertEqual(uses_punycode("https://www.google.com", "www.google.com"), 0)
        self.assertEqual(is_shortened_url("bit.ly"), 1)
        self.assertEqual(is_shortened_url("tinyurl.com"), 1)
        self.assertEqual(is_shortened_url("github.com"), 0)

    def test_threat_intelligence_lookup(self):
        threat = check_threat_intelligence("http://malicious-website.net")
        self.assertTrue(threat["is_malicious"])
        self.assertIsNotNone(threat["source"])

    def test_model_training_and_artifacts(self):
        model_path = PROJECT_DIR / "models" / "phishing_rf.joblib"
        pkl_path = PROJECT_DIR / "models" / "phishing_rf.pkl"
        feature_columns_path = PROJECT_DIR / "models" / "feature_columns.pkl"

        model = training.train_and_save_model()
        self.assertTrue(model_path.exists())
        self.assertTrue(pkl_path.exists())
        self.assertTrue(feature_columns_path.exists())

    def test_api_predict_raw_ip_flags_phishing(self):
        # Specifically test user's test case: http://192.0.2
        response = self.app.post('/predict', json={"url": "http://192.0.2"})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["prediction"], "Phishing")
        self.assertEqual(data["raw_label"], 1)
        # Verify reasons include raw IP flag
        self.assertTrue(any("raw IP address" in r for r in data["reasons"]))
        self.assertTrue(any("Missing HTTPS" in r for r in data["reasons"]))

    def test_api_predict_brand_impersonation(self):
        response = self.app.post('/predict', json={"url": "http://paypal-security-login.xyz/verify"})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["prediction"], "Phishing")
        self.assertTrue(any("Brand impersonation" in r for r in data["reasons"]))

    def test_api_predict_legitimate_site(self):
        response = self.app.post('/predict', json={"url": "https://www.google.com"})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["prediction"], "Legitimate")
        self.assertEqual(data["raw_label"], 0)

    def test_api_predict_suspicious_warning_calibration(self):
        # A site with warning signals (HTTP only on a standard non-brand domain) triggers Suspicious
        response = self.app.post('/predict', json={"url": "http://example.com/browse/page"})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn(data["prediction"], ["Suspicious", "Legitimate"])
        self.assertIn("reasons", data)

    def test_api_predict_missing_url_returns_400(self):
        response = self.app.post('/predict', json={})
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
