# 🛡️ PhishGuard AI — Complete Project Documentation & Interview Defense Guide

**Platform:** Advanced Phishing URL Detection & Real-Time Threat Intelligence  
**Repository:** [https://github.com/ramkishore-en/PhishGuard-ai](https://github.com/ramkishore-en/PhishGuard-ai)  
**Core Technologies:** Python 3.13, Scikit-Learn 1.6, Flask 3.1, URLhaus Threat Intel API, HTML5/CSS3/JS  
**Evaluation Benchmark:** 97.59% Accuracy, 95.24% Precision, 100% Recall, 0.9949 ROC AUC (PhiUSIIL Callset)

---

## 1. Project Elevator Pitch (How to Introduce Your Project)
> *"PhishGuard AI is an intelligent, multi-layer cybersecurity platform for real-time phishing URL detection and threat intelligence. Most phishing solutions rely either strictly on slow blacklist databases or standalone machine learning models that struggle with zero-day evasion tactics. My platform solves this using a 3-Layer Hybrid Defense:*
> 1. *Live external threat intelligence querying URLhaus in real time,*
> 2. *Rule-based heuristic pre-checks that catch severe evasion like Punycode and raw IP addresses,*
> 3. *A 30-feature Random Forest ML engine achieving 97.6% benchmark accuracy and 0.995 ROC AUC.*
> 
> *It includes an interactive cybersecurity dashboard with live URL deep scans, batch scanning with CSV export, human-readable explainability, and full automated unit testing."*

---

## 2. Problem Statement & Motivation
* **Evasion Sophistication:** Over 80% of phishing attacks now use valid HTTPS certificates, internationalized domain spoofing (Punycode `xn--`), URL shorteners (`bit.ly`), and raw IP addresses to bypass basic filters.
* **The Blacklist Gap:** Traditional blocklists take hours to days to discover and index newly registered malicious domains. Attackers exploit this window of vulnerability (zero-hour phishing).
* **The ML Gap:** ML models trained on small or artificial datasets struggle on complex legitimate web applications (such as AWS URLs, Wikipedia queries) and fail to explain why a decision was reached.
* **The PhishGuard Solution:** Combines real-time threat intelligence feeds, rule-based security heuristics, and high-dimensional machine learning into a unified real-time analysis pipeline.

---

## 3. Core Architecture: The 3-Layer Hybrid Defense

```
[Input URL]
     │
     ▼
[Layer 1: External Threat Intelligence]
 ├── Queries URLhaus (abuse.ch) live threat feeds
 ├── Sub-second non-blocking timeout fallback (0.8s)
 └── If malicious -> Instant Critical Phishing Verdict (100% Confidence)
     │ (If clean)
     ▼
[Layer 2: Rule-Based Security Heuristics]
 ├── Raw IP address detection (e.g. http://192.0.2)
 ├── Punycode & IDN homograph detection ('xn--')
 ├── Brand impersonation engine (detects PayPal, Apple, Google, Microsoft, Chase)
 ├── Userinfo credential spoofing (@ symbol) & URL shortener masks
 └── If severe evasion flag found -> Instant High Risk Phishing Verdict
     │ (If clean or warning)
     ▼
[Layer 3: 30-Signal Random Forest Machine Learning]
 ├── Extracts 30 lexical, structural, and Shannon entropy features
 ├── Predicts phishing probability using trained ensemble trees
 └── Calibration Engine outputs final verdict: Phishing, Suspicious, or Legitimate
```

---

## 4. Feature Engineering Deep Dive (The 30 Extracted Signals)

### A. Information Entropy Features (URL & Hostname)
* **Shannon Entropy:** Measures character distribution randomness. Standard domains (e.g. `google.com`) have low entropy (2.5–3.2). Machine-generated DGA domains or malware campaign links exhibit high entropy (> 3.8).

### B. Lexical & Structural Features
* **Length Dimensions:** `url_length`, `hostname_length`, `path_length`, `query_length` (phishing attacks frequently use bloated lengths to hide the true destination).
* **Character Counts:** Counts of dots (`.`), slashes (`/`), hyphens (`-`), underscores (`_`), equals (`=`), ampersands (`&`), question marks (`?`), digits, and letters.
* **Subdomain Depth:** Deeply nested subdomains (e.g. `login.secure.verify.paypal.com`) designed to deceive mobile users.

### C. Security & Deception Flags
* **Red Flags:** `has_ip_address`, `has_punycode`, `brand_impersonation`, `is_shortened`, `count_suspicious_tokens` (`login`, `verify`, `bank`, `account`, `token`, `secure`, `update`, etc.).

---

## 5. Dataset, Training & Validation Pipeline
* **Dataset Source:** Derived from the academic **PhiUSIIL Phishing URL Dataset** (one of the largest modern benchmarks in cybersecurity research).
* **Sample Size:** 830 balanced URLs (430 legitimate, 400 phishing) representing modern HTTPS phishing, edge cases, and complex legitimate web applications.
* **Partitioning:** Stratified 80/20 train/test split (`random_state=42`) maintaining exact class balance across training and evaluation partitions.
* **Model Hyperparameters:** Random Forest with `n_estimators=100`, `max_depth=6`, `min_samples_leaf=2` to ensure strong generalization without overfitting.

---

## 6. Model Evaluation & Benchmark Results

| Evaluation Metric | Score | Industry Significance |
| :--- | :--- | :--- |
| **Model Accuracy** | **97.59%** | Consistently separates legitimate and malicious traffic |
| **Precision** | **95.24%** | Low false alarm rate for genuine enterprise links |
| **Recall** | **100.00%** | Zero missed phishing attacks in evaluation callset |
| **F1 Score** | **97.56%** | Harmonized balance between precision and recall |
| **ROC AUC** | **0.9949** | Near-optimal area under the ROC curve |

### Confusion Matrix Analysis (Test Partition: N = 166)
* **True Legitimate (82):** Genuine websites correctly cleared as Legitimate.
* **False Positives (4):** Borderline legitimate URLs flagged for manual verification (realistic for enterprise security systems).
* **False Negatives (0):** Phishing URLs missed (critical security guarantee: 100% phishing threat coverage).
* **True Phishing (80):** Phishing attacks successfully detected and intercepted.

---

## 7. Software Implementation & User Interface
* **Backend:** Python 3.13, Flask REST API endpoints (`/predict` and `/batch_predict`), Scikit-Learn, Pandas, NumPy.
* **Frontend:** Modern Cyber-Glassmorphism UI, Dark/Light mode toggle with `localStorage` persistence, SVG animated radar scanners.
* **Batch Scanner:** Allows analysts to paste up to 50 URLs, inspect live progress counters, and export summary CSV reports.
* **Transparent Explainability:** Replaces black-box predictions with human-readable rationale (e.g. *"Brand impersonation detected: mentions paypal on unofficial domain"*) and an interactive 30-feature inspectable accordion.
* **Testing Suite:** 11 automated test cases in `tests/test_project.py` covering heuristics, API responses, Shannon entropy, threat intel, and artifact persistence (All tests pass with 0 errors).

---

## 8. Top 10 Technical Interview Questions & Model Answers

### Q1: Why Random Forest instead of Deep Learning (LSTM / Transformers)?
**Answer:** Random Forest was chosen for three key engineering reasons: (1) Sub-10ms inference latency required for real-time URL inspection, (2) native interpretability via Gini feature importances for cybersecurity explainability, and (3) high performance on tabular lexical features without requiring GPU infrastructure or risking deep learning overfitting.

### Q2: What is Shannon entropy and why is it useful in phishing detection?
**Answer:** Shannon entropy measures the uncertainty or character randomness in a string. Normal domains have lower entropy (2.5–3.2), whereas Domain Generation Algorithm (DGA) malware links and obfuscated phishing campaigns exhibit high character randomness (> 3.8). It provides a strong, language-agnostic predictive signal.

### Q3: How does your system detect zero-day phishing attacks not seen in training?
**Answer:** By combining 3 layers: Layer 2 checks for structural evasion tactics (Punycode homographs, raw IPs, unauthorized brand keywords), and Layer 3 evaluates lexical patterns (entropy, token frequency, subdomain depth) rather than memorizing domain names. This catches zero-day attacks even if registered minutes prior.

### Q4: How does the Brand Impersonation engine work?
**Answer:** It extracts the domain and checks for high-profile targets (PayPal, Apple, Google, Microsoft, Chase). If the keyword appears in the hostname or path but the root domain is NOT the official registered domain, Layer 2 flags it as a severe Brand Impersonation violation before model inference.

### Q5: What is a Punycode attack and how do you mitigate it?
**Answer:** Punycode enables Unicode characters in domains using the prefix `xn--`. Attackers use this for homograph attacks (e.g. swapping Latin "a" with Cyrillic "а"). Our system inspects the normalized hostname for `xn--` and raises an immediate security flag.

### Q6: What is the purpose of the 3-tier calibration engine?
**Answer:** Binary Yes/No verdicts can be too rigid. Our calibration engine maps probabilities into three tiers: Phishing ($p \ge 70\%$ or severe flag), Suspicious / Warning ($35\% \le p < 70\%$ or non-critical flags like missing HTTPS), and Legitimate ($p < 35\%$ with zero flags).

### Q7: What happens if URLhaus Threat Intelligence is unreachable?
**Answer:** We implemented resilient networking with a strict sub-second timeout (0.8s) wrapped in a `try-except` block. If the API times out or fails, the system logs a fallback warning and safely delegates evaluation to Layer 2 and Layer 3 without delaying the user.

### Q8: How did you prevent data leakage during training?
**Answer:** All 30 feature extractors are stateless functions operating strictly on the individual URL string. We utilized stratified 80/20 train/test splitting so that evaluation metrics reflect purely unseen test samples.

### Q9: Why is Recall prioritized over Precision in cybersecurity?
**Answer:** In security, a False Negative (missing a real phishing site) can cause catastrophic data breaches or credential theft. A False Positive (flagging a benign site) merely prompts user verification. Hence, achieving 100% recall on the evaluation partition was a primary engineering objective.

### Q10: How can this system scale in an enterprise production environment?
**Answer:** The service is containerized via Docker and served through WSGI (Gunicorn/Waitress). Its stateless REST API can scale horizontally across Kubernetes clusters or serverless containers behind an Nginx reverse proxy or cloud API gateway.
