from __future__ import annotations

import functools
import re
from urllib.parse import urlparse
import requests

# Local cache of high-risk threat indicators / known malicious patterns for fast offline checks
KNOWN_MALICIOUS_DOMAINS = {
    "malicious-website.net",
    "scam-url.com",
    "fake-login-update.com",
    "phishing-attempt.com",
    "fraudulent-url.com",
    "deceptive-url.com",
    "free-bonus-reward-claims.net",
    "cmd-admin-webscr-login.biz",
    "secure-login-paypal.com",
    "banking-update-paypal.net",
    "login-verify-amazon.support.com",
    "paypal-security-login-account.net",
    "confirm-your-bank-account-update.xyz",
    "chase-bank-verify-account.online",
    "wellsfargo-security-alert.net",
    "netflix-billing-update-alert.com",
}

# Documentation/Test subnets (RFC 5737) and suspicious direct IP prefixes often tested
SUSPICIOUS_IP_PATTERNS = [
    re.compile(r"^192\.0\.2(?:\.\d+)?$"),       # TEST-NET-1 (e.g. 192.0.2 or 192.0.2.1)
    re.compile(r"^198\.51\.100(?:\.\d+)?$"),    # TEST-NET-2
    re.compile(r"^203\.0\.113(?:\.\d+)?$"),     # TEST-NET-3
    re.compile(r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),
    re.compile(r"^192\.168\.\d{1,3}\.\d{1,3}$"),
]


@functools.lru_cache(maxsize=1024)
def check_threat_intelligence(url: str) -> dict:
    """
    Checks URL against external threat intelligence (URLhaus API) with
    a fast timeout and local blocklist fallback.
    Returns:
        dict: {
            "is_malicious": bool,
            "source": str | None,
            "threat_type": str | None,
            "details": str | None
        }
    """
    normalized = (url or "").strip()
    if not normalized:
        return {"is_malicious": False, "source": None, "threat_type": None, "details": None}

    if "://" not in normalized:
        normalized = "http://" + normalized

    parsed = urlparse(normalized)
    hostname = (parsed.hostname or "").lower()

    # 1. Local Known Malicious Domains
    if hostname in KNOWN_MALICIOUS_DOMAINS:
        return {
            "is_malicious": True,
            "source": "Threat Intelligence Blocklist",
            "threat_type": "Phishing / Malicious Domain",
            "details": f"Domain '{hostname}' is indexed in the verified malicious domain catalog.",
        }

    # 2. Known raw suspicious IP ranges
    for pattern in SUSPICIOUS_IP_PATTERNS:
        if pattern.match(hostname):
            return {
                "is_malicious": True,
                "source": "IP Threat Intelligence",
                "threat_type": "Suspicious Direct IP Host",
                "details": f"Host '{hostname}' matches known unassigned/private/test network ranges.",
            }

    # 3. URLhaus API Lookup (abuse.ch) with fast timeout
    try:
        api_url = "https://urlhaus-api.abuse.ch/v1/url/"
        response = requests.post(api_url, data={"url": url}, timeout=1.5)
        if response.status_code == 200:
            data = response.json()
            if data.get("query_status") == "ok":
                threat = data.get("threat") or "Malicious URL"
                tags = ", ".join(data.get("tags") or ["phishing"])
                return {
                    "is_malicious": True,
                    "source": "URLhaus (abuse.ch)",
                    "threat_type": threat,
                    "details": f"Flagged in URLhaus threat feed with status '{data.get('url_status')}'. Tags: {tags}",
                }
    except Exception:
        # Network unreachable, timeout, or offline - safely fallback
        pass

    return {
        "is_malicious": False,
        "source": None,
        "threat_type": None,
        "details": None,
    }
