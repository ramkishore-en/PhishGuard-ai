from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlparse
import pandas as pd

SUSPICIOUS_KEYWORDS = [
    'login', 'secure', 'bank', 'account', 'update', 'verify', 'confirm',
    'signin', 'click', 'free', 'bonus', 'ebayisapi', 'paypal', 'webscr',
    'cmd', 'admin', 'pay', 'banking', 'support', 'phishing', 'malicious',
    'scam', 'fraud', 'fraudulent', 'fake', 'deceptive', 'alert', 'security',
    'billing', 'service', 'claim', 'gift', 'prize', 'winner', 'recover',
    'credential', 'wallet', 'suspend', 'restricted', 'unlock', 'token'
]

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'cutt.ly', 'rebrand.ly', 'tiny.cc', 'shorturl.at',
    'qr.net', 'adf.ly', 'bc.vc', 'v.gd', 'trib.al', 'cli.re'
}

OFFICIAL_BRANDS = {
    'paypal': 'paypal.com',
    'apple': 'apple.com',
    'google': 'google.com',
    'microsoft': 'microsoft.com',
    'amazon': 'amazon.com',
    'netflix': 'netflix.com',
    'chase': 'chase.com',
    'wellsfargo': 'wellsfargo.com',
    'bankofamerica': 'bankofamerica.com',
    'facebook': 'facebook.com',
    'instagram': 'instagram.com',
    'whatsapp': 'whatsapp.com',
    'binance': 'binance.com',
    'coinbase': 'coinbase.com',
    'ebay': 'ebay.com',
    'dropbox': 'dropbox.com',
    'spotify': 'spotify.com',
    'adobe': 'adobe.com',
}

# Matches full IPv4 (e.g. 192.168.1.1), incomplete IPv4 (e.g. 192.0.2), and IPv6 ([...])
IP_PATTERN = re.compile(r"^(?:\[[a-fA-F0-9:]+\]|(?:\d{1,3}\.){1,3}\d{1,3})$")


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string (higher = more random/DGA-like)."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return float(-sum((count / total) * math.log2(count / total) for count in counts.values()))


def uses_raw_ip(hostname: str) -> int:
    """Checks whether hostname is a raw IP address (e.g., 192.0.2 or 192.168.1.1)."""
    if not hostname:
        return 0
    return 1 if IP_PATTERN.match(hostname.strip()) else 0


def uses_http(scheme: str) -> int:
    """Checks whether the scheme is insecure HTTP instead of HTTPS."""
    return 1 if scheme.lower() == 'http' else 0


def has_at_symbol(url: str) -> int:
    """Detects '@' in URL used for userinfo obfuscation / credential spoofing."""
    return 1 if '@' in url else 0


def uses_punycode(url: str, hostname: str) -> int:
    """Detects punycode 'xn--' prefix used in IDN homograph phishing attacks."""
    target = f"{url} {hostname}".lower()
    return 1 if 'xn--' in target else 0


def is_shortened_url(hostname: str) -> int:
    """Checks if hostname matches known URL shortener services."""
    host = hostname.lower()
    if host.startswith('www.'):
        host = host[4:]
    return 1 if host in URL_SHORTENERS else 0


def count_subdomains(hostname: str) -> int:
    """Accurately calculates number of subdomains by stripping www and main domain."""
    if not hostname:
        return 0
    host = hostname.lower()
    if host.startswith('www.'):
        host = host[4:]
    if uses_raw_ip(host):
        return 0
    dots = host.count('.')
    return max(0, dots - 1)


def check_brand_impersonation(url: str, hostname: str) -> tuple[str | None, str | None]:
    """
    Checks if a major target brand appears in the URL or hostname when
    the domain does not belong to that brand's official infrastructure.
    """
    host = hostname.lower()
    text = url.lower()
    for brand, official in OFFICIAL_BRANDS.items():
        if brand in text:
            # If the domain is exactly the official domain or a valid subdomain of it, it's legitimate
            if host == official or host.endswith('.' + official):
                continue
            return brand, official
    return None, None


def count_suspicious_tokens(url: str) -> int:
    text = url.lower()
    return sum(1 for token in SUSPICIOUS_KEYWORDS if token in text)


def get_heuristic_flags(url: str) -> list[dict]:
    """
    Evaluates rule-based heuristic red flags and returns structured reasons
    for why a URL is flagged as phishing or suspicious.
    """
    normalized = str(url or '').strip()
    if not normalized:
        return []

    if '://' not in normalized:
        normalized = 'http://' + normalized

    parsed = urlparse(normalized)
    hostname = parsed.hostname or ''
    scheme = parsed.scheme or ''

    flags = []

    # 1. Raw IP Address Check (Severe Red Flag)
    if uses_raw_ip(hostname):
        flags.append({
            'flag': 'RAW_IP',
            'severity': 'high',
            'reason': f"Uses raw IP address ('{hostname}') instead of a registered domain name."
        })

    # 2. Punycode Check (Severe Red Flag)
    if uses_punycode(normalized, hostname):
        flags.append({
            'flag': 'PUNYCODE',
            'severity': 'high',
            'reason': "Punycode ('xn--') detected - Potential internationalized domain homograph attack."
        })

    # 3. Contains '@' Symbol (Severe Red Flag)
    if has_at_symbol(normalized):
        flags.append({
            'flag': 'AT_SYMBOL',
            'severity': 'high',
            'reason': "Contains '@' symbol used for URL obfuscation and credential spoofing."
        })

    # 4. Brand Impersonation Check (Severe Red Flag)
    brand, official = check_brand_impersonation(normalized, hostname)
    if brand:
        flags.append({
            'flag': 'BRAND_IMPERSONATION',
            'severity': 'high',
            'reason': f"Brand impersonation detected: mentions '{brand}' but domain is not '{official}'."
        })

    # 5. Missing HTTPS (Warning Flag)
    if uses_http(scheme):
        flags.append({
            'flag': 'INSECURE_HTTP',
            'severity': 'warning',
            'reason': "Missing HTTPS encryption (Insecure HTTP protocol)."
        })

    # 6. URL Shortener (Warning Flag)
    if is_shortened_url(hostname):
        flags.append({
            'flag': 'SHORTENED_URL',
            'severity': 'warning',
            'reason': f"Uses URL shortening service ('{hostname}') which masks the destination address."
        })

    # 7. Subdomain Count (Warning Flag)
    subdomains = count_subdomains(hostname)
    if subdomains >= 3:
        flags.append({
            'flag': 'EXCESSIVE_SUBDOMAINS',
            'severity': 'warning',
            'reason': f"Excessive subdomains ({subdomains} subdomains detected) - Domain masking risk."
        })

    # 8. Character Entropy (Warning Flag)
    host_entropy = calculate_entropy(hostname)
    if host_entropy >= 3.8 and len(hostname) >= 12 and not uses_raw_ip(hostname):
        flags.append({
            'flag': 'HIGH_ENTROPY',
            'severity': 'warning',
            'reason': f"Unusually high character entropy ({host_entropy:.2f}) indicating randomized DGA domain."
        })

    # 9. Suspicious Keywords (Warning Flag)
    suspicious_count = count_suspicious_tokens(normalized)
    if suspicious_count >= 2:
        flags.append({
            'flag': 'SUSPICIOUS_KEYWORDS',
            'severity': 'warning',
            'reason': f"Contains multiple high-risk credential/banking keywords ({suspicious_count} detected)."
        })

    return flags


def get_url_features(url: str) -> dict:
    """Extracts a comprehensive numeric feature vector for Random Forest classification."""
    if not isinstance(url, str):
        url = str(url) if url is not None else ""

    normalized = url.strip()
    if not normalized:
        normalized = ""

    if "://" not in normalized:
        normalized = "http://" + normalized

    parsed = urlparse(normalized)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    port = parsed.port or 0
    scheme = parsed.scheme or ""

    brand, _ = check_brand_impersonation(normalized, hostname)

    features = {
        'url_length': len(normalized),
        'hostname_length': len(hostname),
        'path_length': len(path),
        'query_length': len(query),
        'entropy_url': round(calculate_entropy(normalized), 4),
        'entropy_hostname': round(calculate_entropy(hostname), 4),
        'count_dots': normalized.count('.'),
        'count_hyphens': normalized.count('-'),
        'count_underscores': normalized.count('_'),
        'count_at': normalized.count('@'),
        'count_question': normalized.count('?'),
        'count_equal': normalized.count('='),
        'count_ampersand': normalized.count('&'),
        'count_slash': normalized.count('/'),
        'count_www': 1 if hostname.startswith('www.') else 0,
        'count_digits': sum(char.isdigit() for char in normalized),
        'count_letters': sum(char.isalpha() for char in normalized),
        'count_suspicious_tokens': count_suspicious_tokens(normalized),
        'has_https': 1 if scheme == 'https' else 0,
        'has_ip_address': uses_raw_ip(hostname),
        'has_port': 1 if port else 0,
        'hostname_has_dash': 1 if '-' in hostname else 0,
        'path_depth': path.count('/') if path else 0,
        'has_long_url': 1 if len(normalized) > 75 else 0,
        'has_at_symbol': has_at_symbol(normalized),
        'has_double_slash': 1 if '//' in path else 0,
        'has_punycode': uses_punycode(normalized, hostname),
        'is_shortened': is_shortened_url(hostname),
        'subdomain_count': count_subdomains(hostname),
        'brand_impersonation': 1 if brand else 0,
    }

    return features


def extract_features_from_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    url_column = None
    for candidate in ['URL', 'url', 'Url', 'uri', 'URI']:
        if candidate in df.columns:
            url_column = candidate
            break

    if url_column is None:
        raise ValueError("DataFrame must contain a URL column (e.g., 'URL' or 'url').")

    feature_rows = [get_url_features(url) for url in df[url_column].fillna("")]
    return pd.DataFrame(feature_rows)
