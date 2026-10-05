"""
risk_engine.py
===============
Layer 3-7 of the PhishGuard AI multi-layer detection pipeline.

Combines:
  - Random Forest ML
  - Domain intelligence
  - Known-legitimate allowlist
  - Deterministic suspicious signals
  - SSL/TLS certificate analysis
  - Brand impersonation
  - Transparent weighted risk scoring
"""

from urllib.parse import urlparse


# =============================================================================
# SUSPICIOUS SIGNAL CONSTANTS
# =============================================================================

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",
    "top", "xyz", "click", "work",
    "support", "zip", "mov", "cam",
    "pw", "cc", "ru", "su", "ws",
    "biz", "info",
    "me",
}

COMMON_TLDS = {
    "com", "org", "net", "edu", "gov",
    "io", "co", "uk", "de", "fr", "jp"
}

PHISHING_KEYWORDS = [
    "login", "verify", "verification", "account", "update",
    "secure", "security", "signin", "sign-in", "banking",
    "password", "credential", "wallet", "confirm", "payment",
    "billing", "auth", "token", "session", "unlock", "recover",
    "suspend", "validate", "activate", "webscr", "ebayisapi",
    "helpdesk", "support",
]

SHORTENING_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly", "rebrand.ly",
    "shorturl.at", "tiny.cc", "rb.gy",
}


# =============================================================================
# BRAND IMPERSONATION
# =============================================================================

_BRAND_MAX_CONTRIBUTION = 35
_BRAND_HIGH_CONFIDENCE = 25
_BRAND_MED_CONFIDENCE = 20
_BRAND_LOW_CONFIDENCE = 12
_BRAND_CONTEXT_BONUS = 8
_BRAND_SUSPICIOUS_TLD_BONUS = 5


# =============================================================================
# SSL/TLS WEIGHTS
# =============================================================================

SSL_INVALID_CERT = 10
SSL_HOSTNAME_MISMATCH = 15
SSL_CERT_UNAVAILABLE = 8


# =============================================================================
# LAYER 4: DETERMINISTIC SUSPICIOUS SIGNALS
# =============================================================================

def compute_suspicious_signals(url: str, domain_intel: dict) -> dict:

    parsed = urlparse(url)

    hostname = domain_intel.get("hostname", "")
    tld = domain_intel.get("tld", "")
    scheme = domain_intel.get("scheme", "")
    is_ip = domain_intel.get("is_ip_address", False)

    full_url_lower = url.lower()

    signals = {}

    # -------------------------------------------------------------------------
    # Transport
    # -------------------------------------------------------------------------

    signals["uses_https"] = (scheme == "https")

    # -------------------------------------------------------------------------
    # TLD
    # -------------------------------------------------------------------------

    signals["suspicious_tld"] = (
        tld in SUSPICIOUS_TLDS
    )

    signals["common_tld"] = (
        tld in COMMON_TLDS
    )

    # -------------------------------------------------------------------------
    # Hostname structure
    # -------------------------------------------------------------------------

    signals["is_ip_address"] = is_ip

    hyphen_count = hostname.count("-")

    signals["hyphen_count"] = hyphen_count
    signals["excessive_hyphens"] = (
        hyphen_count >= 3
    )

    subdomain = domain_intel.get(
        "subdomain",
        ""
    )

    subdomain_parts = (
        [p for p in subdomain.split(".") if p]
        if subdomain
        else []
    )

    signals["subdomain_depth"] = len(
        subdomain_parts
    )

    signals["excessive_subdomains"] = (
        len(subdomain_parts) >= 3
    )

    hostname_len = len(hostname)

    signals["long_hostname"] = (
        hostname_len >= 30
    )

    signals["hostname_length"] = hostname_len

    # -------------------------------------------------------------------------
    # Digits
    # -------------------------------------------------------------------------

    digit_count = sum(
        c.isdigit()
        for c in hostname
    )

    digit_ratio = (
        digit_count / hostname_len
        if hostname_len
        else 0
    )

    signals["digit_heavy_hostname"] = (
        digit_ratio > 0.4
    )

    # -------------------------------------------------------------------------
    # Hostname entropy
    # -------------------------------------------------------------------------

    hostname_entropy = domain_intel.get(
        "hostname_entropy",
        0.0
    )

    signals["hostname_entropy"] = hostname_entropy

    signals["high_hostname_entropy"] = (
        hostname_entropy > 4.0
    )

    # -------------------------------------------------------------------------
    # URL structure
    # -------------------------------------------------------------------------

    url_len = len(url)

    signals["url_length"] = url_len

    signals["very_long_url"] = (
        url_len > 100
    )

    signals["has_at_symbol"] = (
        "@" in url
    )

    signals["has_double_slash_in_path"] = (
        "//" in parsed.path
    )

    # -------------------------------------------------------------------------
    # Encoded characters
    # -------------------------------------------------------------------------

    percent_count = url.count("%")

    signals["encoded_character_count"] = (
        percent_count
    )

    signals["has_encoded_characters"] = (
        percent_count > 3
    )

    # -------------------------------------------------------------------------
    # Port
    # -------------------------------------------------------------------------

    try:
        port = parsed.port
    except ValueError:
        port = None

    signals["non_standard_port"] = (
        port is not None
        and port not in (80, 443)
    )

    signals["port"] = port

    # -------------------------------------------------------------------------
    # Phishing keywords
    # -------------------------------------------------------------------------

    found_keywords = [
        kw
        for kw in PHISHING_KEYWORDS
        if kw in full_url_lower
    ]

    signals["phishing_keyword_count"] = (
        len(found_keywords)
    )

    signals["found_keywords"] = found_keywords

    signals["high_keyword_risk"] = (
        len(found_keywords) >= 3
    )

    # -------------------------------------------------------------------------
    # URL shortener
    # -------------------------------------------------------------------------

    reg_domain = domain_intel.get(
        "registrable_domain",
        ""
    )

    signals["is_url_shortener"] = (
        reg_domain in SHORTENING_DOMAINS
    )

    # -------------------------------------------------------------------------
    # DNS
    # -------------------------------------------------------------------------

    signals["dns_resolved"] = (
        domain_intel.get(
            "dns_resolved",
            False
        )
    )

    # -------------------------------------------------------------------------
    # @ spoofing
    # -------------------------------------------------------------------------

    signals["at_in_url_spoofing_risk"] = (
        "@" in url
        and not is_ip
    )

    return signals


# =============================================================================
# LAYER 5: RISK SCORING
# =============================================================================

SIGNAL_WEIGHTS = {

    # ML
    "known_legitimate_domain": -45,

    # Transport
    "no_https": 8,

    # TLD
    "suspicious_tld": 15,

    # IP / DNS
    "is_ip_address": 12,
    "dns_not_resolved": 10,

    # Hostname
    "excessive_hyphens": 8,
    "excessive_subdomains": 6,
    "long_hostname": 5,
    "high_hostname_entropy": 6,
    "digit_heavy_hostname": 5,

    # URL
    "very_long_url": 5,
    "has_at_symbol": 10,
    "has_encoded_characters": 5,
    "non_standard_port": 5,

    # Keywords
    "high_keyword_risk": 12,
    "medium_keyword_risk": 6,

    # Shortener
    "is_url_shortener": 8,

    # SSL
    "ssl_invalid_certificate": SSL_INVALID_CERT,
    "ssl_hostname_mismatch": SSL_HOSTNAME_MISMATCH,
    "ssl_certificate_unavailable": SSL_CERT_UNAVAILABLE,
}


THRESHOLD_PHISHING = 55
THRESHOLD_SUSPICIOUS = 35


# =============================================================================
# MAIN RISK ENGINE
# =============================================================================

def compute_risk_score(
    ml_phishing_probability: float,
    domain_intel: dict,
    signals: dict,
    ssl_analysis: dict = None,
) -> dict:

    score = 0.0

    breakdown = {}

    reasons = []


    # =========================================================================
    # LAYER 1: ML
    # =========================================================================

    ml_contribution = (
        ml_phishing_probability * 40.0
    )

    score += ml_contribution

    breakdown["ml_model"] = round(
        ml_contribution,
        2
    )


    if ml_phishing_probability >= 0.85:

        reasons.append(
            f"ML model gives a high phishing probability "
            f"({ml_phishing_probability * 100:.1f}%)"
        )

    elif ml_phishing_probability >= 0.5:

        reasons.append(
            f"ML model gives a moderate phishing probability "
            f"({ml_phishing_probability * 100:.1f}%)"
        )

    else:

        reasons.append(
            f"ML model gives a low phishing probability "
            f"({ml_phishing_probability * 100:.1f}%)"
        )


    # =========================================================================
    # LAYER 3: TRUSTED DOMAIN
    # =========================================================================

    is_known_legit = domain_intel.get(
        "is_known_legitimate",
        False
    )

    allowlist_entry = domain_intel.get(
        "allowlist_entry"
    )


    if is_known_legit:

        allowlist_adj = (
            SIGNAL_WEIGHTS[
                "known_legitimate_domain"
            ]
        )

        score += allowlist_adj

        breakdown["allowlist_credit"] = (
            allowlist_adj
        )

        reasons.append(
            f"Domain '{allowlist_entry}' "
            "is present in the trusted domain list"
        )

    else:

        breakdown["allowlist_credit"] = 0


    # =========================================================================
    # HTTPS
    # =========================================================================

    if not signals.get(
        "uses_https",
        False
    ):

        score += SIGNAL_WEIGHTS[
            "no_https"
        ]

        breakdown["no_https"] = (
            SIGNAL_WEIGHTS["no_https"]
        )

        reasons.append(
            "Connection uses HTTP (no encryption)"
        )

    else:

        breakdown["no_https"] = 0

        reasons.append(
            "HTTPS is enabled"
        )


    # =========================================================================
    # TLD
    # =========================================================================

    if signals.get(
        "suspicious_tld",
        False
    ):

        score += SIGNAL_WEIGHTS[
            "suspicious_tld"
        ]

        breakdown["suspicious_tld"] = (
            SIGNAL_WEIGHTS["suspicious_tld"]
        )

        tld = domain_intel.get(
            "tld",
            ""
        )

        reasons.append(
            f"TLD '.{tld}' is frequently associated with abuse"
        )

    else:

        breakdown["suspicious_tld"] = 0

        if not signals.get(
            "common_tld",
            False
        ):

            reasons.append(
                "TLD is uncommon but not flagged as suspicious"
            )

        else:

            reasons.append(
                "TLD is commonly used by legitimate sites"
            )


    # =========================================================================
    # IP ADDRESS
    # =========================================================================

    if signals.get(
        "is_ip_address",
        False
    ):

        score += SIGNAL_WEIGHTS[
            "is_ip_address"
        ]

        breakdown["is_ip_address"] = (
            SIGNAL_WEIGHTS["is_ip_address"]
        )

        reasons.append(
            "Hostname is a raw IP address "
            "(unusual for legitimate sites)"
        )

    else:

        breakdown["is_ip_address"] = 0


    # =========================================================================
    # DNS
    # =========================================================================

    if not signals.get(
        "dns_resolved",
        True
    ):

        score += SIGNAL_WEIGHTS[
            "dns_not_resolved"
        ]

        breakdown["dns_not_resolved"] = (
            SIGNAL_WEIGHTS["dns_not_resolved"]
        )

        reasons.append(
            "Domain does not resolve in DNS"
        )

    else:

        breakdown["dns_not_resolved"] = 0


    # =========================================================================
    # HYphens
    # =========================================================================

    if signals.get(
        "excessive_hyphens",
        False
    ):

        score += SIGNAL_WEIGHTS[
            "excessive_hyphens"
        ]

        breakdown["excessive_hyphens"] = (
            SIGNAL_WEIGHTS[
                "excessive_hyphens"
            ]
        )

        reasons.append(
            f"Hostname contains "
            f"{signals.get('hyphen_count', 0)} "
            "hyphens (excessive)"
        )

    else:

        breakdown["excessive_hyphens"] = 0


    # =========================================================================
    # SUBDOMAINS
    # =========================================================================

    if signals.get(
        "excessive_subdomains",
        False
    ):

        score += SIGNAL_WEIGHTS[
            "excessive_subdomains"
        ]

        breakdown["excessive_subdomains"] = (
            SIGNAL_WEIGHTS[
                "excessive_subdomains"
            ]
        )

        reasons.append(
            f"Hostname has "
            f"{signals.get('subdomain_depth', 0)} "
            "subdomain levels (unusual depth)"
        )

    else:

        breakdown["excessive_subdomains"] = 0


    # =========================================================================
    # LONG HOSTNAME
    # =========================================================================

    if signals.get(
        "long_hostname",
        False
    ):

        score += SIGNAL_WEIGHTS[
            "long_hostname"
        ]

        breakdown["long_hostname"] = (
            SIGNAL_WEIGHTS[
                "long_hostname"
            ]
        )

        reasons.append(
            f"Hostname is very long "
            f"({signals.get('hostname_length', 0)} chars)"
        )

    else:

        breakdown["long_hostname"] = 0


    # =========================================================================
    # HOSTNAME ENTROPY
    # =========================================================================

    if signals.get(
        "high_hostname_entropy",
        False
    ):

        score += SIGNAL_WEIGHTS[
            "high_hostname_entropy"
        ]

        breakdown["high_hostname_entropy"] = (
            SIGNAL_WEIGHTS[
                "high_hostname_entropy"
            ]
        )

        reasons.append(
            f"Hostname has high character entropy "
            f"({signals.get('hostname_entropy', 0):.2f}), "
            "suggesting randomness"
        )

    else:

        breakdown["high_hostname_entropy"] = 0


    # =========================================================================
    # DIGIT HEAVY
    # =========================================================================

    if signals.get(
        "digit_heavy_hostname",
        False
    ):

        score += SIGNAL_WEIGHTS[
            "digit_heavy_hostname"
        ]

        breakdown["digit_heavy_hostname"] = (
            SIGNAL_WEIGHTS[
                "digit_heavy_hostname"
            ]
        )

        reasons.append(
            "Hostname contains an unusually high proportion of digits"
        )

    else:

        breakdown["digit_heavy_hostname"] = 0


    # =========================================================================
    # VERY LONG URL
    # =========================================================================

    if signals.get(
        "very_long_url",
        False
    ):

        score += SIGNAL_WEIGHTS[
            "very_long_url"
        ]

        breakdown["very_long_url"] = (
            SIGNAL_WEIGHTS[
                "very_long_url"
            ]
        )

        reasons.append(
            f"URL is very long "
            f"({signals.get('url_length', 0)} chars)"
        )

    else:

        breakdown["very_long_url"] = 0


    # =========================================================================
    # @ SYMBOL
    # =========================================================================

    if signals.get(
        "has_at_symbol",
        False
    ):

        score += SIGNAL_WEIGHTS[
            "has_at_symbol"
        ]

        breakdown["has_at_symbol"] = (
            SIGNAL_WEIGHTS[
                "has_at_symbol"
            ]
        )

        reasons.append(
            "URL contains an '@' symbol — "
            "a known phishing technique to spoof hostnames"
        )

    else:

        breakdown["has_at_symbol"] = 0


    # =========================================================================
    # ENCODED CHARACTERS
    # =========================================================================

    if signals.get(
        "has_encoded_characters",
        False
    ):

        score += SIGNAL_WEIGHTS[
            "has_encoded_characters"
        ]

        breakdown["has_encoded_characters"] = (
            SIGNAL_WEIGHTS[
                "has_encoded_characters"
            ]
        )

        reasons.append(
            f"URL contains "
            f"{signals.get('encoded_character_count', 0)} "
            "percent-encoded characters"
        )

    else:

        breakdown["has_encoded_characters"] = 0


    # =========================================================================
    # NON-STANDARD PORT
    # =========================================================================

    if signals.get(
        "non_standard_port",
        False
    ):

        score += SIGNAL_WEIGHTS[
            "non_standard_port"
        ]

        breakdown["non_standard_port"] = (
            SIGNAL_WEIGHTS[
                "non_standard_port"
            ]
        )

        reasons.append(
            f"URL uses non-standard port "
            f"{signals.get('port')}"
        )

    else:

        breakdown["non_standard_port"] = 0


    # =========================================================================
    # KEYWORDS
    # =========================================================================

    kw_count = signals.get(
        "phishing_keyword_count",
        0
    )


    if signals.get(
        "high_keyword_risk",
        False
    ):

        score += SIGNAL_WEIGHTS[
            "high_keyword_risk"
        ]

        breakdown["keyword_risk"] = (
            SIGNAL_WEIGHTS[
                "high_keyword_risk"
            ]
        )

        kws = ", ".join(
            signals.get(
                "found_keywords",
                []
            )[:5]
        )

        reasons.append(
            f"URL contains multiple phishing-related "
            f"keywords: [{kws}]"
        )


    elif kw_count >= 1:

        score += SIGNAL_WEIGHTS[
            "medium_keyword_risk"
        ]

        breakdown["keyword_risk"] = (
            SIGNAL_WEIGHTS[
                "medium_keyword_risk"
            ]
        )

        kws = ", ".join(
            signals.get(
                "found_keywords",
                []
            )
        )

        reasons.append(
            f"URL contains a phishing-related "
            f"keyword: [{kws}]"
        )


    else:

        breakdown["keyword_risk"] = 0

        reasons.append(
            "No phishing-related keywords detected in the URL"
        )


    # =========================================================================
    # URL SHORTENER
    # =========================================================================

    if signals.get(
        "is_url_shortener",
        False
    ):

        score += SIGNAL_WEIGHTS[
            "is_url_shortener"
        ]

        breakdown["is_url_shortener"] = (
            SIGNAL_WEIGHTS[
                "is_url_shortener"
            ]
        )

        reasons.append(
            "URL uses a known URL-shortening service "
            "(destination is hidden)"
        )

    else:

        breakdown["is_url_shortener"] = 0


    # =========================================================================
    # SSL / TLS ANALYSIS
    # =========================================================================

    # ssl_analysis is optional so existing callers don't break.
    if ssl_analysis is None:
        ssl_analysis = {}


    ssl_status = ssl_analysis.get(
        "status"
    )

    ssl_contribution = 0


    # -------------------------------------------------------------------------
    # Hostname mismatch gets the strongest SSL penalty.
    # -------------------------------------------------------------------------

    if (
        ssl_analysis.get(
            "certificate_available",
            False
        )
        and not ssl_analysis.get(
            "hostname_match",
            True
        )
    ):

        ssl_contribution = SSL_HOSTNAME_MISMATCH

        score += ssl_contribution

        reasons.append(
            "TLS certificate does not match the requested hostname"
        )


    # -------------------------------------------------------------------------
    # Certificate exists but is invalid/expired.
    # -------------------------------------------------------------------------

    elif (
        ssl_analysis.get(
            "certificate_available",
            False
        )
        and not ssl_analysis.get(
            "certificate_valid",
            True
        )
    ):

        ssl_contribution = SSL_INVALID_CERT

        score += ssl_contribution

        reasons.append(
            "TLS certificate is not currently valid"
        )


    # -------------------------------------------------------------------------
    # Certificate unavailable / verification failed.
    # -------------------------------------------------------------------------

    elif ssl_status in {
        "certificate_unavailable",
        "verification_failed",
    }:

        ssl_contribution = SSL_CERT_UNAVAILABLE

        score += ssl_contribution

        reasons.append(
            "TLS certificate could not be fully verified"
        )


    # -------------------------------------------------------------------------
    # Valid certificate.
    # -------------------------------------------------------------------------

    elif (
        ssl_analysis.get(
            "https_enabled",
            False
        )
        and ssl_analysis.get(
            "certificate_valid",
            False
        )
        and ssl_analysis.get(
            "hostname_match",
            False
        )
    ):

        ssl_contribution = 0

        reasons.append(
            "TLS certificate is valid and matches the hostname"
        )


    # HTTP / not applicable
    elif ssl_status == "not_applicable":

        ssl_contribution = 0


    # Store contribution even when zero.
    breakdown["ssl_analysis"] = ssl_contribution


    # =========================================================================
    # BRAND IMPERSONATION
    # =========================================================================

    brand_imp = domain_intel.get(
        "brand_impersonation",
        {}
    )

    brand_detected = brand_imp.get(
        "detected",
        False
    )

    brand_contribution = 0


    if brand_detected:

        match_type = brand_imp.get(
            "match_type",
            ""
        )

        brand_name = brand_imp.get(
            "brand",
            "Unknown"
        )

        brand_reason = brand_imp.get(
            "reason",
            ""
        )

        has_context = brand_imp.get(
            "has_context",
            False
        )

        context_already_counted = False


        if match_type == "domain_with_context":

            brand_contribution = 25

            context_already_counted = True


        elif match_type == "subdomain":

            brand_contribution = 22


        elif match_type == "typosquatting":

            brand_contribution = 20


        else:

            brand_contribution = 20


        if (
            has_context
            and not context_already_counted
        ):

            brand_contribution += 8


        if signals.get(
            "suspicious_tld",
            False
        ):

            brand_contribution += 5


        brand_contribution = min(
            brand_contribution,
            _BRAND_MAX_CONTRIBUTION
        )


        score += brand_contribution

        breakdown["brand_impersonation"] = (
            brand_contribution
        )


        if brand_reason:

            reasons.append(
                brand_reason
            )

        else:

            reasons.append(
                f"Possible {brand_name} "
                "brand impersonation detected"
            )


    else:

        breakdown["brand_impersonation"] = 0


    # =========================================================================
    # FINAL SCORE
    # =========================================================================

    score = max(
        0.0,
        min(
            100.0,
            score
        )
    )


    # =========================================================================
    # VERDICT
    # =========================================================================

    if score >= THRESHOLD_PHISHING:

        verdict = "Phishing"

    elif score >= THRESHOLD_SUSPICIOUS:

        verdict = "Suspicious"

    else:

        verdict = "Legitimate"


    return {

        "risk_score": round(
            score,
            2
        ),

        "verdict": verdict,

        "signal_breakdown": breakdown,

        "reasons": reasons,
    }


# =============================================================================
# LAYER 6: SIGNAL SUMMARY
# =============================================================================

def build_signal_summary(
    signals: dict,
    domain_intel: dict,
    ssl_analysis: dict = None,
) -> dict:

    brand_imp = domain_intel.get(
        "brand_impersonation",
        {}
    )

    if ssl_analysis is None:
        ssl_analysis = {}


    # SSL summary
    ssl_status = ssl_analysis.get(
        "status"
    )

    if ssl_status == "valid":

        ssl_summary = "valid"

    elif ssl_status == "hostname_mismatch":

        ssl_summary = "hostname_mismatch"

    elif ssl_status in {
        "invalid",
        "verification_failed",
        "certificate_unavailable",
    }:

        ssl_summary = "risk_detected"

    elif ssl_status == "not_applicable":

        ssl_summary = "not_applicable"

    else:

        ssl_summary = "unknown"


    return {

        "ml_model": (
            "high_risk"
            if signals.get(
                "_ml_prob",
                0
            ) >= 0.7

            else (
                "moderate_risk"
                if signals.get(
                    "_ml_prob",
                    0
                ) >= 0.4

                else "low_risk"
            )
        ),

        "domain_reputation": (
            "known_legitimate"
            if domain_intel.get(
                "is_known_legitimate"
            )
            else "unknown"
        ),

        "https": (
            "enabled"
            if signals.get(
                "uses_https"
            )
            else "disabled"
        ),

        "ssl": ssl_summary,

        "suspicious_tld": (
            "detected"
            if signals.get(
                "suspicious_tld"
            )
            else "not_detected"
        ),

        "keyword_risk": (
            "high"
            if signals.get(
                "high_keyword_risk"
            )

            else (
                "medium"
                if signals.get(
                    "phishing_keyword_count",
                    0
                ) >= 1

                else "none"
            )
        ),

        "hostname_risk": (
            "ip_address"
            if signals.get(
                "is_ip_address"
            )

            else (
                "high_entropy"
                if signals.get(
                    "high_hostname_entropy"
                )

                else "normal"
            )
        ),

        "dns_resolved": signals.get(
            "dns_resolved",
            False
        ),

        "excessive_hyphens": signals.get(
            "excessive_hyphens",
            False
        ),

        "excessive_subdomains": signals.get(
            "excessive_subdomains",
            False
        ),

        "is_url_shortener": signals.get(
            "is_url_shortener",
            False
        ),

        "at_symbol": signals.get(
            "has_at_symbol",
            False
        ),

        "encoded_characters": signals.get(
            "has_encoded_characters",
            False
        ),

        "non_standard_port": signals.get(
            "non_standard_port",
            False
        ),

        "brand_impersonation": (
            brand_imp.get(
                "brand",
                "none"
            )
            if brand_imp.get(
                "detected"
            )
            else "none"
        ),
    }