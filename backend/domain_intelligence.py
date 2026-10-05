"""
domain_intelligence.py
======================
Layer 2 of the PhishGuard AI multi-layer detection pipeline.

Collects factual, observable domain information that is available
WITHOUT fabricating data.  All values that cannot be determined
are returned as None or "unknown" so the risk engine can treat
them honestly.

External dependencies used:
  - socket     (stdlib)  – DNS resolution
  - difflib    (stdlib)  – fuzzy brand-name matching
  - tldextract           – registrable-domain / subdomain parsing

No paid APIs, no fake threat feeds, no invented ASN data.
"""

import json
import os
import re
import math
import socket
import difflib
from urllib.parse import urlparse

import tldextract


# ─────────────────────────────────────────────────────────────────────────────
# LOAD KNOWN-LEGITIMATE DOMAIN LIST
# ─────────────────────────────────────────────────────────────────────────────

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_ALLOWLIST_PATH = os.path.join(_BASE_DIR, "known_legitimate_domains.json")


def _load_allowlist() -> set:
    """Load the registrable-domain allowlist from the JSON config file."""
    domains = set()
    try:
        with open(_ALLOWLIST_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        domains = set(d.strip().lower() for d in data.get("domains", []) if d.strip())
    except Exception as exc:
        print(f"[domain_intelligence] WARNING: could not load allowlist: {exc}")

    # Also include all legitimate domains declared in BRAND_PROFILES
    for profile in BRAND_PROFILES.values():
        domains.update(profile.get("domains", set()))

    return domains


# ─────────────────────────────────────────────────────────────────────────────
# BRAND PROFILES
# ─────────────────────────────────────────────────────────────────────────────
# Each brand entry maps a canonical brand name to:
#   "domains"   – the set of registrable domains that legitimately own the brand.
#   "keywords"  – short identifiers that may appear inside a spoofed hostname.
#
# Rules:
#   1. A brand keyword match ALONE does not flag impersonation.
#      We additionally require that the registrable domain of the URL is NOT
#      one of the brand's own legitimate domains.
#   2. Keywords are short and distinctive enough to be meaningful.
#   3. This dictionary is generic – no individual phishing URL is hardcoded.

BRAND_PROFILES: dict[str, dict] = {

    "Microsoft": {
        "domains": {
            "microsoft.com", "live.com", "outlook.com", "office.com",
            "microsoftonline.com", "sharepoint.com", "azure.com",
            "bing.com", "windows.com", "msn.com",
        },
        "keywords": ["microsoft", "outlook", "office365", "office", "msn",
                     "xbox", "azure", "onedrive", "sharepoint", "teams"],
    },

    "Google": {
        "domains": {
            "google.com", "googleapis.com", "googleusercontent.com",
            "youtube.com", "gmail.com", "googledrive.com",
            "google.co.in", "google.co.uk",
        },
        "keywords": ["google", "gmail", "youtube", "googledrive"],
    },

    "Apple": {
        "domains": {"apple.com", "icloud.com"},
        "keywords": ["apple", "icloud", "appleid", "itunes", "iphone"],
    },

    "PayPal": {
        "domains": {"paypal.com"},
        "keywords": ["paypal"],
    },

    "Amazon": {
        "domains": {
            "amazon.com", "amazonaws.com", "amazon.co.uk",
            "amazon.in", "amazon.de", "amazon.fr",
        },
        "keywords": ["amazon", "amazonaws", "aws"],
    },

    "Meta": {
        "domains": {
            "meta.com", "facebook.com", "instagram.com",
            "fb.com", "messenger.com",
        },
        "keywords": ["meta", "facebook", "instagram", "messenger"],
    },

    "WhatsApp": {
        "domains": {"whatsapp.com"},
        "keywords": ["whatsapp"],
    },

    "LinkedIn": {
        "domains": {"linkedin.com"},
        "keywords": ["linkedin"],
    },

    "Netflix": {
        "domains": {"netflix.com"},
        "keywords": ["netflix"],
    },

    "Dropbox": {
        "domains": {"dropbox.com"},
        "keywords": ["dropbox"],
    },

    "Adobe": {
        "domains": {"adobe.com"},
        "keywords": ["adobe"],
    },

    "Twitter/X": {
        "domains": {"twitter.com", "x.com", "t.co"},
        "keywords": ["twitter"],
    },

    "Snapchat": {
        "domains": {"snapchat.com"},
        "keywords": ["snapchat"],
    },

    "Zoom": {
        "domains": {"zoom.us"},
        "keywords": ["zoom"],
    },

    "Slack": {
        "domains": {"slack.com"},
        "keywords": ["slack"],
    },

    "GitHub": {
        "domains": {"github.com", "githubusercontent.com", "github.io"},
        "keywords": ["github"],
    },

    "DHL": {
        "domains": {"dhl.com", "dhl.de"},
        "keywords": ["dhl"],
    },

    "FedEx": {
        "domains": {"fedex.com"},
        "keywords": ["fedex"],
    },

    "UPS": {
        "domains": {"ups.com"},
        "keywords": ["ups"],
    },

    "Chase": {
        "domains": {"chase.com"},
        "keywords": ["chase"],
    },

    "Bank of America": {
        "domains": {"bankofamerica.com"},
        "keywords": ["bankofamerica"],
    },

    "Wells Fargo": {
        "domains": {"wellsfargo.com"},
        "keywords": ["wellsfargo"],
    },

    "Stripe": {
        "domains": {"stripe.com"},
        "keywords": ["stripe"],
    },

    "Coinbase": {
        "domains": {"coinbase.com"},
        "keywords": ["coinbase"],
    },

    "Binance": {
        "domains": {"binance.com"},
        "keywords": ["binance"],
    },

    "Steam": {
        "domains": {"steampowered.com", "steamcommunity.com"},
        "keywords": ["steam", "steampowered"],
    },

    "Discord": {
        "domains": {"discord.com", "discordapp.com"},
        "keywords": ["discord"],
    },

    "Roblox": {
        "domains": {"roblox.com"},
        "keywords": ["roblox"],
    },
}

# Loaded once after BRAND_PROFILES is defined
KNOWN_LEGITIMATE_DOMAINS: set = _load_allowlist()


# Phishing-context keywords: if a brand keyword AND one of these appear
# together in the hostname/URL, the impersonation confidence is increased.
PHISHING_CONTEXT_KEYWORDS = [
    "login", "signin", "sign-in", "secure", "verify", "verification",
    "account", "update", "auth", "authentication", "support",
    "helpdesk", "password", "wallet", "billing", "payment", "confirm",
    "activate", "recover", "unlock", "reset",
]


# ─────────────────────────────────────────────────────────────────────────────
# HELPER UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def _extract_parts(url: str) -> tldextract.tldextract.ExtractResult:
    """
    Return the tldextract result for the given URL.
    tldextract reliably separates subdomain / domain / suffix (TLD).
    """
    return tldextract.extract(url)


def _registrable_domain(parts: tldextract.tldextract.ExtractResult) -> str:
    """
    Return the registrable domain, e.g.:
        www.google.com  →  google.com
        mail.google.co.uk  →  google.co.uk
    Returns empty string when the domain cannot be determined.
    """
    if parts.domain and parts.suffix:
        return f"{parts.domain}.{parts.suffix}".lower()
    return ""


def _resolve_dns(hostname: str) -> dict:
    """
    Attempt to resolve a hostname to an IP address.

    Returns:
        {
            "resolved": True/False,
            "ip_address": "x.x.x.x" | None
        }
    """
    if not hostname:
        return {"resolved": False, "ip_address": None}

    try:
        ip = socket.gethostbyname(hostname)
        return {"resolved": True, "ip_address": ip}
    except (socket.gaierror, socket.timeout):
        return {"resolved": False, "ip_address": None}


def _calculate_entropy(value: str) -> float:
    """Shannon entropy of a string – higher = more random-looking."""
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(value)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def _is_ip_address(hostname: str) -> bool:
    """True if the hostname is a raw IPv4 or IPv6 address."""
    import ipaddress
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _normalize_leet(text: str) -> str:
    """
    Replace common leet-speak substitutions so that
    "micros0ft" → "microsoft", "paypa1" → "paypal", "goog1e" → "google".
    Only the most common substitutions used in phishing are mapped.
    """
    LEET_MAP = {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "@": "a",
        "8": "b",
    }
    return "".join(LEET_MAP.get(ch, ch) for ch in text.lower())


def _format_brand_and_domain(brand_key: str, matched_kw: str, profile_domains: set) -> tuple[str, str]:
    """Return (display_brand_name, legitimate_example_domain)."""
    if brand_key == "Microsoft" and matched_kw.lower() in ("outlook", "office365", "office"):
        display_brand = "Microsoft/Outlook"
        legit = "outlook.com" if "outlook.com" in profile_domains else "microsoft.com"
    else:
        display_brand = brand_key
        for pref in (f"{matched_kw.lower()}.com", f"{brand_key.lower()}.com"):
            if pref in profile_domains:
                legit = pref
                break
        else:
            legit = sorted(profile_domains)[0] if profile_domains else ""
    return display_brand, legit


def _extract_tokens_with_source(subdomain: str, domain_label: str) -> list[tuple[str, str]]:
    """
    Extract meaningful tokens tagged with their source ('subdomain' or 'domain').
    Handles hyphens, underscores, dots, and alphanumeric boundaries (e.g. outlook365 -> outlook, 365).
    """
    tokens = []
    seen = set()

    for text, source in [(domain_label, "domain"), (subdomain, "subdomain")]:
        if not text:
            continue
        t_low = text.lower()
        if (t_low, source) not in seen:
            tokens.append((t_low, source))
            seen.add((t_low, source))
        parts = re.split(r'[^a-zA-Z0-9]+', t_low)
        for p in parts:
            if p and (p, source) not in seen:
                tokens.append((p, source))
                seen.add((p, source))
            subparts = re.findall(r'[a-zA-Z]+|\d+', p)
            if len(subparts) > 1:
                for sp in subparts:
                    if sp and (sp, source) not in seen:
                        tokens.append((sp, source))
                        seen.add((sp, source))
    return tokens


# ─────────────────────────────────────────────────────────────────────────────
# BRAND IMPERSONATION DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def detect_brand_impersonation(
    hostname: str,
    registrable_domain: str,
    url: str,
) -> dict:
    """
    Detect generic brand impersonation.

    Strategy (in order of confidence):
    1. Exact brand keyword in non-owned domain or subdomain
    2. Leet-speak typo near-match
    3. Fuzzy similarity match (difflib SequenceMatcher ratio >= 0.82)

    Returns:
        detected          – bool
        brand             – brand name string or None
        confidence        – 0–100 integer
        matched_text      – the matched substring
        reason            – human-readable explanation
        legitimate_domain – example legitimate domain
        match_type        – 'domain_with_context', 'subdomain', 'typosquatting', etc.
        has_context       – True if phishing context keyword present
    """
    hostname_lower = hostname.lower()
    url_lower = url.lower()
    parts = _extract_parts(url)
    subdomain = parts.subdomain.lower() if parts.subdomain else ""
    domain_label = parts.domain.lower() if parts.domain else ""

    tokens_with_source = _extract_tokens_with_source(subdomain, domain_label)

    phishing_context = any(
        kw in url_lower
        for kw in PHISHING_CONTEXT_KEYWORDS
    )

    # 1. Exact brand keyword checks across all brand profiles
    for brand_name, profile in BRAND_PROFILES.items():
        brand_domains: set[str] = profile["domains"]
        brand_keywords: list[str] = profile["keywords"]

        # Legitimate brand ownership - do NOT flag
        if registrable_domain in brand_domains:
            continue

        for keyword in brand_keywords:
            kw_low = keyword.lower()
            if not kw_low or len(kw_low) < 3:
                continue

            for token, source in tokens_with_source:
                # Require meaningful brand match (not just accidental substring of an unrelated word)
                is_exact_match = (
                    token == kw_low or
                    re.fullmatch(rf"{re.escape(kw_low)}\d+|\d+{re.escape(kw_low)}", token) or
                    (len(kw_low) >= 4 and any(
                        token.startswith(kw_low + ctx) or token.endswith(ctx + kw_low)
                        for ctx in ("id", "login", "auth", "secure", "verify", "update")
                    ))
                )

                if is_exact_match:
                    display_brand, legit_domain = _format_brand_and_domain(brand_name, kw_low, brand_domains)
                    if source == "domain":
                        if phishing_context:
                            match_type = "domain_with_context"
                            confidence = 95
                        else:
                            match_type = "domain_exact"
                            confidence = 80
                    else:  # subdomain
                        match_type = "subdomain"
                        confidence = 90 if phishing_context else 80

                    reason = (
                        f"Possible {display_brand} brand impersonation detected: "
                        f"the brand appears in the URL but the registrable domain is not "
                        f"owned by the brand."
                    )
                    return {
                        "detected": True,
                        "brand": display_brand,
                        "confidence": confidence,
                        "matched_text": token,
                        "reason": reason,
                        "legitimate_domain": legit_domain,
                        "match_type": match_type,
                        "has_context": phishing_context,
                    }

    # 2. Typo-squatting / Near-match checks (leet speak & difflib)
    for brand_name, profile in BRAND_PROFILES.items():
        brand_domains: set[str] = profile["domains"]
        brand_keywords: list[str] = profile["keywords"]

        if registrable_domain in brand_domains:
            continue

        for keyword in brand_keywords:
            kw_low = keyword.lower()
            if len(kw_low) < 4:
                continue

            for token, source in tokens_with_source:
                if len(token) < 4:
                    continue

                # Leet-speak check
                normalised = _normalize_leet(token)
                is_leet_match = (
                    normalised != token and (
                        normalised == kw_low or
                        (kw_low in normalised and len(token) <= len(kw_low) + 3)
                    )
                )

                # SequenceMatcher fuzzy check (requires keyword >= 5 and token >= 5)
                is_diff_match = False
                if len(kw_low) >= 5 and len(token) >= 5 and not is_leet_match:
                    ratio = difflib.SequenceMatcher(None, kw_low, token).ratio()
                    if ratio >= 0.82 and token != kw_low:
                        is_diff_match = True

                if is_leet_match or is_diff_match:
                    display_brand, legit_domain = _format_brand_and_domain(brand_name, kw_low, brand_domains)
                    match_type = "typosquatting"
                    confidence = 85 if phishing_context else 75
                    reason = f"Possible {display_brand} brand typo-squatting detected."
                    return {
                        "detected": True,
                        "brand": display_brand,
                        "confidence": confidence,
                        "matched_text": token,
                        "reason": reason,
                        "legitimate_domain": legit_domain,
                        "match_type": match_type,
                        "has_context": phishing_context,
                    }

    # ── No brand impersonation detected ──────────────────────────────────────
    return {
        "detected": False,
        "brand": None,
        "confidence": 0,
        "matched_text": None,
        "reason": None,
        "legitimate_domain": None,
        "match_type": None,
        "has_context": False,
    }


# ─────────────────────────────────────────────────────────────────────────────
# MAIN PUBLIC FUNCTION
# ─────────────────────────────────────────────────────────────────────────────

def get_domain_intelligence(url: str) -> dict:
    """
    Gather all deterministic, observable domain intelligence for a URL.

    Returns a dict with:
        hostname              – raw hostname from URL
        registrable_domain    – google.com / github.com / etc.
        subdomain             – www / accounts / ''
        tld                   – com / xyz / org
        scheme                – https / http
        is_ip_address         – True if hostname is a bare IP
        dns_resolved          – True if hostname resolved in DNS
        ip_address            – resolved IP (or None)
        is_known_legitimate   – True if registrable_domain is in our allowlist
        allowlist_entry       – the matching allowlist entry (or None)
        hostname_entropy      – Shannon entropy of the hostname
        suspicious_flags      – list of observable suspicious characteristics
        brand_impersonation   – brand impersonation analysis result dict
    """
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    scheme = parsed.scheme.lower()

    parts = _extract_parts(url)
    reg_domain = _registrable_domain(parts)
    subdomain = parts.subdomain.lower() if parts.subdomain else ""
    tld = parts.suffix.lower() if parts.suffix else ""

    # ── DNS resolution ──────────────────────────────────────────────────────
    # We only attempt DNS for domain names, not for bare IP addresses.
    is_ip = _is_ip_address(hostname)
    if is_ip:
        dns_info = {"resolved": True, "ip_address": hostname}
    else:
        dns_info = _resolve_dns(hostname)

    # ── Known-legitimate allowlist check ────────────────────────────────────
    # We match the REGISTRABLE DOMAIN, so:
    #   www.google.com → google.com  → match
    #   google.com.evil.xyz → evil.xyz → no match (correct)
    # This prevents "google.com.evil.xyz" from being treated as Google.
    is_known_legitimate = reg_domain in KNOWN_LEGITIMATE_DOMAINS
    allowlist_entry = reg_domain if is_known_legitimate else None

    # ── Entropy ─────────────────────────────────────────────────────────────
    hostname_entropy = _calculate_entropy(hostname)

    # ── Brand impersonation ─────────────────────────────────────────────────
    # Only run impersonation check when the registrable domain is NOT already
    # known-legitimate (avoids wasting cycles on google.com, github.com, etc.)
    if is_known_legitimate:
        brand_impersonation = {
            "detected": False,
            "brand": None,
            "confidence": 0,
            "matched_text": None,
            "reason": None,
            "legitimate_domain": None,
        }
    else:
        brand_impersonation = detect_brand_impersonation(
            hostname=hostname,
            registrable_domain=reg_domain,
            url=url,
        )

    # ── Observable suspicious flags ─────────────────────────────────────────
    # These are pure observations – no verdict is made here.
    suspicious_flags: list[str] = []

    if is_ip:
        suspicious_flags.append("hostname_is_ip_address")

    if not dns_info["resolved"] and not is_ip:
        suspicious_flags.append("dns_not_resolved")

    if scheme == "http":
        suspicious_flags.append("http_no_encryption")

    if hostname_entropy > 4.0:
        suspicious_flags.append("high_hostname_entropy")

    # Excessive hyphens in hostname (raw count, not the registrable domain)
    hyphen_count = hostname.count("-")
    if hyphen_count >= 3:
        suspicious_flags.append("excessive_hyphens_in_hostname")

    # Excessive subdomains
    subdomain_parts = subdomain.split(".") if subdomain else []
    if len(subdomain_parts) >= 3:
        suspicious_flags.append("excessive_subdomains")

    # Digit-heavy hostname
    digit_count = sum(c.isdigit() for c in hostname)
    if hostname and (digit_count / len(hostname)) > 0.4:
        suspicious_flags.append("digit_heavy_hostname")

    # URL port usage
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port and port not in (80, 443, 8080, 8443):
        suspicious_flags.append("unusual_port")

    # @ symbol in URL (classic phishing trick to spoof hostname)
    if "@" in url:
        suspicious_flags.append("at_symbol_in_url")

    # Percent-encoded characters in hostname (very unusual for legit sites)
    if "%" in hostname:
        suspicious_flags.append("encoded_characters_in_hostname")

    if brand_impersonation["detected"]:
        suspicious_flags.append("brand_impersonation_detected")

    return {
        "hostname": hostname,
        "registrable_domain": reg_domain,
        "subdomain": subdomain,
        "tld": tld,
        "scheme": scheme,
        "is_ip_address": is_ip,
        "dns_resolved": dns_info["resolved"],
        "ip_address": dns_info["ip_address"],
        "is_known_legitimate": is_known_legitimate,
        "allowlist_entry": allowlist_entry,
        "hostname_entropy": hostname_entropy,
        "suspicious_flags": suspicious_flags,
        "brand_impersonation": brand_impersonation,
    }
