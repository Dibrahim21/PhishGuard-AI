from urllib.parse import urlparse
import ipaddress
import math
import re


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "security",
    "signin",
    "sign-in",
    "banking",
    "password",
    "credential",
    "wallet",
    "confirm",
    "payment",
    "billing",
    "auth",
    "token",
    "session",
    "unlock",
    "recover",
    "suspend",
    "validate",
    "activate",
]


SUSPICIOUS_TLDS = {
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "top",
    "xyz",
    "click",
    "work",
    "support",
    "zip",
    "mov",
    "cam",
}


SHORTENING_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
}


COMMON_LEGITIMATE_TLDS = {
    "com",
    "org",
    "net",
    "edu",
    "gov",
    "io",
    "co",
    "in",
    "uk",
    "de",
    "fr",
    "jp",
}


def calculate_entropy(value: str) -> float:
    if not value:
        return 0.0

    frequency = {}

    for char in value:
        frequency[char] = frequency.get(char, 0) + 1

    entropy = 0.0
    length = len(value)

    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def count_special_characters(value: str) -> int:
    return len(re.findall(r"[^a-zA-Z0-9]", value))


def extract_url_features(url: str) -> dict:

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    hostname = hostname.lower()

    path = parsed.path or ""
    query = parsed.query or ""

    full_url = url.lower()

    # =========================================
    # BASIC LENGTH FEATURES
    # =========================================

    url_length = len(url)

    hostname_length = len(hostname)

    path_length = len(path)

    query_length = len(query)

    # =========================================
    # HOSTNAME FEATURES
    # =========================================

    dots = hostname.count(".")

    hyphens = hostname.count("-")

    digits = sum(
        char.isdigit()
        for char in hostname
    )

    hostname_letters = sum(
        char.isalpha()
        for char in hostname
    )

    hostname_special = count_special_characters(
        hostname
    )

    hostname_parts = (
        hostname.split(".")
        if hostname
        else []
    )

    subdomain_count = max(
        len(hostname_parts) - 2,
        0
    )

    # =========================================
    # URL CHARACTER FEATURES
    # =========================================

    total_digits = sum(
        char.isdigit()
        for char in url
    )

    total_letters = sum(
        char.isalpha()
        for char in url
    )

    special_url_characters = len(
        re.findall(
            r"[^a-zA-Z0-9:/?.=&_%\-]",
            url
        )
    )

    slash_count = url.count("/")

    question_count = url.count("?")

    equal_count = url.count("=")

    ampersand_count = url.count("&")

    percent_count = url.count("%")

    underscore_count = url.count("_")

    # =========================================
    # PROTOCOL FEATURES
    # =========================================

    has_https = parsed.scheme == "https"

    has_http = parsed.scheme == "http"

    # =========================================
    # SUSPICIOUS URL FEATURES
    # =========================================

    has_ip = is_ip_address(hostname)

    has_at_symbol = "@" in url

    has_double_slash = "//" in path

    try:
        has_port = parsed.port is not None
    except ValueError:
        has_port = False

    # =========================================
    # URL SHORTENER
    # =========================================

    is_shortened = any(
        hostname == domain
        or hostname.endswith("." + domain)
        for domain in SHORTENING_DOMAINS
    )

    # =========================================
    # SUSPICIOUS KEYWORDS
    # =========================================

    found_keywords = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in full_url
    ]

    keyword_count = len(found_keywords)

    # =========================================
    # TLD FEATURES
    # =========================================

    tld = ""

    if hostname_parts:
        tld = hostname_parts[-1]

    suspicious_tld = int(
        tld in SUSPICIOUS_TLDS
    )

    common_tld = int(
        tld in COMMON_LEGITIMATE_TLDS
    )

    # =========================================
    # DOMAIN STRUCTURE FEATURES
    # =========================================

    short_hostname = int(
        0 < hostname_length <= 12
    )

    long_hostname = int(
        hostname_length >= 30
    )

    many_subdomains = int(
        subdomain_count >= 3
    )

    many_hyphens = int(
        hyphens >= 3
    )

    # =========================================
    # RATIO FEATURES
    # =========================================

    digit_ratio = (
        total_digits / url_length
        if url_length
        else 0
    )

    hostname_digit_ratio = (
        digits / hostname_length
        if hostname_length
        else 0
    )

    hyphen_ratio = (
        hyphens / hostname_length
        if hostname_length
        else 0
    )

    special_character_ratio = (
        special_url_characters / url_length
        if url_length
        else 0
    )

    # =========================================
    # ENTROPY FEATURES
    # =========================================

    hostname_entropy = calculate_entropy(
        hostname
    )

    url_entropy = calculate_entropy(
        url
    )

    path_entropy = calculate_entropy(
        path
    )

    # =========================================
    # QUERY FEATURES
    # =========================================

    query_parameter_count = (
        len(query.split("&"))
        if query
        else 0
    )

    # =========================================
    # RETURN FEATURES
    # =========================================

    return {

        "url_length": url_length,

        "hostname_length": hostname_length,

        "path_length": path_length,

        "query_length": query_length,

        "dot_count": dots,

        "hyphen_count": hyphens,

        "digit_count": digits,

        "total_digit_count": total_digits,

        "total_letter_count": total_letters,

        "special_character_count":
            hostname_special,

        "special_url_character_count":
            special_url_characters,

        "subdomain_count":
            subdomain_count,

        "has_https":
            int(has_https),

        "has_http":
            int(has_http),

        "has_ip":
            int(has_ip),

        "has_at_symbol":
            int(has_at_symbol),

        "has_double_slash":
            int(has_double_slash),

        "has_port":
            int(has_port),

        "is_shortened":
            int(is_shortened),

        "keyword_count":
            keyword_count,

        "query_parameter_count":
            query_parameter_count,

        "slash_count":
            slash_count,

        "question_count":
            question_count,

        "equal_count":
            equal_count,

        "ampersand_count":
            ampersand_count,

        "percent_count":
            percent_count,

        "underscore_count":
            underscore_count,

        "suspicious_tld":
            suspicious_tld,

        "common_tld":
            common_tld,

        "short_hostname":
            short_hostname,

        "long_hostname":
            long_hostname,

        "many_subdomains":
            many_subdomains,

        "many_hyphens":
            many_hyphens,

        "digit_ratio":
            round(digit_ratio, 6),

        "hostname_digit_ratio":
            round(hostname_digit_ratio, 6),

        "hyphen_ratio":
            round(hyphen_ratio, 6),

        "special_character_ratio":
            round(
                special_character_ratio,
                6
            ),

        "hostname_entropy":
            hostname_entropy,

        "url_entropy":
            url_entropy,

        "path_entropy":
            path_entropy,

        "found_keywords":
            found_keywords,
    }