import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse


def _parse_certificate_date(value):
    """
    Convert Python SSL certificate date format into timezone-aware datetime.
    """
    try:
        dt = datetime.strptime(
            value,
            "%b %d %H:%M:%S %Y %Z"
        )
        return dt.replace(tzinfo=timezone.utc)

    except Exception:
        return None


def _hostname_matches_certificate(cert, hostname):
    """
    Verify whether the certificate covers the requested hostname.

    Checks:
    1. Subject Alternative Name (SAN)
    2. Wildcard certificates
    3. Common Name fallback
    """

    hostname = hostname.lower().rstrip(".")

    # ─────────────────────────────────────────────────────────────
    # 1. Check Subject Alternative Name (SAN)
    # ─────────────────────────────────────────────────────────────

    san_entries = cert.get("subjectAltName", [])

    dns_names = [
        value.lower().rstrip(".")
        for key, value in san_entries
        if key == "DNS"
    ]

    for cert_name in dns_names:

        # Exact match
        if hostname == cert_name:
            return True

        # Wildcard match
        if cert_name.startswith("*."):

            base_domain = cert_name[2:]

            # Example:
            # *.microsoft.com
            # www.microsoft.com -> True
            if hostname.endswith("." + base_domain):

                # Wildcard should normally match
                # only one hostname level.
                remaining = hostname[
                    :-(len(base_domain) + 1)
                ]

                if remaining and "." not in remaining:
                    return True


    # ─────────────────────────────────────────────────────────────
    # 2. Fallback to Common Name
    # ─────────────────────────────────────────────────────────────

    subject = cert.get("subject", [])

    common_names = []

    for part in subject:

        for key, value in part:

            if key == "commonName":
                common_names.append(
                    value.lower().rstrip(".")
                )

    for cert_name in common_names:

        if hostname == cert_name:
            return True

        if cert_name.startswith("*."):

            base_domain = cert_name[2:]

            if hostname.endswith("." + base_domain):

                remaining = hostname[
                    :-(len(base_domain) + 1)
                ]

                if remaining and "." not in remaining:
                    return True


    return False


def analyze_ssl(url, timeout=5):
    """
    Perform real TLS/SSL certificate analysis.

    Returns actual certificate information.
    Never fabricates certificate data.
    """

    parsed = urlparse(url)

    hostname = parsed.hostname


    # ─────────────────────────────────────────────────────────────
    # Invalid URL
    # ─────────────────────────────────────────────────────────────

    if not hostname:

        return {
            "https_enabled": False,
            "certificate_available": False,
            "certificate_valid": False,
            "hostname_match": False,
            "issuer": None,
            "subject": None,
            "valid_from": None,
            "valid_until": None,
            "days_until_expiry": None,
            "status": "invalid_url",
        }


    # ─────────────────────────────────────────────────────────────
    # HTTP URL
    # ─────────────────────────────────────────────────────────────

    if parsed.scheme.lower() != "https":

        return {
            "https_enabled": False,
            "certificate_available": False,
            "certificate_valid": False,
            "hostname_match": False,
            "issuer": None,
            "subject": None,
            "valid_from": None,
            "valid_until": None,
            "days_until_expiry": None,
            "status": "not_applicable",
        }


    port = parsed.port or 443

    # Use Python's trusted CA store
    context = ssl.create_default_context()


    try:

        # ─────────────────────────────────────────────────────────
        # TCP connection
        # ─────────────────────────────────────────────────────────

        with socket.create_connection(
            (hostname, port),
            timeout=timeout
        ) as raw_socket:

            # ─────────────────────────────────────────────────────
            # TLS connection
            # ─────────────────────────────────────────────────────

            with context.wrap_socket(
                raw_socket,
                server_hostname=hostname
            ) as tls_socket:

                cert = tls_socket.getpeercert()


                # ─────────────────────────────────────────────────
                # Certificate unavailable
                # ─────────────────────────────────────────────────

                if not cert:

                    return {
                        "https_enabled": True,
                        "certificate_available": False,
                        "certificate_valid": False,
                        "hostname_match": False,
                        "issuer": None,
                        "subject": None,
                        "valid_from": None,
                        "valid_until": None,
                        "days_until_expiry": None,
                        "status": "certificate_unavailable",
                    }


                # ─────────────────────────────────────────────────
                # Hostname verification
                # ─────────────────────────────────────────────────

                hostname_match = _hostname_matches_certificate(
                    cert,
                    hostname
                )


                # ─────────────────────────────────────────────────
                # Certificate dates
                # ─────────────────────────────────────────────────

                valid_from_raw = cert.get(
                    "notBefore"
                )

                valid_until_raw = cert.get(
                    "notAfter"
                )


                valid_from_dt = (
                    _parse_certificate_date(
                        valid_from_raw
                    )
                    if valid_from_raw
                    else None
                )


                valid_until_dt = (
                    _parse_certificate_date(
                        valid_until_raw
                    )
                    if valid_until_raw
                    else None
                )


                now = datetime.now(
                    timezone.utc
                )


                # ─────────────────────────────────────────────────
                # Certificate validity
                # ─────────────────────────────────────────────────

                certificate_valid = (

                    valid_from_dt is not None

                    and valid_until_dt is not None

                    and valid_from_dt <= now <= valid_until_dt

                    and hostname_match
                )


                # ─────────────────────────────────────────────────
                # Days until expiry
                # ─────────────────────────────────────────────────

                days_until_expiry = None

                if valid_until_dt:

                    days_until_expiry = max(
                        0,
                        (valid_until_dt - now).days
                    )


                # ─────────────────────────────────────────────────
                # Issuer
                # ─────────────────────────────────────────────────

                issuer = None

                issuer_parts = cert.get(
                    "issuer",
                    []
                )

                for part in issuer_parts:

                    for key, value in part:

                        if key == "commonName":

                            issuer = value
                            break

                    if issuer:
                        break


                # ─────────────────────────────────────────────────
                # Subject
                # ─────────────────────────────────────────────────

                subject = None

                subject_parts = cert.get(
                    "subject",
                    []
                )

                for part in subject_parts:

                    for key, value in part:

                        if key == "commonName":

                            subject = value
                            break

                    if subject:
                        break


                # ─────────────────────────────────────────────────
                # Status
                # ─────────────────────────────────────────────────

                if not hostname_match:

                    status = "hostname_mismatch"

                elif not certificate_valid:

                    status = "invalid"

                else:

                    status = "valid"


                # ─────────────────────────────────────────────────
                # Final SSL result
                # ─────────────────────────────────────────────────

                return {

                    "https_enabled": True,

                    "certificate_available": True,

                    "certificate_valid": certificate_valid,

                    "hostname_match": hostname_match,

                    "issuer": issuer,

                    "subject": subject,

                    "valid_from": (
                        valid_from_dt.isoformat()
                        if valid_from_dt
                        else None
                    ),

                    "valid_until": (
                        valid_until_dt.isoformat()
                        if valid_until_dt
                        else None
                    ),

                    "days_until_expiry": (
                        days_until_expiry
                    ),

                    "status": status,
                }


    # ─────────────────────────────────────────────────────────────
    # Certificate verification failure
    # ─────────────────────────────────────────────────────────────

    except ssl.SSLCertVerificationError as error:

        return {

            "https_enabled": True,

            "certificate_available": False,

            "certificate_valid": False,

            "hostname_match": False,

            "issuer": None,

            "subject": None,

            "valid_from": None,

            "valid_until": None,

            "days_until_expiry": None,

            "status": "verification_failed",

            "error": str(error),
        }


    # ─────────────────────────────────────────────────────────────
    # Timeout
    # ─────────────────────────────────────────────────────────────

    except (socket.timeout, TimeoutError):

        return {

            "https_enabled": True,

            "certificate_available": False,

            "certificate_valid": False,

            "hostname_match": False,

            "issuer": None,

            "subject": None,

            "valid_from": None,

            "valid_until": None,

            "days_until_expiry": None,

            "status": "timeout",

            "error": "TLS connection timed out",
        }


    # ─────────────────────────────────────────────────────────────
    # Other errors
    # ─────────────────────────────────────────────────────────────

    except Exception as error:

        return {

            "https_enabled": True,

            "certificate_available": False,

            "certificate_valid": False,

            "hostname_match": False,

            "issuer": None,

            "subject": None,

            "valid_from": None,

            "valid_until": None,

            "days_until_expiry": None,

            "status": "verification_failed",

            "error": str(error),
        }