"""
rdap_intelligence.py
====================

Real RDAP-based domain registration intelligence.

Provides:
- Domain registration status
- Registrar
- Registration date
- Expiry date
- Domain age
- Days until expiry
- Nameservers
- RDAP source
"""

from datetime import datetime, timezone
import requests


RDAP_BOOTSTRAP_URL = (
    "https://data.iana.org/rdap/dns.json"
)

REQUEST_TIMEOUT = 8


def _parse_datetime(value):
    """
    Convert RDAP timestamp into ISO-8601 UTC.
    """
    if not value:
        return None

    try:
        value = value.replace("Z", "+00:00")

        dt = datetime.fromisoformat(value)

        if dt.tzinfo is None:
            dt = dt.replace(
                tzinfo=timezone.utc
            )

        return dt.astimezone(
            timezone.utc
        ).isoformat()

    except Exception:
        return None


def _calculate_domain_age(registration_date):
    """
    Calculate domain age in days.
    """
    if not registration_date:
        return None

    try:
        registered = datetime.fromisoformat(
            registration_date
        )

        now = datetime.now(
            timezone.utc
        )

        return max(
            0,
            (now - registered).days
        )

    except Exception:
        return None


def _calculate_days_until_expiry(expiry_date):
    """
    Calculate remaining days until domain expiry.
    """
    if not expiry_date:
        return None

    try:
        expiry = datetime.fromisoformat(
            expiry_date
        )

        now = datetime.now(
            timezone.utc
        )

        return (
            expiry - now
        ).days

    except Exception:
        return None


def _find_event(events, event_type):
    """
    Find a specific RDAP event.
    """

    for event in events or []:

        if (
            event.get("eventAction")
            == event_type
        ):
            return _parse_datetime(
                event.get("eventDate")
            )

    return None


def _find_registrar(data):
    """
    Extract registrar name from RDAP entities.
    """

    for entity in data.get(
        "entities",
        []
    ):

        roles = entity.get(
            "roles",
            []
        )

        if "registrar" not in roles:
            continue

        vcard = entity.get(
            "vcardArray"
        )

        if not vcard:
            continue

        try:
            properties = vcard[1]

            for prop in properties:

                if (
                    prop[0]
                    == "fn"
                ):
                    return prop[3]

        except Exception:
            pass

    return None


def _find_nameservers(data):
    """
    Extract nameservers.
    """

    nameservers = []

    for nameserver in data.get(
        "nameservers",
        []
    ):

        name = nameserver.get(
            "ldhName"
        )

        if name:
            nameservers.append(
                name.lower()
            )

    return nameservers


def lookup_rdap(domain):
    """
    Perform RDAP lookup using
    the IANA bootstrap registry.
    """

    result = {
        "available": False,
        "status": "unknown",
        "domain": domain,
        "registrar": None,
        "registration_date": None,
        "expiration_date": None,
        "domain_age_days": None,
        "days_until_expiry": None,
        "nameservers": [],
        "rdap_source": None,
        "error": None,
    }

    if not domain:
        result["error"] = (
            "Domain is empty"
        )
        return result

    domain = (
        domain
        .strip()
        .lower()
        .rstrip(".")
    )

    try:

        # --------------------------------------------------
        # STEP 1: Get IANA RDAP bootstrap data
        # --------------------------------------------------

        bootstrap_response = requests.get(
            RDAP_BOOTSTRAP_URL,
            timeout=REQUEST_TIMEOUT,
        )

        bootstrap_response.raise_for_status()

        bootstrap_data = (
            bootstrap_response.json()
        )

        rdap_servers = []

        for service in bootstrap_data.get(
            "services",
            []
        ):

            if len(service) != 2:
                continue

            domains = service[0]
            urls = service[1]

            for registered_domain in domains:

                if domain.endswith(
                    registered_domain
                ):

                    rdap_servers.extend(
                        urls
                    )

        if not rdap_servers:

            result["error"] = (
                "No RDAP server found"
            )

            return result

        # --------------------------------------------------
        # STEP 2: Query RDAP server
        # --------------------------------------------------

        base_url = rdap_servers[0]

        if not base_url.endswith("/"):
            base_url += "/"

        rdap_url = (
            base_url
            + "domain/"
            + domain
        )

        response = requests.get(
            rdap_url,
            timeout=REQUEST_TIMEOUT,
            headers={
                "Accept":
                    "application/rdap+json"
            },
        )

        result[
            "rdap_source"
        ] = rdap_url

        # Domain does not exist
        if response.status_code == 404:

            result[
                "available"
            ] = True

            result[
                "status"
            ] = "not_registered"

            return result

        response.raise_for_status()

        data = response.json()

        # --------------------------------------------------
        # STEP 3: Extract information
        # --------------------------------------------------

        events = data.get(
            "events",
            []
        )

        registration_date = (
            _find_event(
                events,
                "registration"
            )
        )

        expiration_date = (
            _find_event(
                events,
                "expiration"
            )
        )

        registrar = _find_registrar(
            data
        )

        nameservers = (
            _find_nameservers(
                data
            )
        )

        # --------------------------------------------------
        # STEP 4: Build result
        # --------------------------------------------------

        result[
            "available"
        ] = True

        result[
            "status"
        ] = "registered"

        result[
            "registrar"
        ] = registrar

        result[
            "registration_date"
        ] = registration_date

        result[
            "expiration_date"
        ] = expiration_date

        result[
            "domain_age_days"
        ] = _calculate_domain_age(
            registration_date
        )

        result[
            "days_until_expiry"
        ] = _calculate_days_until_expiry(
            expiration_date
        )

        result[
            "nameservers"
        ] = nameservers

        return result

    except requests.Timeout:

        result["error"] = (
            "RDAP request timed out"
        )

        return result

    except requests.RequestException as error:

        result["error"] = (
            f"RDAP request failed: {error}"
        )

        return result

    except Exception as error:

        result["error"] = (
            f"RDAP analysis failed: {error}"
        )

        return result