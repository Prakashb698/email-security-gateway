import spf
from typing import Any


def check_spf(
    ip_address: str,
    mail_from: str,
    helo_domain: str,
) -> dict[str, Any]:
    """
    Perform real SPF validation.

    SPF evaluates whether the connecting sender IP is authorized
    to send mail for the SMTP envelope MAIL FROM identity.
    """

    domain = None

    if mail_from and "@" in mail_from:
        domain = mail_from.rsplit("@", 1)[1].lower()

    if not ip_address:
        return {
            "domain": domain,
            "ip_address": None,
            "mail_from": mail_from,
            "helo": helo_domain,
            "status": "INVALID",
            "reason": "Unable to determine sender IP address",
        }

    if not mail_from:
        return {
            "domain": domain,
            "ip_address": ip_address,
            "mail_from": None,
            "helo": helo_domain,
            "status": "INVALID",
            "reason": "Unable to determine MAIL FROM address",
        }

    try:
        result, explanation = spf.check2(
            i=ip_address,
            s=mail_from,
            h=helo_domain or domain or "unknown",
        )

        status = result.upper()

        return {
            "domain": domain,
            "ip_address": ip_address,
            "mail_from": mail_from,
            "helo": helo_domain,
            "status": status,
            "reason": explanation,
        }

    except Exception as exc:
        return {
            "domain": domain,
            "ip_address": ip_address,
            "mail_from": mail_from,
            "helo": helo_domain,
            "status": "ERROR",
            "reason": str(exc),
        }
