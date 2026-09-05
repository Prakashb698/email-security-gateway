import re
import dkim
from email.message import Message
from typing import Any


def check_dkim(message: Message, raw_email: bytes) -> dict[str, Any]:
    """
    Verify an email's DKIM signature cryptographically.

    The parsed message is used to extract DKIM metadata.
    The original raw email bytes are used for cryptographic verification.
    """

    signature = message.get("DKIM-Signature")

    if not signature:
        return {
            "exists": False,
            "status": "FAIL",
            "domain": None,
            "selector": None,
            "algorithm": None,
            "verified": False,
            "reason": "DKIM-Signature header is missing",
        }

    domain_match = re.search(
        r"(?:^|;)\s*d=([^;\s]+)",
        signature,
        re.IGNORECASE,
    )

    selector_match = re.search(
        r"(?:^|;)\s*s=([^;\s]+)",
        signature,
        re.IGNORECASE,
    )

    algorithm_match = re.search(
        r"(?:^|;)\s*a=([^;\s]+)",
        signature,
        re.IGNORECASE,
    )

    domain = (
        domain_match.group(1).strip()
        if domain_match
        else None
    )

    selector = (
        selector_match.group(1).strip()
        if selector_match
        else None
    )

    algorithm = (
        algorithm_match.group(1).strip()
        if algorithm_match
        else None
    )

    if not domain or not selector:
        return {
            "exists": True,
            "status": "INVALID",
            "domain": domain,
            "selector": selector,
            "algorithm": algorithm,
            "verified": False,
            "reason": "DKIM signature is missing the domain or selector",
        }

    try:
        verified = dkim.verify(raw_email)

        if verified:
            return {
                "exists": True,
                "status": "PASS",
                "domain": domain,
                "selector": selector,
                "algorithm": algorithm,
                "verified": True,
                "reason": "DKIM cryptographic signature verified successfully",
            }

        return {
            "exists": True,
            "status": "FAIL",
            "domain": domain,
            "selector": selector,
            "algorithm": algorithm,
            "verified": False,
            "reason": "DKIM cryptographic signature verification failed",
        }

    except Exception as exc:
        return {
            "exists": True,
            "status": "ERROR",
            "domain": domain,
            "selector": selector,
            "algorithm": algorithm,
            "verified": False,
            "reason": str(exc),
        }
