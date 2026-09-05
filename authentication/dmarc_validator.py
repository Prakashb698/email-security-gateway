import dns.resolver
from typing import Any


def _domains_align(domain_a: str | None, domain_b: str | None) -> bool:
    """
    Basic DMARC domain alignment.

    For this phase we require exact domain alignment.
    """
    if not domain_a or not domain_b:
        return False

    return domain_a.lower().strip(".") == domain_b.lower().strip(".")


def check_dmarc(
    domain: str,
    spf_result: dict[str, Any] | None = None,
    dkim_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Retrieve the DMARC policy and evaluate SPF/DKIM alignment.

    DMARC passes when at least one of these conditions is true:

    1. SPF passes and the SPF-authenticated domain aligns
       with the visible From domain.

    2. DKIM passes and the DKIM signing domain aligns
       with the visible From domain.
    """

    dmarc_domain = f"_dmarc.{domain}"

    try:
        answers = dns.resolver.resolve(dmarc_domain, "TXT")

        record_text = None
        tags = {}

        for record in answers:
            text = "".join(
                part.decode() if isinstance(part, bytes) else part
                for part in record.strings
            )

            if not text.lower().startswith("v=dmarc1"):
                continue

            record_text = text

            for item in text.split(";"):
                item = item.strip()

                if "=" in item:
                    key, value = item.split("=", 1)
                    tags[key.strip().lower()] = value.strip()

            break

        if record_text is None:
            return {
                "domain": domain,
                "exists": False,
                "record": None,
                "policy": None,
                "subdomain_policy": None,
                "percentage": None,
                "reporting_address": None,
                "spf_aligned": False,
                "dkim_aligned": False,
                "status": "FAIL",
                "reason": "No DMARC record found",
            }

        policy = tags.get("p")

        if policy not in {"none", "quarantine", "reject"}:
            return {
                "domain": domain,
                "exists": True,
                "record": record_text,
                "policy": policy,
                "subdomain_policy": tags.get("sp"),
                "percentage": tags.get("pct", "100"),
                "reporting_address": tags.get("rua"),
                "spf_aligned": False,
                "dkim_aligned": False,
                "status": "INVALID",
                "reason": "DMARC record contains an invalid or missing policy",
            }

        spf_domain = None
        spf_pass = False

        if spf_result:
            spf_domain = spf_result.get("domain")
            spf_pass = spf_result.get("status") == "PASS"

        dkim_domain = None
        dkim_pass = False

        if dkim_result:
            dkim_domain = dkim_result.get("domain")
            dkim_pass = dkim_result.get("status") == "PASS"

        spf_aligned = spf_pass and _domains_align(
            domain,
            spf_domain,
        )

        dkim_aligned = dkim_pass and _domains_align(
            domain,
            dkim_domain,
        )

        dmarc_pass = spf_aligned or dkim_aligned

        if dmarc_pass:
            status = "PASS"
            reason = (
                "DMARC passed: authenticated SPF or DKIM domain "
                "aligns with the From domain"
            )
        else:
            status = "FAIL"
            reason = (
                "DMARC failed: neither SPF nor DKIM passed "
                "with aligned domains"
            )

        return {
            "domain": domain,
            "exists": True,
            "record": record_text,
            "policy": policy,
            "subdomain_policy": tags.get("sp"),
            "percentage": tags.get("pct", "100"),
            "reporting_address": tags.get("rua"),
            "spf_aligned": spf_aligned,
            "dkim_aligned": dkim_aligned,
            "status": status,
            "reason": reason,
        }

    except dns.resolver.NXDOMAIN:
        return {
            "domain": domain,
            "exists": False,
            "record": None,
            "policy": None,
            "subdomain_policy": None,
            "percentage": None,
            "reporting_address": None,
            "spf_aligned": False,
            "dkim_aligned": False,
            "status": "FAIL",
            "reason": "DMARC DNS name does not exist",
        }

    except dns.resolver.NoAnswer:
        return {
            "domain": domain,
            "exists": False,
            "record": None,
            "policy": None,
            "subdomain_policy": None,
            "percentage": None,
            "reporting_address": None,
            "spf_aligned": False,
            "dkim_aligned": False,
            "status": "FAIL",
            "reason": "No DMARC TXT record found",
        }

    except dns.resolver.Timeout:
        return {
            "domain": domain,
            "exists": False,
            "record": None,
            "policy": None,
            "subdomain_policy": None,
            "percentage": None,
            "reporting_address": None,
            "spf_aligned": False,
            "dkim_aligned": False,
            "status": "ERROR",
            "reason": "DMARC DNS lookup timed out",
        }

    except Exception as exc:
        return {
            "domain": domain,
            "exists": False,
            "record": None,
            "policy": None,
            "subdomain_policy": None,
            "percentage": None,
            "reporting_address": None,
            "spf_aligned": False,
            "dkim_aligned": False,
            "status": "ERROR",
            "reason": str(exc),
        }
