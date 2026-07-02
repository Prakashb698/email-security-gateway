from email.utils import parseaddr

SUPPORTED_DOMAINS = [
    "swifpass.local"
]

def extract_domain(email_address: str):
    if not email_address:
        return ""

    _, addr = parseaddr(email_address)

    if "@" not in addr:
        return ""

    return addr.split("@")[-1].lower().strip()

def get_tenant_domain(email_data):
    recipient = email_data.get("to", "")
    domain = extract_domain(recipient)

    if domain in SUPPORTED_DOMAINS:
        return domain

    return "unknown"

def is_supported_domain(domain: str):
    return domain in SUPPORTED_DOMAINS
