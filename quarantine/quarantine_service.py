from pathlib import Path
from uuid import uuid4


QUARANTINE_ROOT = Path("quarantine")


def store_quarantined_email(
    raw_email: bytes,
    domain_name: str,
) -> str:
    domain_dir = QUARANTINE_ROOT / domain_name
    domain_dir.mkdir(parents=True, exist_ok=True)

    file_name = f"{uuid4().hex}.eml"
    file_path = domain_dir / file_name

    file_path.write_bytes(raw_email)

    return str(file_path)
