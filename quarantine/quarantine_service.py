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


def delete_quarantined_email_file(
    file_path: str,
    domain_name: str,
) -> bool:
    path = Path(file_path)
    expected_root = (QUARANTINE_ROOT / domain_name).resolve()

    try:
        resolved_path = path.resolve()
    except OSError:
        return False

    if resolved_path.parent != expected_root:
        return False

    if not resolved_path.is_file():
        return False

    resolved_path.unlink()
    return True
