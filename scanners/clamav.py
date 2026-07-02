import subprocess
import tempfile
import os

def scan_bytes(content: bytes):
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(content)
        path = tmp.name

    process = subprocess.run(
        ["clamscan", path],
        capture_output=True,
        text=True
    )

    os.remove(path)

    output = process.stdout + process.stderr

    return {
        "infected": "FOUND" in output,
        "details": output
    }
