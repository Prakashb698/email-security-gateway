from scanners.clamav import scan_bytes

DANGEROUS_EXTENSIONS = [
    ".exe", ".bat", ".cmd", ".scr", ".js", ".vbs",
    ".ps1", ".jar", ".msi", ".dll"
]

def analyze_attachments(attachments):
    findings = []
    score = 0
    infected = False

    for attachment in attachments:
        filename = attachment["filename"].lower()
        content = attachment["content"]

        if any(filename.endswith(ext) for ext in DANGEROUS_EXTENSIONS):
            findings.append(f"Dangerous attachment type: {filename}")
            score += 25

        if filename.count(".") >= 2:
            findings.append(f"Double extension attachment: {filename}")
            score += 15

        clam_result = scan_bytes(content)

        if clam_result["infected"]:
            infected = True
            findings.append(f"ClamAV detected malware in: {filename}")
            score += 60

    return {
        "score": score,
        "findings": findings,
        "infected": infected
    }
