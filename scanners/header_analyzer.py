def analyze_headers(email_data):
    findings = []
    score = 0

    sender = email_data.get("from", "")
    reply_to = email_data.get("reply_to", "")
    return_path = email_data.get("return_path", "")
    message_id = email_data.get("message_id", "")

    if reply_to and reply_to != sender:
        findings.append("Reply-To address differs from From address")
        score += 15

    if return_path and sender and return_path not in sender:
        findings.append("Return-Path differs from sender")
        score += 10

    if not message_id:
        findings.append("Missing Message-ID header")
        score += 10

    return {
        "score": score,
        "findings": findings
    }
