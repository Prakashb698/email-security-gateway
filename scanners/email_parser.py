from email import policy
from email.parser import BytesParser

def parse_email(raw_email: bytes):
    msg = BytesParser(policy=policy.default).parsebytes(raw_email)

    data = {
        "subject": msg.get("subject", ""),
        "from": msg.get("from", ""),
        "to": msg.get("to", ""),
        "reply_to": msg.get("reply-to", ""),
        "return_path": msg.get("return-path", ""),
        "message_id": msg.get("message-id", ""),
        "body": "",
        "attachments": []
    }

    if msg.is_multipart():
        for part in msg.walk():
            filename = part.get_filename()
            content_type = part.get_content_type()

            if filename:
                data["attachments"].append({
                    "filename": filename,
                    "content": part.get_payload(decode=True) or b""
                })
            elif content_type in ["text/plain", "text/html"]:
                try:
                    data["body"] += part.get_content()
                except Exception:
                    pass
    else:
        try:
            data["body"] = msg.get_content()
        except Exception:
            data["body"] = ""

    return data
