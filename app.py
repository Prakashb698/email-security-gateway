import re
from email.utils import parseaddr

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel

from auth.auth_service import authenticate_user
from auth.dependencies import get_current_user
from authentication.dkim_validator import check_dkim
from authentication.dmarc_validator import check_dmarc
from authentication.spf_validator import check_spf
from database.email_log_repository import (
    get_email_logs_by_domain,
    save_email_log,
)
from domains.domain_manager import get_tenant_domain, is_supported_domain
from quarantine.quarantine_repository import (
    delete_quarantine_record,
    get_quarantine_record_by_id,
    get_quarantine_records_by_domain,
    save_quarantine_record,
)
from quarantine.quarantine_service import (
    delete_quarantined_email_file,
    store_quarantined_email,
)
from scanners.attachment_scanner import analyze_attachments
from scanners.email_parser import parse_email
from scanners.header_analyzer import analyze_headers
from scanners.risk_engine import calculate_verdict
from scanners.url_scanner import analyze_urls, extract_urls


app = FastAPI(title="SwifPass Email Security API")


SUSPICIOUS_WORDS = [
    "urgent",
    "verify",
    "password",
    "account suspended",
    "click here",
    "login",
    "invoice",
    "payment failed",
    "confirm your identity",
    "reset your password",
]


@app.get("/")
def home():
    return {"message": "SwifPass Email Security API running"}


@app.post("/scan-email/")
async def scan_email(file: UploadFile = File(...)):
    raw_email = await file.read()

    email_data = parse_email(raw_email)
    tenant_domain = get_tenant_domain(email_data)

    # Extract the visible From domain.
    sender_address = parseaddr(email_data["from"])[1]

    sender_domain = (
        sender_address.rsplit("@", 1)[1].lower()
        if "@" in sender_address
        else ""
    )

    # Extract SMTP envelope sender from Return-Path.
    mail_from = parseaddr(email_data["return_path"])[1]

    # Extract sender IP and HELO hostname from Received headers.
    sender_ip = ""
    helo_domain = ""

    received_headers = email_data["message"].get_all("Received", [])

    for received in reversed(received_headers):
        match = re.search(
            r"from\s+([^\s(]+).*?\[([0-9a-fA-F:.]+)\]",
            received,
            re.IGNORECASE | re.DOTALL,
        )

        if match:
            helo_domain = match.group(1).strip()
            sender_ip = match.group(2).strip()
            break

    # Perform real SPF validation.
    if mail_from and sender_ip:
        spf_result = check_spf(
            sender_ip,
            mail_from,
            helo_domain,
        )
    else:
        spf_result = {
            "domain": (
                mail_from.rsplit("@", 1)[1].lower()
                if "@" in mail_from
                else None
            ),
            "ip_address": sender_ip or None,
            "mail_from": mail_from or None,
            "helo": helo_domain or None,
            "status": "INVALID",
            "reason": "Unable to determine SPF sender information",
        }

    # Retrieve DMARC policy for the visible From domain.
    if sender_domain:
        dmarc_result = check_dmarc(sender_domain)
    else:
        dmarc_result = {
            "domain": None,
            "exists": False,
            "record": None,
            "policy": None,
            "status": "INVALID",
            "reason": "Unable to determine sender domain",
        }

        # Inspect the parsed email message for a DKIM-Signature header.
    dkim_result = check_dkim(
        email_data["message"],
        email_data["raw_email"],
    )

    # Evaluate DMARC using the visible From domain plus SPF/DKIM results.
    if sender_domain:
        dmarc_result = check_dmarc(
            sender_domain,
            spf_result,
            dkim_result,
        )
    else:
        dmarc_result = {
            "domain": None,
            "exists": False,
            "record": None,
            "policy": None,
            "subdomain_policy": None,
            "percentage": None,
            "reporting_address": None,
            "spf_aligned": False,
            "dkim_aligned": False,
            "status": "INVALID",
            "reason": "Unable to determine sender domain",
        }

    authentication_results = {
        "spf": spf_result,
        "dkim": dkim_result,
        "dmarc": dmarc_result,
    }

    score = 0
    findings = []

    # Apply authentication risk scoring.
    if spf_result["status"] != "PASS":
        score += 15
        findings.append(
            "SPF check failed: "
            f"{spf_result.get('reason', 'No valid SPF record found')}"
        )

    if dkim_result["status"] != "PASS":
        score += 20
        findings.append(
            "DKIM check failed: "
            f"{dkim_result.get('reason', 'DKIM validation failed')}"
        )

    if dmarc_result["status"] != "PASS":
        score += 25
        findings.append(
            "DMARC check failed: "
            f"{dmarc_result.get('reason', 'No valid DMARC record found')}"
        )
    elif dmarc_result.get("policy") == "none":
        score += 10
        findings.append("DMARC monitoring policy detected: p=none")

    # Scan subject and body for suspicious keywords.
    text = f"{email_data['subject']} {email_data['body']}".lower()

    for word in SUSPICIOUS_WORDS:
        if word in text:
            score += 10
            findings.append(f"Suspicious keyword found: {word}")

    # Analyze email headers.
    header_result = analyze_headers(email_data)
    score += header_result["score"]
    findings.extend(header_result["findings"])

    # Analyze URLs found in the email body.
    urls = extract_urls(email_data["body"])
    url_result = analyze_urls(urls)
    score += url_result["score"]
    findings.extend(url_result["findings"])

    # Analyze email attachments.
    attachment_result = analyze_attachments(email_data["attachments"])
    score += attachment_result["score"]
    findings.extend(attachment_result["findings"])

    final_score = min(score, 100)

    verdict = calculate_verdict(
        final_score,
        infected=attachment_result["infected"],
    )

    # Save tenant-scoped email scan metadata.
    save_email_log(
        sender=email_data["from"],
        recipient=email_data["to"],
        subject=email_data["subject"],
        verdict=verdict,
        risk_score=final_score,
        domain_name=tenant_domain,
    )

    quarantine_id = None
    quarantine_file_path = None

    # Automatically quarantine high-risk or infected email.
    if verdict in ("high_risk", "infected", "malicious") or final_score >= 70:
        quarantine_file_path = store_quarantined_email(
            raw_email=raw_email,
            domain_name=tenant_domain,
        )

        quarantine_id = save_quarantine_record(
            sender=email_data["from"],
            recipient=email_data["to"],
            subject=email_data["subject"],
            verdict=verdict,
            risk_score=final_score,
            reason="High-risk or infected email",
            file_path=quarantine_file_path,
            domain_name=tenant_domain,
        )

    return {
        "verdict": verdict,
        "risk_score": final_score,
        "subject": email_data["subject"],
        "from": email_data["from"],
        "to": email_data["to"],
        "reply_to": email_data["reply_to"],
        "return_path": email_data["return_path"],
        "message_id": email_data["message_id"],
        "urls": urls,
        "attachments": [
            attachment["filename"]
            for attachment in email_data["attachments"]
        ],
        "findings": findings,
        "tenant_domain": tenant_domain,
        "supported_domain": is_supported_domain(tenant_domain),
        "authentication": authentication_results,
        "quarantined": quarantine_id is not None,
        "quarantine_id": quarantine_id,
        "quarantine_file_path": quarantine_file_path,
    }


@app.get("/domains/{domain_name}/email-logs")
def domain_email_logs(
    domain_name: str,
    current_user: dict = Depends(get_current_user),
):
    if domain_name != current_user["domain_name"]:
        raise HTTPException(
            status_code=403,
            detail="Access denied to this domain",
        )

    return {
        "domain": domain_name,
        "email_logs": get_email_logs_by_domain(domain_name),
    }


class LoginRequest(BaseModel):
    email: str
    password: str


@app.post("/auth/login")
def login(request: LoginRequest):
    token = authenticate_user(
        email=request.email,
        password=request.password,
    )

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
        )

    return token


@app.get("/me/email-logs")
def my_email_logs(
    current_user: dict = Depends(get_current_user),
):
    domain_name = current_user["domain_name"]

    return {
        "user": current_user["email"],
        "domain": domain_name,
        "email_logs": get_email_logs_by_domain(domain_name),
    }


@app.get("/me/quarantine")
def my_quarantine_records(
    current_user: dict = Depends(get_current_user),
):
    domain_name = current_user["domain_name"]

    return {
        "user": current_user["email"],
        "domain": domain_name,
        "quarantine_records": get_quarantine_records_by_domain(
            domain_name
        ),
    }


@app.get("/me/quarantine/{record_id}")
def my_quarantine_record(
    record_id: int,
    current_user: dict = Depends(get_current_user),
):
    domain_name = current_user["domain_name"]

    record = get_quarantine_record_by_id(
        record_id=record_id,
        domain_name=domain_name,
    )

    if not record:
        raise HTTPException(
            status_code=404,
            detail="Quarantine record not found",
        )

    return {
        "user": current_user["email"],
        "domain": domain_name,
        "quarantine_record": record,
    }


@app.delete("/me/quarantine/{record_id}")
def delete_my_quarantine_record(
    record_id: int,
    current_user: dict = Depends(get_current_user),
):
    domain_name = current_user["domain_name"]

    record = get_quarantine_record_by_id(
        record_id=record_id,
        domain_name=domain_name,
    )

    if not record:
        raise HTTPException(
            status_code=404,
            detail="Quarantine record not found",
        )

    file_deleted = delete_quarantined_email_file(
        file_path=record["file_path"],
        domain_name=domain_name,
    )

    db_deleted = delete_quarantine_record(
        record_id=record_id,
        domain_name=domain_name,
    )

    return {
        "deleted": db_deleted,
        "file_deleted": file_deleted,
        "record_id": record_id,
        "domain": domain_name,
    }
