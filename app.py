from fastapi import Depends
from auth.dependencies import get_current_user
from pydantic import BaseModel
from fastapi import HTTPException
from auth.auth_service import authenticate_user
from database.email_log_repository import save_email_log, get_email_logs_by_domain
from domains.domain_manager import get_tenant_domain, is_supported_domain
from fastapi import FastAPI, File, UploadFile
from scanners.email_parser import parse_email
from scanners.header_analyzer import analyze_headers
from scanners.url_scanner import extract_urls, analyze_urls
from scanners.attachment_scanner import analyze_attachments
from scanners.risk_engine import calculate_verdict

app = FastAPI(title="SwifPass Email Security API")

SUSPICIOUS_WORDS = [
    "urgent", "verify", "password", "account suspended",
    "click here", "login", "invoice", "payment failed",
    "confirm your identity", "reset your password"
]

@app.get("/")
def home():
    return {"message": "SwifPass Email Security API running"}

@app.post("/scan-email/")
async def scan_email(file: UploadFile = File(...)):
    raw_email = await file.read()
    email_data = parse_email(raw_email)
    tenant_domain = get_tenant_domain(email_data)

    score = 0
    findings = []

    text = f"{email_data['subject']} {email_data['body']}".lower()

    for word in SUSPICIOUS_WORDS:
        if word in text:
            score += 10
            findings.append(f"Suspicious keyword found: {word}")

    header_result = analyze_headers(email_data)
    score += header_result["score"]
    findings.extend(header_result["findings"])

    urls = extract_urls(email_data["body"])
    url_result = analyze_urls(urls)
    score += url_result["score"]
    findings.extend(url_result["findings"])

    attachment_result = analyze_attachments(email_data["attachments"])
    score += attachment_result["score"]
    findings.extend(attachment_result["findings"])

    verdict = calculate_verdict(score, infected=attachment_result["infected"])

    save_email_log(
        sender=email_data["from"],
        recipient=email_data["to"],
        subject=email_data["subject"],
        verdict=verdict,
        risk_score=min(score, 100),
        domain_name=tenant_domain
    )

    return {
        "verdict": verdict,
        "risk_score": min(score, 100),
        "subject": email_data["subject"],
        "from": email_data["from"],
        "to": email_data["to"],
        "reply_to": email_data["reply_to"],
        "return_path": email_data["return_path"],
        "message_id": email_data["message_id"],
        "urls": urls,
        "attachments": [a["filename"] for a in email_data["attachments"]],
        "findings": findings,
        "tenant_domain": tenant_domain,
"supported_domain": is_supported_domain(tenant_domain)
    }


@app.get("/domains/{domain_name}/email-logs")
def domain_email_logs(
    domain_name: str,
    current_user: dict = Depends(get_current_user)
):
    if domain_name != current_user["domain_name"]:
        raise HTTPException(
            status_code=403,
            detail="Access denied to this domain"
        )

    return {
        "domain": domain_name,
        "email_logs": get_email_logs_by_domain(domain_name)
    }


class LoginRequest(BaseModel):
    email: str
    password: str


@app.post("/auth/login")
def login(request: LoginRequest):
    token = authenticate_user(
        email=request.email,
        password=request.password
    )

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    return token


@app.get("/me/email-logs")
def my_email_logs(current_user: dict = Depends(get_current_user)):
    domain_name = current_user["domain_name"]

    return {
        "user": current_user["email"],
        "domain": domain_name,
        "email_logs": get_email_logs_by_domain(domain_name)
    }
