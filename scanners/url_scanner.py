import re

def extract_urls(text: str):
    return re.findall(r"https?://[^\s\"'<>]+", text or "")

def analyze_urls(urls):
    findings = []
    score = 0

    for url in urls:
        if re.search(r"https?://\d+\.\d+\.\d+\.\d+", url):
            findings.append(f"IP-based URL found: {url}")
            score += 20

        if any(short in url for short in ["bit.ly", "tinyurl", "t.co", "goo.gl"]):
            findings.append(f"Shortened URL found: {url}")
            score += 15

        if url.startswith("http://"):
            findings.append(f"Non-HTTPS URL found: {url}")
            score += 10

    return {
        "urls": urls,
        "score": score,
        "findings": findings
    }
