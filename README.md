# Email Security Gateway

### Research-Inspired Multi-Signal Phishing Detection and Email Authentication Platform

## Project Overview

This project is a research-inspired Email Security Gateway developed after studying research related to phishing-email detection, multi-modal security analysis, explainable machine learning, and email authentication.

A major idea from the research I studied was that phishing detection should not depend on only one feature such as email text.

Modern phishing attacks can contain:

- Legitimate-looking message content
- Malicious or misleading URLs
- Suspicious sender information
- Abnormal email headers
- Dangerous attachments
- Spoofed sender domains
- Failed SPF authentication
- Invalid DKIM signatures
- DMARC alignment failures

Based on these ideas, I designed and implemented a practical **multi-signal email security architecture**.

The system analyzes several independent email characteristics and combines them into an explainable security risk score and final verdict.

---

# Research Motivation

Before building the application, I studied phishing-detection research that explored concepts such as:

- Multi-modal phishing detection
- Deep-learning-based email analysis
- Email content classification
- URL and metadata analysis
- Feature fusion
- Explainable AI
- Email sender authentication
- Federated and privacy-preserving security models

The research showed that relying on only one feature can miss sophisticated phishing attacks.

For example, an email may contain normal-looking text but still contain:

- A spoofed sender
- An unauthorized sending server
- A malicious URL
- A broken cryptographic signature

This motivated me to design the project as a combination of several security-analysis modules.

---

# From Research to Engineering

A simplified research-style phishing architecture can be represented as:

```text
                     EMAIL
                       |
             ---------------------
             |                   |
          Content             Metadata
             |                   |
       Text Features        Header Features
             |                   |
             ----------- ---------
                       |
                 Feature Fusion
                       |
                 Classification
                       |
              Legitimate / Phishing
```

I translated this research concept into a practical email-security platform:

```text
                         RAW EMAIL (.eml)
                                |
                                v
                         EMAIL PARSER
                                |
          ---------------------------------------------
          |                |              |           |
          v                v              v           v
    CONTENT ANALYSIS   HEADER ANALYSIS  URL ANALYSIS  ATTACHMENTS
          |                |              |           |
          -----------------+--------------+------------
                           |
                           v
                 EMAIL AUTHENTICATION
                           |
                -------------------------
                |           |           |
                v           v           v
               SPF         DKIM        DMARC
                |           |           |
                ----------- + -----------
                           |
                           v
                       RISK ENGINE
                           |
                           v
                EXPLAINABLE FINDINGS
                           |
                           v
                    SECURITY VERDICT
                           |
                 ---------------------
                 |                   |
                 v                   v
             EMAIL LOG           QUARANTINE
                 |                   |
                 ----------- ---------
                           |
                           v
                  SECURITY DASHBOARD
```

---

# Important Clarification

The research papers I studied include advanced machine-learning and deep-learning approaches.

The current version of this project does **not claim to be a trained multi-modal deep-learning model**.

Instead, it implements the complete security-engineering pipeline required around such a model:

- Email parsing
- Multiple security-signal extraction
- Risk aggregation
- Email authentication
- Explainable findings
- Tenant isolation
- Quarantine
- Security monitoring
- Dashboard visualization

A trained BERT, DistilBERT, LSTM, or other deep-learning classifier can later be integrated into the content-analysis layer.

---

# Multi-Signal Email Analysis

## 1. Email Content Analysis

The system analyzes message content for phishing-related language and suspicious patterns.

Examples include:

- Urgent requests
- Password verification
- Login requests
- Account suspension messages
- Credential-related terminology
- Invoice and financial language
- Suspicious calls to action

These findings contribute to the final risk score.

Example:

```text
URGENT
Verify your password
Login immediately
Account suspended
```

These signals increase the risk associated with the message.

---

# 2. Header Analysis

Email headers are analyzed for suspicious or missing metadata.

Header analysis can identify indicators such as:

- Missing Message-ID
- Suspicious sender information
- Abnormal email metadata
- Header inconsistencies
- Sender-related anomalies

The findings are added to the explainable security result.

---

# 3. URL Analysis

URLs inside the email body are extracted and analyzed.

The URL scanner evaluates characteristics such as:

- Suspicious URL structures
- Unusual links
- Non-HTTPS URLs
- Potentially misleading links
- Risky URL patterns

URL findings contribute to the total email risk score.

---

# 4. Attachment Analysis

Attachments are analyzed as an additional security signal.

Attachment metadata and infection-related findings can contribute to:

- Risk scoring
- Security findings
- Final verdict
- Automatic quarantine decisions

---

# Email Authentication Engine

Content analysis alone cannot determine whether a sender is legitimate.

The system therefore implements:

- SPF
- DKIM
- DMARC

---

## SPF — Sender Policy Framework

SPF checks whether the server sending an email is authorized to send mail for the sender's domain.

Simplified flow:

```text
Sending IP
    |
    v
Sender Domain
    |
    v
DNS SPF Record
    |
    v
Is IP Authorized?
    |
  -------
  |     |
 PASS  FAIL
```

The implementation can return authentication states such as:

```text
PASS
FAIL
SOFTFAIL
NEUTRAL
INVALID
```

A negative SPF test was also performed by replacing the legitimate sending IP with an unauthorized test IP.

The authentication engine correctly returned:

```text
SPF: SOFTFAIL
```

---

## DKIM — DomainKeys Identified Mail

DKIM provides cryptographic verification of an email message.

The system:

1. Extracts the DKIM-Signature header.
2. Identifies the signing domain.
3. Identifies the DKIM selector.
4. Retrieves the public key from DNS.
5. Performs cryptographic signature verification.
6. Returns the verification result.

Simplified flow:

```text
Email
  |
  v
DKIM Signature
  |
  v
Selector + Domain
  |
  v
DNS Public Key
  |
  v
Cryptographic Verification
  |
 ------
 |    |
PASS FAIL
```

Tampering tests were also performed to confirm that modifying signed email content can cause DKIM validation to fail.

---

## DMARC — Domain-Based Message Authentication

DMARC combines authentication and domain-alignment concepts.

The system evaluates:

- SPF result
- SPF domain alignment
- DKIM result
- DKIM domain alignment
- From-domain identity
- Published DMARC policy

Simplified flow:

```text
              FROM DOMAIN
                   |
          -------------------
          |                 |
         SPF               DKIM
          |                 |
      Alignment         Alignment
          |                 |
          --------- ---------
                   |
                  DMARC
                   |
               PASS / FAIL
```

This helps detect sender-domain spoofing.

---

# Explainable Security Decisions

An important concept from the research I studied is explainability.

A security platform should not only return:

```text
PHISHING
```

It should also explain why.

The Email Security Gateway therefore returns:

- Risk score
- Final verdict
- Individual findings
- Authentication results
- Quarantine decision

Example:

```text
Risk Score: 100/100

Verdict:
HIGH RISK

Findings:
- Urgent language detected
- Password-related language detected
- Login-related language detected
- Suspicious URL detected

SPF:
INVALID

DKIM:
FAIL

DMARC:
FAIL

Quarantined:
YES
```

This makes the system easier to understand and investigate.

---

# Risk Scoring

Security signals are combined into a bounded risk score.

```text
Content
   |
Headers
   |
URLs
   |
Attachments
   |
Authentication
   |
   v
RISK ENGINE
   |
   v
Score: 0 - 100
   |
 ------------------------------
 |              |             |
 v              v             v
LOW RISK    SUSPICIOUS     HIGH RISK
```

High-risk or infected messages can automatically trigger quarantine.

---

# Multi-Tenant Security Architecture

The application was designed as a multi-tenant security platform.

Different organizations can have isolated data.

```text
                 Email Security Gateway
                           |
                -----------------------
                |                     |
                v                     v
             Tenant A              Tenant B
                |                     |
          Email Logs              Email Logs
          Quarantine              Quarantine
          Dashboard               Dashboard
```

Tenant identity is derived from the authenticated user's JWT.

The client cannot simply request another tenant's data.

This provides isolation between organizations.

---

# Authentication and Authorization

Users authenticate using email and password credentials.

Passwords are protected using hashing.

After successful authentication:

```text
Email + Password
       |
       v
Authentication Service
       |
       v
JWT Token
       |
       v
Protected API
       |
       v
Authenticated Tenant
       |
       v
Tenant Data Only
```

The system was tested for:

- Correct authentication
- Invalid passwords
- Missing tokens
- Cross-tenant access
- Tenant-specific email-log access

---

# Automatic Email Quarantine

High-risk emails can automatically be quarantined.

```text
Email
  |
  v
Security Analysis
  |
  v
Risk Score
  |
  v
High Risk?
  |
 -------
 |     |
YES    NO
 |      |
 v      v
Quarantine
        |
      Record
```

For quarantined messages, the system:

1. Stores the raw `.eml` message.
2. Stores quarantine metadata.
3. Associates the record with the correct tenant.
4. Allows authenticated administrators to inspect records.
5. Allows secure deletion.
6. Prevents cross-tenant deletion.

Filesystem path validation is also used before deleting physical quarantine files.

---

# Security Operations Dashboard

A web security dashboard was developed on top of the FastAPI backend.

The dashboard displays real application data rather than hard-coded demo statistics.

Features include:

- Total emails analyzed
- Threats detected
- Quarantined messages
- Average risk score
- Recent email activity
- Email logs
- Quarantine records
- SPF status
- DKIM status
- DMARC status
- Live `.eml` email scanning

---

# Experimental Validation

The project was validated using both genuine emails and controlled security tests.

## Test 1 — Legitimate Authenticated Email

A genuine email was downloaded as a raw `.eml` message and analyzed.

Observed result:

```text
Risk Score: 20/100

Verdict:
LOW RISK

SPF:
PASS

DKIM:
PASS

DMARC:
PASS

Quarantined:
NO
```

This demonstrated successful authentication of a legitimate message.

---

## Test 2 — Controlled Phishing Simulation

A synthetic phishing-style email contained indicators including:

```text
URGENT
Verify your password
Login immediately
Account suspended
```

Observed result:

```text
Risk Score:
100/100

Verdict:
HIGH RISK

Quarantined:
YES
```

The high-risk message was automatically placed into quarantine.

---

## Test 3 — SPF Negative Validation

A test message was modified to simulate delivery from an unauthorized sending IP.

Observed authentication result:

```text
SPF:
SOFTFAIL
```

This demonstrated detection of an unauthorized sending host.

---

## Test 4 — DKIM Tampering

A signed email was modified to validate cryptographic integrity checking.

Observed result:

```text
DKIM:
FAIL
```

This demonstrated that DKIM verification can detect message modification.

---

# Research Concepts Mapped to the Implementation

| Research Concept | Project Implementation |
|---|---|
| Multi-modal phishing analysis | Multiple email security signals |
| Email content processing | Content and phishing-language analysis |
| Metadata features | Header analysis |
| URL features | URL extraction and analysis |
| Attachment features | Attachment inspection |
| Feature fusion | Combined risk engine |
| Explainability | Individual security findings |
| Sender authentication | SPF |
| Cryptographic verification | DKIM |
| Domain alignment | DMARC |
| Classification | Risk score and verdict |
| Threat response | Automatic quarantine |
| Privacy / isolation | Multi-tenant authorization |
| Operational monitoring | Security dashboard |

---

# Research-to-Implementation Workflow

```text
Read Research Papers
        |
        v
Understand Proposed Architectures
        |
        v
Identify Important Email Features
        |
        v
Design Multi-Signal Architecture
        |
        v
Implement Email Parsing
        |
        v
Implement Security Analyzers
        |
        v
Implement SPF / DKIM / DMARC
        |
        v
Implement Explainable Risk Scoring
        |
        v
Implement Tenant Isolation
        |
        v
Implement Automatic Quarantine
        |
        v
Build Security Dashboard
        |
        v
Validate Using Real and Synthetic Emails
```

---

# Current Version vs Future Deep-Learning Version

The current implementation uses security features, rules, authentication signals, and risk aggregation.

```text
Current Version

Email
  |
  v
Security Signals
  |
  v
Risk Engine
  |
  v
Verdict
```

A future version can integrate a trained deep-learning classifier:

```text
Future Version

Email Text
   |
   v
BERT / DistilBERT / LSTM
   |
   v
Phishing Probability
   |
   v
Existing Risk Engine
   |
   v
Final Security Verdict
```

The existing architecture allows an ML model to be added without redesigning the entire platform.

---

# Technology Stack

## Backend

- Python
- FastAPI
- Uvicorn

## Security

- SPF
- DKIM
- DMARC
- JWT
- Password hashing

## Database

- SQLite

## Frontend

- HTML5
- CSS3
- JavaScript

## Infrastructure

- Linux
- systemd
- DigitalOcean

---

# Core API Endpoints

```text
POST   /auth/login
POST   /scan-email/
GET    /me/email-logs
GET    /domains/{domain_name}/email-logs
GET    /me/quarantine
GET    /me/quarantine/{record_id}
DELETE /me/quarantine/{record_id}
GET    /dashboard/
```

---

# Project Structure

```text
email-security-gateway/
|
├── app.py
├── auth/
├── authentication/
├── scanners/
├── database/
├── quarantine/
├── dashboard/
│   ├── index.html
│   ├── dashboard.css
│   └── dashboard.js
├── requirements.txt
├── .gitignore
└── README.md
```

---

# Future Research Work

Potential future extensions include:

- BERT phishing-email classification
- DistilBERT classification
- LSTM-based email classification
- Multi-modal feature fusion
- URL embedding models
- Explainable AI using SHAP
- Federated learning
- Non-IID federated learning
- Adversarial-client experiments
- Robust phishing-detection models

---

# Research References

This project was developed after studying research on multi-modal phishing detection and deep-learning-based email security.

## Paper 1 — Multi-Modal Phishing Detection

**M. Murhej and G. Nallasivan**

**“Multi-modal framework for phishing attack detection and mitigation through behavior analysis using EM-BERT and SPCA-based EAI-SC-LSTM.”**

*Frontiers in Communications and Networks*, 2025.

DOI: https://doi.org/10.3389/frcmn.2025.1587654

### Connection to this project

This paper influenced the multi-signal architecture used in the Email Security Gateway. The research combines multiple sources of phishing information instead of relying only on message text.

Concepts adapted into this project include:

- Multi-modal / multi-signal phishing analysis
- Email-content analysis
- Feature combination
- Explainable security decisions
- Integration of multiple security indicators

The current implementation combines content, headers, URLs, attachments, SPF, DKIM, and DMARC into an explainable risk-scoring pipeline.

---

## Paper 2 — Deep-Learning-Based Phishing Email Detection

**K. Thakur, M. L. Ali, M. A. Obaidat, and A. Kamruzzaman**

**“A systematic review on deep-learning-based phishing email detection.”**

*Electronics*, 2023, 12(21), 4545.

DOI: https://doi.org/10.3390/electronics12214545

### Connection to this project

This paper provided background on deep-learning approaches for phishing-email detection, including NLP, neural-network classification, feature extraction, datasets, and hybrid detection systems.

The current project focuses on building the complete security-engineering pipeline around such models. A future BERT, DistilBERT, or LSTM classifier can be integrated into the existing content-analysis layer.

---

## Research-to-Implementation Mapping

| Research Concept | Project Implementation |
|---|---|
| Multi-modal detection | Multi-signal email analysis |
| Email-text analysis | Content analyzer |
| Metadata features | Header analysis |
| URL features | URL scanner |
| Feature fusion | Risk-scoring engine |
| Explainability | Security findings |
| Sender authentication | SPF |
| Cryptographic validation | DKIM |
| Domain alignment | DMARC |
| Threat mitigation | Automatic quarantine |
| Data isolation | Multi-tenant JWT authorization |
| Visualization | Security operations dashboard |

The project represents a **research-to-engineering implementation**, translating phishing-detection research concepts into a working email-security platform.

---


# Project Status

## Version 1.0

Completed components:

- Email parsing
- Multi-signal phishing analysis
- Header analysis
- URL analysis
- Attachment analysis
- Explainable risk scoring
- SPF validation
- DKIM cryptographic verification
- DMARC alignment evaluation
- JWT authentication
- Multi-tenant isolation
- Email event logging
- Automatic quarantine
- Quarantine management
- Live `.eml` scanning
- Security operations dashboard
- Linux deployment

The project demonstrates how concepts studied in phishing-detection research can be translated into a functioning email-security engineering platform.
