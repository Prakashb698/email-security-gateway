from database.database import get_connection


def get_or_create_domain(domain_name: str):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "INSERT OR IGNORE INTO domains(name) VALUES (?)",
        (domain_name,)
    )

    cur.execute(
        "SELECT id FROM domains WHERE name = ?",
        (domain_name,)
    )

    row = cur.fetchone()
    conn.commit()
    conn.close()

    return row["id"] if row else None


def save_email_log(sender, recipient, subject, verdict, risk_score, domain_name):
    domain_id = get_or_create_domain(domain_name)

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO email_logs(sender, recipient, subject, verdict, risk_score, domain_id)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (sender, recipient, subject, verdict, risk_score, domain_id)
    )

    conn.commit()
    conn.close()


def get_email_logs_by_domain(domain_name: str):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT
            email_logs.id,
            email_logs.sender,
            email_logs.recipient,
            email_logs.subject,
            email_logs.verdict,
            email_logs.risk_score,
            email_logs.created_at
        FROM email_logs
        JOIN domains ON email_logs.domain_id = domains.id
        WHERE domains.name = ?
        ORDER BY email_logs.id DESC
        """,
        (domain_name,)
    )

    rows = cur.fetchall()
    conn.close()

    return [dict(row) for row in rows]
