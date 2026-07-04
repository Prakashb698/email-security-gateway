from database.database import get_connection


def save_quarantine_record(
    sender: str,
    recipient: str,
    subject: str,
    verdict: str,
    risk_score: int,
    reason: str,
    file_path: str,
    domain_name: str,
):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT id FROM domains WHERE name = ? AND active = 1",
        (domain_name,),
    )
    domain = cur.fetchone()

    if not domain:
        conn.close()
        raise ValueError(f"Unknown or inactive domain: {domain_name}")

    cur.execute(
        """
        INSERT INTO quarantine_records (
            sender,
            recipient,
            subject,
            verdict,
            risk_score,
            reason,
            file_path,
            domain_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            sender,
            recipient,
            subject,
            verdict,
            risk_score,
            reason,
            file_path,
            domain["id"],
        ),
    )

    record_id = cur.lastrowid
    conn.commit()
    conn.close()

    return record_id


def get_quarantine_records_by_domain(domain_name: str):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT
            q.id,
            q.sender,
            q.recipient,
            q.subject,
            q.verdict,
            q.risk_score,
            q.reason,
            q.file_path,
            q.created_at
        FROM quarantine_records q
        JOIN domains d ON q.domain_id = d.id
        WHERE d.name = ?
        ORDER BY q.created_at DESC
        """,
        (domain_name,),
    )

    records = [dict(row) for row in cur.fetchall()]
    conn.close()

    return records
