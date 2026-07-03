from database.database import get_connection


def create_user(email: str, password_hash: str, domain_name: str):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT id FROM domains WHERE name = ? AND active = 1",
        (domain_name,)
    )

    domain = cur.fetchone()

    if not domain:
        conn.close()
        raise ValueError("Domain does not exist or is inactive")

    cur.execute(
        """
        INSERT INTO users(email, password_hash, domain_id)
        VALUES (?, ?, ?)
        """,
        (email.lower().strip(), password_hash, domain["id"])
    )

    conn.commit()
    user_id = cur.lastrowid
    conn.close()

    return user_id


def get_user_by_email(email: str):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT
            users.id,
            users.email,
            users.password_hash,
            users.active,
            domains.name AS domain_name
        FROM users
        JOIN domains ON users.domain_id = domains.id
        WHERE users.email = ?
        """,
        (email.lower().strip(),)
    )

    row = cur.fetchone()
    conn.close()

    return dict(row) if row else None
