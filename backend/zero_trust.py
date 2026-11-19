
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_DIR = BASE_DIR / "datasets"
DATABASE_DIR.mkdir(exist_ok=True)

DATABASE_PATH = DATABASE_DIR / "zero_trust_audit.db"


def get_connection():
    return sqlite3.connect(DATABASE_PATH)


def initialize_zero_trust():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                resource TEXT NOT NULL,
                device_trusted INTEGER NOT NULL,
                mfa_verified INTEGER NOT NULL,
                risk_score INTEGER NOT NULL,
                decision TEXT NOT NULL,
                reason TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)


def evaluate_access(data):
    required_fields = [
        "username",
        "role",
        "resource",
        "device_trusted",
        "mfa_verified",
        "risk_score"
    ]

    for field in required_fields:
        if field not in data:
            raise ValueError(f"Missing required field: {field}")

    username = str(data["username"]).strip()
    role = str(data["role"]).strip()
    resource = str(data["resource"]).strip()

    if not username or not role or not resource:
        raise ValueError("Username, role and resource cannot be empty.")

    if not isinstance(data["device_trusted"], bool):
        raise ValueError("device_trusted must be true or false.")

    if not isinstance(data["mfa_verified"], bool):
        raise ValueError("mfa_verified must be true or false.")

    try:
        risk_score = int(data["risk_score"])
    except (TypeError, ValueError):
        raise ValueError("Risk score must be an integer.")

    if not 0 <= risk_score <= 100:
        raise ValueError("Risk score must be between 0 and 100.")

    reasons = []

    if not data["device_trusted"]:
        reasons.append("Untrusted device")

    if not data["mfa_verified"]:
        reasons.append("MFA verification failed")

    if risk_score >= 70:
        reasons.append("High risk score")

    decision = "DENY" if reasons else "ALLOW"

    reason = (
        "; ".join(reasons)
        if reasons
        else "All Zero-Trust security checks passed"
    )

    timestamp = datetime.now(timezone.utc).isoformat()

    with get_connection() as connection:
        cursor = connection.execute("""
            INSERT INTO access_logs (
                username, role, resource,
                device_trusted, mfa_verified,
                risk_score, decision, reason, timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            username,
            role,
            resource,
            int(data["device_trusted"]),
            int(data["mfa_verified"]),
            risk_score,
            decision,
            reason,
            timestamp
        ))

        log_id = cursor.lastrowid

    return {
        "status": "success",
        "decision": decision,
        "reason": reason,
        "log_id": log_id,
        "timestamp": timestamp
    }


def get_access_logs(limit=100):
    limit = max(1, min(int(limit), 500))

    with get_connection() as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute("""
            SELECT * FROM access_logs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]
