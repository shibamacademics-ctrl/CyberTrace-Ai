"""
database.py
Lightweight SQLite persistence layer for CyberTrace AI alerts.

This module was referenced by api/main.py (`import database`,
`database.init_db()`, `database.save_alert()`, `database.get_alerts()`)
but was missing from the project, which caused the API to fail on
startup with:

    ModuleNotFoundError: No module named 'database'

It stores every /predict response so the /alerts endpoint (and the
frontend's live alert feed) can show recent history.
"""

import json
import os
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone

# On Vercel / serverless lambda environments, only /tmp is writable.
if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    DB_PATH = os.path.join(tempfile.gettempdir(), "alerts.db")
    source_db = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alerts.db")
    if os.path.exists(source_db) and not os.path.exists(DB_PATH):
        try:
            shutil.copyfile(source_db, DB_PATH)
        except Exception:
            pass
else:
    DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alerts.db")


def _get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create the alerts table if it doesn't already exist."""
    try:
        with _get_conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    attack_type VARCHAR NOT NULL,
                    confidence FLOAT NOT NULL,
                    is_attack BOOLEAN NOT NULL,
                    summary TEXT NOT NULL,
                    context TEXT NOT NULL,
                    reasons TEXT NOT NULL,
                    top_shap_values TEXT NOT NULL
                )
                """
            )
            conn.commit()
    except Exception as e:
        print(f"Database init warning: {e}")


def save_alert(response: dict) -> dict:
    """Persist a /predict response and return the stored record."""
    try:
        ts = datetime.now(timezone.utc).isoformat()
        with _get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO alerts (timestamp, attack_type, confidence, is_attack, summary, context, reasons, top_shap_values)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    str(response["attack_type"]),
                    float(response["confidence"]),
                    1 if response["is_attack"] else 0,
                    str(response["summary"]),
                    str(response["context"]),
                    json.dumps(response["reasons"]),
                    json.dumps(response["top_shap_values"]),
                ),
            )
            conn.commit()
            return {
                "id": cursor.lastrowid,
                "timestamp": ts,
                **response,
            }
    except Exception as e:
        print(f"Warning: Failed to save alert: {e}")
        return {
            "id": None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **response,
        }


def get_alerts(limit: int = 50) -> list:
    """Return the most recent alerts, newest first."""
    try:
        with _get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, timestamp, attack_type, confidence, is_attack, summary, context, reasons, top_shap_values FROM alerts ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()
            result = []
            for r in rows:
                result.append(
                    {
                        "id": r["id"],
                        "timestamp": str(r["timestamp"]) if r["timestamp"] else None,
                        "attack_type": r["attack_type"],
                        "confidence": float(r["confidence"]),
                        "is_attack": bool(r["is_attack"]),
                        "summary": r["summary"],
                        "context": r["context"],
                        "reasons": json.loads(r["reasons"]) if r["reasons"] else [],
                        "top_shap_values": json.loads(r["top_shap_values"]) if r["top_shap_values"] else [],
                    }
                )
            return result
    except Exception as e:
        print(f"Warning: Failed to get alerts: {e}")
        return []
