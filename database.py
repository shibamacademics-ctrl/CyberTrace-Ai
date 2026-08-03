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
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Boolean,
    Text,
    DateTime,
    create_engine,
)
from sqlalchemy.orm import declarative_base, sessionmaker

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alerts.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    attack_type = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)
    is_attack = Column(Boolean, nullable=False)
    summary = Column(Text, nullable=False)
    context = Column(Text, nullable=False)
    # Stored as JSON text since SQLite has no native list/dict column type.
    reasons = Column(Text, nullable=False)
    top_shap_values = Column(Text, nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "attack_type": self.attack_type,
            "confidence": self.confidence,
            "is_attack": self.is_attack,
            "summary": self.summary,
            "context": self.context,
            "reasons": json.loads(self.reasons),
            "top_shap_values": json.loads(self.top_shap_values),
        }


def init_db() -> None:
    """Create the alerts table if it doesn't already exist."""
    Base.metadata.create_all(bind=engine)


def save_alert(response: dict) -> dict:
    """Persist a /predict response and return the stored record."""
    session = SessionLocal()
    try:
        alert = Alert(
            attack_type=response["attack_type"],
            confidence=response["confidence"],
            is_attack=response["is_attack"],
            summary=response["summary"],
            context=response["context"],
            reasons=json.dumps(response["reasons"]),
            top_shap_values=json.dumps(response["top_shap_values"]),
        )
        session.add(alert)
        session.commit()
        session.refresh(alert)
        return alert.to_dict()
    finally:
        session.close()


def get_alerts(limit: int = 50) -> list:
    """Return the most recent alerts, newest first."""
    session = SessionLocal()
    try:
        rows = (
            session.query(Alert)
            .order_by(Alert.id.desc())
            .limit(limit)
            .all()
        )
        return [row.to_dict() for row in rows]
    finally:
        session.close()
