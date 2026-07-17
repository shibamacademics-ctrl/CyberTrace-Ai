"""
database.py
Minimal SQLite alert store used by the /alerts endpoint.
"""

from datetime import datetime, timezone

from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, JSON
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = "sqlite:///./alerts.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    attack_type = Column(String, index=True)
    confidence = Column(Float)
    is_attack = Column(Boolean)
    summary = Column(String)
    top_shap_values = Column(JSON)


def init_db():
    Base.metadata.create_all(bind=engine)


def save_alert(result: dict):
    db = SessionLocal()
    try:
        alert = Alert(
            attack_type=result["attack_type"],
            confidence=result["confidence"],
            is_attack=result["is_attack"],
            summary=result["summary"],
            top_shap_values=result["top_shap_values"],
        )
        db.add(alert)
        db.commit()
    finally:
        db.close()


def get_alerts(limit: int = 50):
    db = SessionLocal()
    try:
        rows = (
            db.query(Alert)
            .order_by(Alert.timestamp.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "id": r.id,
                "timestamp": r.timestamp.isoformat(),
                "attack_type": r.attack_type,
                "confidence": r.confidence,
                "is_attack": r.is_attack,
                "summary": r.summary,
                "top_shap_values": r.top_shap_values,
            }
            for r in rows
        ]
    finally:
        db.close()