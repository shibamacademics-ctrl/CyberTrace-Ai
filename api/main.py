"""
api/main.py
FastAPI backend for CyberTrace AI.

Loads the SAME model artifacts produced by train_model.py:
    model/model.pkl
    model/scaler.pkl
    model/le_encoder.pkl
    model/feature_names.json

so predictions here are guaranteed consistent with the trained model
(same feature order, same scaler, same label encoding).

Run from the project root:
    cd cybertrace_ai
    uvicorn api.main:app --reload --port 8000
"""

import os
import sys
from typing import Dict, List, Optional

# Allow "explainer", "certificate_generator", "database" to be imported
# even though this file lives inside api/ rather than the project root.
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from explainer import IDSExplainer
from certificate_generator import generate_certificate
import database

app = FastAPI(title="CyberTrace AI API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Loaded on demand or at startup. This is the single source of truth for
# model / scaler / label_encoder / feature_names across every request.
explainer: Optional[IDSExplainer] = None


def get_explainer() -> IDSExplainer:
    global explainer
    if explainer is None:
        explainer = IDSExplainer()
        try:
            database.init_db()
        except Exception as e:
            print(f"Warning: Database init failed: {e}")
    return explainer


@app.on_event("startup")
def startup_event():
    get_explainer()


class PredictRequest(BaseModel):
    features: Dict[str, float]


class ShapEntry(BaseModel):
    feature: str
    shap_value: float
    impact: str


class ReasonEntry(BaseModel):
    phrase: str
    impact_level: str


class PredictResponse(BaseModel):
    attack_type: str
    confidence: float
    is_attack: bool
    summary: str
    context: str
    reasons: List[ReasonEntry]
    top_shap_values: List[ShapEntry]


@app.get("/health")
@app.get("/api/health")
def health():
    try:
        exp = get_explainer()
        loaded = exp is not None
    except Exception:
        loaded = False
    return {
        "status": "ok" if loaded else "model not loaded",
        "model_loaded": loaded,
    }


@app.get("/features")
@app.get("/api/features")
def get_features():
    exp = get_explainer()
    if exp is None:
        raise HTTPException(status_code=503, detail="Model not loaded yet")
    return {"feature_names": exp.feature_names}


@app.post("/predict", response_model=PredictResponse)
@app.post("/api/predict", response_model=PredictResponse)
def predict(request: PredictRequest):
    exp = get_explainer()
    if exp is None:
        raise HTTPException(status_code=503, detail="Model not loaded yet")

    try:
        result = exp.predict(request.features)
        top_shap_values = exp.explain(
            result["X_scaled"], result["pred_encoded"], top_n=5
        )

        certificate = generate_certificate(
            attack_type=result["attack_type"],
            confidence=result["confidence"],
            top_shap_values=top_shap_values,
        )

        response = {
            "attack_type": result["attack_type"],
            "confidence": result["confidence"],
            "is_attack": result["is_attack"],
            "summary": certificate["summary"],
            "context": certificate["context"],
            "reasons": certificate["reasons"],
            "top_shap_values": top_shap_values,
        }

        try:
            database.save_alert(response)
        except Exception as db_err:
            print(f"Warning: Database save failed: {db_err}")

        return response

    except KeyError as e:
        raise HTTPException(status_code=400, detail=f"Missing/invalid feature: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/alerts")
@app.get("/api/alerts")
def alerts(limit: int = 50):
    return database.get_alerts(limit=limit)
