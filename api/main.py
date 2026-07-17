"""
api/main.py
FastAPI backend for CyberTrace AI.
"""

import os
import sys
from typing import Dict, List, Optional

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

explainer: Optional[IDSExplainer] = None


@app.on_event("startup")
def startup_event():
    global explainer
    explainer = IDSExplainer()
    database.init_db()


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
def health():
    return {
        "status": "ok" if explainer is not None else "model not loaded",
        "model_loaded": explainer is not None,
    }


@app.get("/features")
def get_features():
    if explainer is None:
        raise HTTPException(status_code=503, detail="Model not loaded yet")
    return {"feature_names": explainer.feature_names}


@app.post("/predict", response_model=PredictResponse)
def predict(request: PredictRequest):
    if explainer is None:
        raise HTTPException(status_code=503, detail="Model not loaded yet")

    try:
        result = explainer.predict(request.features)
        top_shap_values = explainer.explain(
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

        database.save_alert(response)
        return response

    except KeyError as e:
        raise HTTPException(status_code=400, detail=f"Missing/invalid feature: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/alerts")
def alerts(limit: int = 50):
    return database.get_alerts(limit=limit)
