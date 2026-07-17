"""
explainer.py
SHAP wrapper around the trained Random Forest classifier.
"""

import json
import joblib
import numpy as np
import pandas as pd
import shap

MODEL_PATH = "model/model.pkl"
SCALER_PATH = "model/scaler.pkl"
LABEL_ENCODER_PATH = "model/le_encoder.pkl"
FEATURE_NAMES_PATH = "model/feature_names.json"


class IDSExplainer:
    def __init__(self):
        self.model = joblib.load(MODEL_PATH)
        self.scaler = joblib.load(SCALER_PATH)
        self.label_encoder = joblib.load(LABEL_ENCODER_PATH)

        with open(FEATURE_NAMES_PATH) as f:
            self.feature_names = json.load(f)

        self.shap_explainer = shap.TreeExplainer(self.model)

    def _to_frame(self, features: dict) -> pd.DataFrame:
        row = {name: features.get(name, 0.0) for name in self.feature_names}
        return pd.DataFrame([row], columns=self.feature_names)

    def predict(self, features: dict) -> dict:
        X = self._to_frame(features)
        X_scaled = self.scaler.transform(X)

        pred_encoded = self.model.predict(X_scaled)[0]
        pred_label = self.label_encoder.inverse_transform([pred_encoded])[0]

        proba = self.model.predict_proba(X_scaled)[0]
        confidence = float(np.max(proba) * 100)

        return {
            "attack_type": pred_label,
            "confidence": round(confidence, 2),
            "is_attack": pred_label != "BENIGN",
            "X_scaled": X_scaled,
            "pred_encoded": pred_encoded,
        }

    def explain(self, X_scaled, pred_encoded, top_n: int = 5) -> list:
        shap_values = self.shap_explainer.shap_values(X_scaled)
        class_shap = shap_values[pred_encoded][0]

        pairs = list(zip(self.feature_names, class_shap))
        pairs.sort(key=lambda p: abs(p[1]), reverse=True)

        top = pairs[:top_n]
        return [
            {
                "feature": name,
                "shap_value": round(float(val), 4),
                "impact": "positive" if val > 0 else "negative",
            }
            for name, val in top
        ]