"""
explainer.py
SHAP wrapper around the trained Random Forest classifier.
"""

import json
import os
import warnings
import joblib
import numpy as np
import shap

# Suppress feature name UserWarning from scikit-learn when passing raw arrays
warnings.filterwarnings("ignore", category=UserWarning)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model", "model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "model", "scaler.pkl")
LABEL_ENCODER_PATH = os.path.join(BASE_DIR, "model", "le_encoder.pkl")
FEATURE_NAMES_PATH = os.path.join(BASE_DIR, "model", "feature_names.json")


class IDSExplainer:
    def __init__(self):
        self.model = joblib.load(MODEL_PATH)
        self.scaler = joblib.load(SCALER_PATH)
        self.label_encoder = joblib.load(LABEL_ENCODER_PATH)

        with open(FEATURE_NAMES_PATH) as f:
            self.feature_names = json.load(f)

        self.shap_explainer = shap.TreeExplainer(self.model)

    def _to_array(self, features: dict) -> np.ndarray:
        row = [float(features.get(name, 0.0)) for name in self.feature_names]
        return np.array([row], dtype=np.float32)

    def predict(self, features: dict) -> dict:
        X = self._to_array(features)
        X_scaled = self.scaler.transform(X)

        pred_encoded = int(self.model.predict(X_scaled)[0])
        pred_label = str(self.label_encoder.inverse_transform([pred_encoded])[0])

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

        # FIX: older SHAP versions returned a list of (n_samples, n_features)
        # arrays, one per class — `shap_values[pred_encoded][0]` indexed into
        # that list. Newer SHAP versions (0.44+) instead return a single
        # (n_samples, n_features, n_classes) ndarray, so the same indexing
        # was reaching into the SAMPLES axis instead of the CLASSES axis and
        # raising IndexError for any pred_encoded > 0 (i.e. almost always).
        if isinstance(shap_values, list):
            class_shap = shap_values[pred_encoded][0]
        else:
            class_shap = shap_values[0, :, pred_encoded]

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