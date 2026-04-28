# core/ai_detector.py
# Real autoencoder-based anomaly detector for ZeroGuardian XDR
# Replaces the fake tanh-based stub with a trained TensorFlow model.
# Falls back to statistical scoring if model file not found.

import os
import json
import numpy as np

MODEL_DIR  = os.path.join(os.path.dirname(__file__), "..", "models")
MODEL_PATH = os.path.join(MODEL_DIR, "autoencoder.keras")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.json")

FEATURE_DIM = 5   # must match core/features.py build_features() output length

# ── Threshold (percentile-based, set during training) ─────────────────────────
DEFAULT_THRESHOLD = 0.15   # overridden by models/scaler.json if present


class AutoEncoderDetector:
    """
    Wraps a trained Keras autoencoder + a min-max scaler saved as JSON.
    If the model file is missing, falls back to a statistical scorer so the
    dashboard still runs while you collect training data.
    """

    def __init__(self):
        self.model      = None
        self.scaler     = None          # {"min": [...], "scale": [...]}
        self.threshold  = DEFAULT_THRESHOLD
        self._load()

    # ── Loading ───────────────────────────────────────────────────────────────

    def _load(self):
        # Load scaler (always needed for inference)
        if os.path.exists(SCALER_PATH):
            try:
                with open(SCALER_PATH) as f:
                    meta = json.load(f)
                self.scaler    = meta
                self.threshold = float(meta.get("threshold", DEFAULT_THRESHOLD))
                print("[AI] Scaler loaded ✅")
            except Exception as e:
                print(f"[AI] Scaler load failed: {e}")

        # Load Keras model (optional — graceful fallback if missing)
        if os.path.exists(MODEL_PATH):
            try:
                os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"   # silence TF logs
                from tensorflow import keras                 # lazy import
                self.model = keras.models.load_model(MODEL_PATH)
                print("[AI] Autoencoder model loaded ✅")
            except Exception as e:
                print(f"[AI] Model load failed (fallback mode): {e}")
        else:
            print("[AI] No trained model found — using statistical fallback."
                  " Run: python3 train_autoencoder.py")

    # ── Preprocessing ─────────────────────────────────────────────────────────

    def _scale(self, features: list) -> np.ndarray:
        x = np.array(features, dtype=float)

        if self.scaler:
            mn  = np.array(self.scaler["min"],   dtype=float)
            sc  = np.array(self.scaler["scale"], dtype=float)
            x = (x - mn) / (sc + 1e-8)
        else:
            # Z-score normalise if no scaler saved
            x = (x - np.mean(x)) / (np.std(x) + 1e-8)

        return x.reshape(1, -1)

    # ── Scoring ───────────────────────────────────────────────────────────────

    def _reconstruction_error(self, x_scaled: np.ndarray) -> float:
        if self.model is not None:
            recon = self.model.predict(x_scaled, verbose=0)
            return float(np.mean(np.abs(x_scaled - recon)))

        # ── Statistical fallback (no model) ──────────────────────────────────
        # Uses a simple heuristic: large deviations from typical normal-traffic
        # ranges flag as anomalous.
        raw = x_scaled[0]   # already normalised
        # MSE of reconstruction via identity (tanh trick) — better than old code
        recon = np.clip(raw, -1, 1)
        return float(np.mean((raw - recon) ** 2))

    # ── Public API ────────────────────────────────────────────────────────────

    def predict(self, features: list) -> dict:
        """
        features : list[float] matching core/features.py build_features()
        Returns  : {anomaly, score, severity, confidence, details}
        """
        if len(features) < FEATURE_DIM:
            features = features + [0.0] * (FEATURE_DIM - len(features))
        features = features[:FEATURE_DIM]

        try:
            x_scaled = self._scale(features)
            error    = self._reconstruction_error(x_scaled)
        except Exception as e:
            return {
                "anomaly":    False,
                "score":      0.0,
                "severity":   "LOW",
                "confidence": 0,
                "details":    f"Detector error: {e}",
                "model":      "AutoEncoder (error)"
            }

        anomaly  = error > self.threshold
        ratio    = error / (self.threshold + 1e-8)

        # severity bands
        if error >= self.threshold * 3:
            severity = "CRITICAL"
        elif error >= self.threshold * 2:
            severity = "HIGH"
        elif error >= self.threshold * 1.2:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # confidence 0-100 (capped)
        confidence = int(min(100, ratio * 50))

        model_tag = "AutoEncoder (trained)" if self.model else "AutoEncoder (statistical)"

        return {
            "anomaly":    anomaly,
            "score":      round(error, 4),
            "severity":   severity if anomaly else "LOW",
            "confidence": confidence,
            "details":    (
                f"Reconstruction error {error:.4f} vs threshold {self.threshold:.4f} "
                f"({'ANOMALY' if anomaly else 'NORMAL'})"
            ),
            "model": model_tag,
            "features": [
                {"feature": "device_count",   "value": str(features[0])},
                {"feature": "total_packets",  "value": str(features[1])},
                {"feature": "talker_count",   "value": str(features[2])},
                {"feature": "proto_count",    "value": str(features[3])},
                {"feature": "pps",            "value": str(round(features[4], 2))},
            ]
        }


# ── Drop-in alias so orchestrator.py needs zero changes ───────────────────────
SimpleAutoEncoderDetector = AutoEncoderDetector


# ── Quick self-test ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    det = AutoEncoderDetector()

    normal = [5.0, 3.0, 2.0, 2.0, 1.5]
    attack = [5.0, 800.0, 50.0, 8.0, 400.0]   # port scan / flood signature

    print("\n[Normal traffic]")
    print(det.predict(normal))

    print("\n[Simulated attack]")
    print(det.predict(attack))
