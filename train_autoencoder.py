#!/usr/bin/env python3
# train_autoencoder.py
# ─────────────────────────────────────────────────────────────────────────────
# Trains a real Keras autoencoder on your normal_samples.jsonl data.
# Run once to create the model, then re-run whenever you collect more samples.
#
# Usage (from ~/ZeroGuardian-XDR/):
#   source venv/bin/activate
#   pip install tensorflow scikit-learn   # if not already installed
#   python3 train_autoencoder.py
#
# Outputs:
#   models/autoencoder.keras   ← Keras model file
#   models/scaler.json         ← min-max scaler + threshold
# ─────────────────────────────────────────────────────────────────────────────

import os, json, sys
import numpy as np

DATA_PATH   = os.path.join("data", "normal_samples.jsonl")
MODEL_DIR   = "models"
MODEL_PATH  = os.path.join(MODEL_DIR, "autoencoder.keras")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.json")

FEATURE_DIM   = 5       # [device_count, total_packets, talker_count, proto_count, pps]
EPOCHS        = 120
BATCH_SIZE    = 16
LATENT_DIM    = 2       # bottleneck — small = stronger compression = better anomaly signal
THRESHOLD_PCT = 95      # percentile of training errors used as anomaly threshold

os.makedirs(MODEL_DIR, exist_ok=True)


# ── 1. Load data ──────────────────────────────────────────────────────────────
def load_samples(path):
    samples = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            feat = obj.get("features", [])
            if len(feat) == FEATURE_DIM:
                samples.append(feat)
    return np.array(samples, dtype=float)


print("[Train] Loading samples …")
if not os.path.exists(DATA_PATH):
    print(f"[Train] ERROR: {DATA_PATH} not found.")
    print("        Run scripts/collect_samples.py first to gather baseline data.")
    sys.exit(1)

X = load_samples(DATA_PATH)
print(f"[Train] Loaded {len(X)} samples, shape={X.shape}")

if len(X) < 20:
    print("[Train] WARNING: fewer than 20 samples — model may be unreliable.")
    print("        Keep the system running to collect more normal traffic samples.")


# ── 2. Augment (doubles dataset with small noise for robustness) ───────────────
noise = np.random.normal(0, 0.05, X.shape)
X_aug = np.vstack([X, X + noise * X])   # proportional noise

# Shuffle
idx = np.random.permutation(len(X_aug))
X_aug = X_aug[idx]


# ── 3. Min-Max scale to [0, 1] ────────────────────────────────────────────────
x_min  = X_aug.min(axis=0)
x_max  = X_aug.max(axis=0)
scale  = (x_max - x_min) + 1e-8

X_scaled = (X_aug - x_min) / scale
print(f"[Train] Feature ranges after scaling: min={X_scaled.min():.3f} max={X_scaled.max():.3f}")


# ── 4. Build autoencoder ──────────────────────────────────────────────────────
print("[Train] Building autoencoder …")
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

try:
    from tensorflow import keras
    from tensorflow.keras import layers, callbacks
except ImportError:
    print("[Train] TensorFlow not installed. Run: pip install tensorflow")
    sys.exit(1)

inp = keras.Input(shape=(FEATURE_DIM,))

# Encoder
x = layers.Dense(16, activation="relu")(inp)
x = layers.Dense(8,  activation="relu")(x)
encoded = layers.Dense(LATENT_DIM, activation="relu", name="bottleneck")(x)

# Decoder
x = layers.Dense(8,  activation="relu")(encoded)
x = layers.Dense(16, activation="relu")(x)
decoded = layers.Dense(FEATURE_DIM, activation="sigmoid", name="reconstruction")(x)

autoencoder = keras.Model(inp, decoded, name="ZeroGuardian_AE")
autoencoder.compile(optimizer="adam", loss="mse")
autoencoder.summary()


# ── 5. Train ──────────────────────────────────────────────────────────────────
early_stop = callbacks.EarlyStopping(
    monitor="val_loss", patience=15, restore_best_weights=True
)
lr_sched = callbacks.ReduceLROnPlateau(
    monitor="val_loss", factor=0.5, patience=8, min_lr=1e-5
)

print(f"\n[Train] Training for up to {EPOCHS} epochs …")
history = autoencoder.fit(
    X_scaled, X_scaled,
    epochs=EPOCHS,
    batch_size=BATCH_SIZE,
    validation_split=0.15,
    callbacks=[early_stop, lr_sched],
    verbose=1,
)

final_loss = history.history["loss"][-1]
final_val  = history.history["val_loss"][-1]
print(f"\n[Train] Final loss={final_loss:.6f}  val_loss={final_val:.6f}")


# ── 6. Compute threshold ──────────────────────────────────────────────────────
recon      = autoencoder.predict(X_scaled, verbose=0)
errors     = np.mean(np.abs(X_scaled - recon), axis=1)
threshold  = float(np.percentile(errors, THRESHOLD_PCT))

print(f"[Train] Reconstruction error — mean={errors.mean():.5f}  "
      f"max={errors.max():.5f}  p{THRESHOLD_PCT}={threshold:.5f}")
print(f"[Train] Anomaly threshold set to {threshold:.5f} (p{THRESHOLD_PCT})")


# ── 7. Save model + scaler ────────────────────────────────────────────────────
autoencoder.save(MODEL_PATH)

scaler_data = {
    "min":       x_min.tolist(),
    "scale":     scale.tolist(),
    "threshold": threshold,
    "feature_dim": FEATURE_DIM,
    "features":  ["device_count", "total_packets", "talker_count",
                  "proto_count", "pps"],
    "samples_used": len(X),
    "epochs_run": len(history.history["loss"]),
    "final_val_loss": float(final_val),
    "threshold_percentile": THRESHOLD_PCT,
}

with open(SCALER_PATH, "w") as f:
    json.dump(scaler_data, f, indent=2)

print(f"\n[Train] ✅ Model saved  → {MODEL_PATH}")
print(f"[Train] ✅ Scaler saved → {SCALER_PATH}")
print(f"\n[Train] Done! Restart your Flask app to load the new model.")
print(f"        Kill and restart: pkill -f 'python.*app.py' && python3 dashboard/app.py")
