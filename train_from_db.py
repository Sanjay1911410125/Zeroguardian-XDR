import sqlite3
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib

# Connect to DB
conn = sqlite3.connect("database/zeroguardian.db")

# Load data from logs table
data = pd.read_sql_query("""
SELECT request_count, data_size, failed_attempts,
CASE 
    WHEN request_count > 100 OR failed_attempts > 3 THEN 1
    ELSE 0
END as label
FROM logs
""", conn)

conn.close()

# Features & labels
X = data[["request_count", "data_size", "failed_attempts"]]
y = data["label"]

# Train model
model = RandomForestClassifier(n_estimators=50)
model.fit(X, y)

# Save model
joblib.dump(model, "model.pkl")

print("✅ Model trained successfully from real data")
