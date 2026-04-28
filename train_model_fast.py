import sqlite3
from sklearn.ensemble import RandomForestClassifier
import joblib

conn = sqlite3.connect("database/zeroguardian.db")
cursor = conn.cursor()

cursor.execute("""
SELECT request_count, data_size, failed_attempts
FROM logs
""")

rows = cursor.fetchall()
conn.close()

# Prepare data
X = []
y = []

for r in rows:
    rc, ds, fa = r
    X.append([rc, ds, fa])

    # Label logic
    if rc > 100 or fa > 3:
        y.append(1)
    else:
        y.append(0)

# Train model
model = RandomForestClassifier()
model.fit(X, y)

joblib.dump(model, "model.pkl")

print("✅ Fast model trained (no pandas)")
