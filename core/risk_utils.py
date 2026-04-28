import json, os, time

RISK_DB = os.path.join("database", "risk_scores.json")

def load_risk_db():
    if not os.path.exists(RISK_DB):
        os.makedirs(os.path.dirname(RISK_DB), exist_ok=True)
        with open(RISK_DB, "w") as f:
            f.write("{}")
    with open(RISK_DB, "r") as f:
        try:
            return json.load(f)
        except:
            return {}

def save_risk_snapshot(summary, per_ip):
    db = load_risk_db()
    ts = str(int(time.time()))

    # store small history (last 20 snapshots)
    db.setdefault("history", [])
    db["history"].append({
        "ts": ts,
        "overall_score": summary.get("overall_score", 0),
        "overall_level": summary.get("overall_level", "LOW"),
        "high_count": summary.get("high_count", 0),
        "medium_count": summary.get("medium_count", 0)
    })
    db["history"] = db["history"][-20:]

    # store latest per-device
    db["latest"] = per_ip

    with open(RISK_DB, "w") as f:
        json.dump(db, f, indent=2)
