import os
import sqlite3

DB_PATH = os.path.join("database", "zeroguardian.db")

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS threat_signatures (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  category TEXT NOT NULL,          -- e.g., Network, Endpoint, Web, Auth
  indicator TEXT NOT NULL,         -- what we check (e.g., "dst_port", "packet_rate", "proto")
  operator TEXT NOT NULL,          -- e.g., "eq", "gt", "in", "contains"
  value TEXT NOT NULL,             -- store as text; parse later
  severity TEXT NOT NULL,          -- LOW/MEDIUM/HIGH/CRITICAL
  description TEXT
);

CREATE TABLE IF NOT EXISTS ml_baseline_samples (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,             -- unix ms
  device_count INTEGER NOT NULL,
  total_packets INTEGER NOT NULL,
  talker_count INTEGER NOT NULL,
  tcp_count INTEGER NOT NULL,
  udp_count INTEGER NOT NULL,
  icmp_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  first_seen_ts INTEGER NOT NULL,
  last_seen_ts INTEGER NOT NULL,
  ip TEXT NOT NULL,
  mac TEXT,
  name TEXT,
  state TEXT
);

CREATE TABLE IF NOT EXISTS detections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  source TEXT NOT NULL,            -- "rule" or "ml"
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  ip TEXT,
  details TEXT
);
"""

def init_db():
  os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
  conn = sqlite3.connect(DB_PATH)
  cur = conn.cursor()
  cur.executescript(SCHEMA_SQL)
  conn.commit()
  conn.close()
  print("[DB] Initialized:", DB_PATH)

if __name__ == "__main__":
  init_db()
