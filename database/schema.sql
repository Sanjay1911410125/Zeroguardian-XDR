-- LOGS TABLE (core data)
CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT,
    endpoint TEXT,
    request_count INTEGER,
    data_size INTEGER,
    response_code INTEGER,
    failed_attempts INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- DEVICES TABLE (unique devices)
CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE,
    device_name TEXT,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- THREATS TABLE (basic detection)
CREATE TABLE threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT,
    threat_type TEXT,
    severity TEXT,
    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- AI THREATS TABLE (ML output)
CREATE TABLE ai_threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT,
    prediction TEXT,
    confidence REAL,
    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- RISK SCORING TABLE
CREATE TABLE risk_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT,
    risk_score INTEGER,
    risk_level TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
