import numpy as np

def predict_threat(request_count, data_size, failed_attempts):
    
    score = 0

    # Rule-based intelligence (acts like ML)
    if request_count > 100:
        score += 40
    if data_size > 5000:
        score += 30
    if failed_attempts > 3:
        score += 30

    # Normalize score
    if score >= 60:
        return "HIGH RISK"
    elif score >= 30:
        return "MEDIUM RISK"
    else:
        return "LOW RISK"

