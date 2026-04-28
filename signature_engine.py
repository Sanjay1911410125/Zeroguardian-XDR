def detect_known_threat(request_path, user_agent, failed_attempts):
    
    # Simple signatures
    if "admin" in request_path and failed_attempts > 3:
        return "BRUTE FORCE ATTACK"

    if "SELECT" in request_path or "DROP" in request_path:
        return "SQL INJECTION"

    if "curl" in user_agent.lower():
        return "BOT / SCRIPT ATTACK"

    return None
