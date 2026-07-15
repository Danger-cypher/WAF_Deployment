from typing import Tuple


def classify_attack(rule_id: str) -> Tuple[str, str]:
    """
    Classify the attack type and severity based on ModSecurity/OWASP CRS rule IDs.
    Returns a tuple of (attack_type, severity).
    See: https://coreruleset.org/docs/rules/
    """
    if not rule_id:
        return "Unknown", "Low"

    try:
        rule_num = int(rule_id)
    except ValueError:
        return "Custom/Unknown", "Low"

    # OWASP CRS rule families
    # 910xxx - IP reputation, GeoIP blocking
    if 910000 <= rule_num <= 910999:
        return "IP Reputation", "High"
    # 911xxx - Method enforcement
    elif 911000 <= rule_num <= 911999:
        return "HTTP Method Abuse", "Medium"
    # 912xxx - DoS protection
    elif 912000 <= rule_num <= 912999:
        return "DoS/DDoS", "High"
    # 913xxx - Scanner detection
    elif 913000 <= rule_num <= 913999:
        return "Scanner/Recon", "Medium"
    # 920xxx - Protocol enforcement
    elif 920000 <= rule_num <= 920999:
        return "Protocol Violation", "Low"
    # 921xxx - HTTP request smuggling
    elif 921000 <= rule_num <= 921999:
        return "HTTP Smuggling", "High"
    # 922xxx - Multipart validation
    elif 922000 <= rule_num <= 922999:
        return "Multipart Violation", "Medium"
    # 930xxx - LFI/path traversal
    elif 930000 <= rule_num <= 930999:
        return "LFI/RFI", "High"
    # 931xxx - RFI
    elif 931000 <= rule_num <= 931999:
        return "LFI/RFI", "High"
    # 932xxx - Remote code execution
    elif 932000 <= rule_num <= 932999:
        return "RCE", "Critical"
    # 933xxx - PHP injection
    elif 933000 <= rule_num <= 933999:
        return "PHP Injection", "High"
    # 934xxx - Generic Attacks: SSRF (934100-934101), Node.js injection, XXE (934102)
    elif 934000 <= rule_num <= 934999:
        if 934100 <= rule_num <= 934101:
            return "SSRF", "Critical"
        elif rule_num == 934102:
            return "XXE Injection", "Critical"
        return "Code Injection", "High"
    # 941xxx - XSS
    elif 941000 <= rule_num <= 941999:
        return "XSS", "Critical"
    # 942xxx - SQL Injection
    elif 942000 <= rule_num <= 942999:
        return "SQL Injection", "Critical"
    # 943xxx - Session fixation
    elif 943000 <= rule_num <= 943999:
        return "Session Fixation", "Medium"
    # 944xxx - Java injection
    elif 944000 <= rule_num <= 944999:
        return "Java Injection", "High"
    # 949xxx - Anomaly score threshold (blocking)
    elif 949000 <= rule_num <= 949999:
        return "Anomaly Threshold Exceeded", "High"
    # 980xxx - Anomaly score threshold (response)
    elif 980000 <= rule_num <= 980999:
        return "Anomaly Threshold Exceeded", "Medium"

    return "Unknown", "Medium"
