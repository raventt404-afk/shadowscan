# core/risk.py
# Calculates overall risk score based on collected scan data

def calculate_risk(data: dict):
    score = 0
    reasons = []

    # ✅ FIX: use 'http' key (matches shadowscan.py), not 'headers'
    http = data.get("http", {})
    raw_headers = http.get("headers", {})
    server = (raw_headers.get("Server") or raw_headers.get("server") or "").upper()

    behind_cdn = any(cdn in server for cdn in ["QRATOR", "CLOUDFLARE", "AKAMAI", "FASTLY", "INCAPSULA"])

    # 1. Security headers from http_audit result
    http_audit = data.get("http_audit", {})
    security_headers = http_audit.get("security_headers", {})
    cookies = http_audit.get("cookies", [])

    IMPORTANT_HEADERS = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Referrer-Policy",
        "Permissions-Policy"
    ]
    missing_headers = [h for h in IMPORTANT_HEADERS if h not in security_headers]
    if missing_headers:
        penalty = len(missing_headers) * (0.3 if behind_cdn else 1.0)
        score += penalty
        reasons.append(f"Missing {len(missing_headers)} security headers: {', '.join(missing_headers)}")

    # 2. Insecure cookies
    for cookie in cookies:
        if not cookie.get("secure"):
            score += 2
            reasons.append(f"Cookie '{cookie.get('name')}' missing Secure flag")
        if not cookie.get("httponly"):
            score += 1
            reasons.append(f"Cookie '{cookie.get('name')}' missing HttpOnly flag")

    # 3. X-Powered-By leaks server info
    powered_by = raw_headers.get("X-Powered-By") or raw_headers.get("x-powered-by")
    if powered_by:
        score += 1
        reasons.append(f"X-Powered-By header leaks server info: {powered_by}")

    # 4. Directories / sensitive files
    for d in data.get("paths", []):
        path = d if isinstance(d, str) else d.get("path", "")
        if any(critical in path for critical in ["/.env", "/.git", "/backup", "wp-config"]):
            score += 10
            reasons.append(f"Critical file/path exposed: {path}")
        elif any(sensitive in path for sensitive in ["/admin", "/config", "/panel"]):
            score += 2
            reasons.append(f"Sensitive path accessible: {path}")

    # 5. Dangerous open ports
    for p in data.get("ports", []):
        port = p.get("port")
        if port in [21, 23, 445, 3389]:
            score += 8
            reasons.append(f"Dangerous port open: {port} ({p.get('service', '')})")
        elif port in [3306, 27017, 6379]:
            score += 6
            reasons.append(f"Database port exposed: {port} ({p.get('service', '')})")
        elif port not in [80, 443]:
            score += 1

    # 6. Email leaks
    emails = data.get("leaks", {}).get("emails", [])
    if emails:
        score += min(len(emails) * 0.5, 3)
        reasons.append(f"Email addresses leaked: {len(emails)} found")

    # 7. API keys / secrets in JS
    api_keys = data.get("leaks", {}).get("api_keys", [])
    if api_keys:
        score += 8
        reasons.append(f"Potential API keys/secrets found in JS: {len(api_keys)}")

    # 8. Vulnerabilities
    vulns = data.get("vulnerabilities", {})
    vuln_map = {
        "sql_injection": ("SQL Injection", 10),
        "xss": ("XSS", 7),
        "csrf": ("CSRF", 5),
        "ssrf": ("SSRF", 8),
        "idor": ("IDOR", 6),
        "open_redirect": ("Open Redirect", 4),
    }
    for key, (name, weight) in vuln_map.items():
        if vulns.get(key) == "possible":
            score += weight
            reasons.append(f"Vulnerability detected: {name}")
        elif vulns.get(key) == "likely":
            score += weight * 0.5
            reasons.append(f"Vulnerability likely: {name}")

    # 9. SSL
    ssl = data.get("ssl", {})
    if not ssl.get("valid"):
        score += 5
        reasons.append("SSL certificate invalid or missing")

    # 10. DNS — zone transfer or missing SPF/DMARC
    dns = data.get("dns", {})
    txt_records = dns.get("TXT", [])
    has_spf = any("v=spf1" in str(r) for r in txt_records)
    has_dmarc = any("v=DMARC1" in str(r) for r in txt_records)
    if not has_spf:
        score += 1
        reasons.append("Missing SPF record (email spoofing risk)")
    if not has_dmarc:
        score += 1
        reasons.append("Missing DMARC record (email spoofing risk)")

    # Determine level
    if score >= 20:
        level = "CRITICAL"
    elif score >= 12:
        level = "HIGH"
    elif score >= 5:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "level": level,
        "score": round(score, 2),
        "reasons": reasons
    }
