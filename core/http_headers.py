import requests

# === USER AGENT (ОБЯЗАТЕЛЬНО) ===
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
}

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Strict-Transport-Security"
]

def check_headers(url: str):
    result = {
        "present": [],
        "missing": [],
        "server": None,
        "powered_by": None
    }

    try:
        r = requests.get(url, headers=HEADERS, timeout=8, verify=False)
        headers = r.headers

        for h in SECURITY_HEADERS:
            if h in headers:
                result["present"].append(h)
            else:
                result["missing"].append(h)

        result["server"] = headers.get("Server")
        result["powered_by"] = headers.get("X-Powered-By")

    except Exception as e:
        result["error"] = str(e)

    return result
