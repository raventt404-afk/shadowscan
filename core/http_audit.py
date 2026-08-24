# core/http_audit.py
# HTTP security audit: headers, cookies, redirects, HTTPS enforcement

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]

DANGEROUS_HEADERS = [
    "X-Powered-By",
    "Server",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
]


def audit_http(url: str, session=None, existing_response=None):
    """
    Audit HTTP security from either an existing response object
    or by fetching the URL fresh.
    Pass existing_response to avoid duplicate network requests.
    """
    result = {
        "status_code": None,
        "server": None,
        "security_headers": {},
        "missing_headers": [],
        "info_leaking_headers": {},
        "cookies": [],
        "redirects": [],
        "https_enforced": False,
        "error": None
    }

    try:
        if existing_response is not None:
            response = existing_response
            # We can't get history from a cached response object,
            # so just use what we have
        elif session is not None:
            response = session.get(url, timeout=10, allow_redirects=True)
        else:
            import requests
            import urllib3
            urllib3.disable_warnings()
            response = requests.get(url, timeout=10, allow_redirects=True, verify=False)

        result["status_code"] = response.status_code
        headers = response.headers

        result["server"] = headers.get("Server")

        # Security headers — present vs missing
        for h in SECURITY_HEADERS:
            if h in headers:
                result["security_headers"][h] = headers[h]
            else:
                result["missing_headers"].append(h)

        # Headers that leak technology info
        for h in DANGEROUS_HEADERS:
            if h in headers:
                result["info_leaking_headers"][h] = headers[h]

        # Cookies analysis
        for cookie in response.cookies:
            cookie_info = {
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                "samesite": cookie.has_nonstandard_attr("SameSite"),
                "domain": cookie.domain,
            }
            result["cookies"].append(cookie_info)

        # Redirect chain
        if hasattr(response, "history"):
            for r in response.history:
                result["redirects"].append(r.url)

        # Check if HTTP redirects to HTTPS
        if url.startswith("http://"):
            for r in (response.history or []):
                if r.url.startswith("https://"):
                    result["https_enforced"] = True
                    break
        elif url.startswith("https://"):
            result["https_enforced"] = True

    except Exception as e:
        result["error"] = str(e)

    return result
