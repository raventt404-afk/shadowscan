# core/vuln_surface.py
# Passive vulnerability surface analysis
import re
import requests
from urllib.parse import urlparse, urlencode, urljoin

urllib3_imported = False
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    urllib3_imported = True
except ImportError:
    pass

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}
TIMEOUT = 5


def scan_vulnerabilities(base_url: str, main_html: str = ""):
    vulns = {
        "sql_injection": "unknown",
        "xss": "unknown",
        "csrf": "unknown",
        "ssrf": "unknown",
        "idor": "unknown",
        "open_redirect": "unknown",
        "directory_listing": "unknown",
        "info_disclosure": "unknown",
    }

    parsed = urlparse(base_url)

    # ── 1. SQL Injection ─────────────────────────────────────────────────────
    sqli_payloads = ["'", "' OR '1'='1", "\" OR \"1\"=\"1", "1 AND 1=2--"]
    sqli_errors = [
        "sql syntax", "mysql", "postgresql", "ora-", "syntax error",
        "unclosed quotation", "sqlite", "you have an error in your sql"
    ]
    for payload in sqli_payloads:
        try:
            r = requests.get(base_url, params={"id": payload},
                             headers=HEADERS, timeout=TIMEOUT, verify=False)
            if any(e in r.text.lower() for e in sqli_errors):
                vulns["sql_injection"] = "possible"
                break
        except Exception:
            pass

    # ── 2. XSS (Reflected) ──────────────────────────────────────────────────
    xss_payload = "<script>alert('xss')</script>"
    try:
        r = requests.get(base_url, params={"q": xss_payload},
                         headers=HEADERS, timeout=TIMEOUT, verify=False)
        if xss_payload in r.text:
            vulns["xss"] = "possible"
        elif "&lt;script&gt;" not in r.text and "alert" in r.text:
            vulns["xss"] = "likely"
    except Exception:
        pass

    # ── 3. CSRF ──────────────────────────────────────────────────────────────
    html_to_check = main_html
    if not html_to_check:
        try:
            r = requests.get(base_url, headers=HEADERS, timeout=TIMEOUT, verify=False)
            html_to_check = r.text
        except Exception:
            html_to_check = ""

    if html_to_check:
        forms = re.findall(r"<form[^>]*>(.*?)</form>", html_to_check, re.DOTALL | re.IGNORECASE)
        for form in forms:
            # Form has no CSRF token → likely vulnerable
            has_token = bool(re.search(
                r'(csrf|_token|authenticity_token|nonce)',
                form, re.IGNORECASE
            ))
            if not has_token:
                vulns["csrf"] = "likely"
                break
        if vulns["csrf"] == "unknown" and forms:
            vulns["csrf"] = "not_detected"

    # ── 4. SSRF ──────────────────────────────────────────────────────────────
    # Check if URL or common params accept URLs
    ssrf_params = ["url", "callback", "redirect", "next", "return",
                   "uri", "path", "dest", "target", "link", "src"]
    query = parsed.query.lower()
    if any(f"{p}=" in query for p in ssrf_params):
        vulns["ssrf"] = "possible"
    elif html_to_check:
        # Look for fetch/XMLHttpRequest with user-controlled URL in JS
        if re.search(r'fetch\s*\(\s*["\']?https?://', html_to_check, re.IGNORECASE):
            vulns["ssrf"] = "possible"

    # ── 5. IDOR ──────────────────────────────────────────────────────────────
    # ✅ FIX: check if path contains numeric IDs, don't use broken 'any()' trick
    path = parsed.path
    if re.search(r'/\d+(/|$)', path):
        # Try incrementing the ID
        new_path = re.sub(r'/(\d+)', lambda m: f"/{int(m.group(1)) + 1}", path, count=1)
        try:
            r1 = requests.get(base_url, headers=HEADERS, timeout=TIMEOUT, verify=False)
            alt_url = parsed._replace(path=new_path).geturl()
            r2 = requests.get(alt_url, headers=HEADERS, timeout=TIMEOUT, verify=False)
            if r1.status_code == 200 and r2.status_code == 200:
                vulns["idor"] = "possible"
        except Exception:
            pass
    elif html_to_check:
        # Look for numeric IDs in links
        if re.search(r'href=["\'][^"\']*?/\d+[/"\'?]', html_to_check):
            vulns["idor"] = "possible"

    # ── 6. Open Redirect ─────────────────────────────────────────────────────
    redirect_params = ["redirect", "next", "return", "returnUrl", "goto", "url", "dest"]
    for param in redirect_params:
        try:
            test_url = f"{base_url}?{param}=https://evil.com"
            r = requests.get(test_url, headers=HEADERS, timeout=TIMEOUT,
                             verify=False, allow_redirects=False)
            location = r.headers.get("Location", "")
            if "evil.com" in location:
                vulns["open_redirect"] = "possible"
                break
        except Exception:
            pass

    # ── 7. Directory Listing ─────────────────────────────────────────────────
    listing_paths = ["/uploads/", "/files/", "/static/", "/images/", "/assets/"]
    for lpath in listing_paths:
        try:
            r = requests.get(urljoin(base_url, lpath),
                             headers=HEADERS, timeout=TIMEOUT, verify=False)
            if r.status_code == 200 and (
                "index of" in r.text.lower() or
                "<title>directory" in r.text.lower()
            ):
                vulns["directory_listing"] = "possible"
                break
        except Exception:
            pass

    # ── 8. Info Disclosure ───────────────────────────────────────────────────
    disclosure_patterns = [
        r"stack trace",
        r"exception in thread",
        r"traceback \(most recent call",
        r"warning:.*php",
        r"fatal error:",
        r"laravel\.log",
        r"debug.*true",
    ]
    if html_to_check:
        for pattern in disclosure_patterns:
            if re.search(pattern, html_to_check, re.IGNORECASE):
                vulns["info_disclosure"] = "possible"
                break

    return vulns
