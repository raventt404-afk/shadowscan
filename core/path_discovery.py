# core/path_discovery.py
# Path/endpoint discovery: robots.txt, sitemap.xml, HTML links, JS endpoints, common paths
import re
import time
import requests
from urllib.parse import urljoin, urlparse

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; ShadowScan/2.0)"
}
TIMEOUT = 5

COMMON_PATHS = [
    "admin", "login", "dashboard", "api", "config", "panel", "auth",
    "user", "account", ".env", ".git/config", "backup", "wp-admin",
    "administrator", "phpinfo.php", "server-status", "actuator",
]


def discover_paths(base_url: str, main_html: str = ""):
    """
    Discover paths and endpoints.
    Pass main_html to reuse an already-fetched page (avoids duplicate request).
    """
    found = {}  # path → status_code

    def add(path, status=None):
        found[path] = status

    # ── 1. robots.txt ────────────────────────────────────────────────────────
    try:
        robots_url = urljoin(base_url, "/robots.txt")
        r = requests.get(robots_url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        if r.status_code == 200:
            add("/robots.txt", 200)
            for line in r.text.splitlines():
                if line.startswith("Disallow:") or line.startswith("Allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        add(path)
    except Exception:
        pass

    # ── 2. sitemap.xml ───────────────────────────────────────────────────────
    try:
        sitemap_url = urljoin(base_url, "/sitemap.xml")
        r = requests.get(sitemap_url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        if r.status_code == 200:
            add("/sitemap.xml", 200)
            urls = re.findall(r"<loc>(.*?)</loc>", r.text)
            for u in urls:
                parsed = urlparse(u)
                add(parsed.path or u, None)
    except Exception:
        pass

    # ── 3. HTML link extraction (use existing main_html if available) ─────────
    html = main_html
    if not html:
        try:
            r = requests.get(base_url, headers=HEADERS, timeout=TIMEOUT, verify=False)
            html = r.text
        except Exception:
            html = ""

    if html:
        links = re.findall(r'href=["\'](.*?)["\']', html)
        for link in links:
            if link.startswith("/") and not link.startswith("//"):
                add(link)
            elif link.startswith(base_url):
                parsed = urlparse(link)
                add(parsed.path)

    # ── 4. JS endpoint extraction ─────────────────────────────────────────────
    if html:
        scripts = re.findall(r'src=["\'](.*?\.js(?:\?[^"\']*)?)["\']', html)
        for script in scripts[:5]:  # Limit to 5 JS files
            try:
                js_url = urljoin(base_url, script)
                js_r = requests.get(js_url, headers=HEADERS, timeout=TIMEOUT, verify=False)
                if js_r.status_code == 200:
                    endpoints = re.findall(r'["\'](/(?:api|v\d+|graphql)[^"\'<> ]{0,80})["\']', js_r.text)
                    for ep in endpoints:
                        add(ep)
                time.sleep(0.3)
            except Exception:
                pass

    # ── 5. Common path probing ───────────────────────────────────────────────
    for path in COMMON_PATHS:
        if f"/{path}" in found:
            continue  # Already found via HTML/robots, skip re-request
        try:
            test_url = urljoin(base_url, path)
            r = requests.get(test_url, headers=HEADERS, timeout=TIMEOUT, verify=False)
            if r.status_code in [200, 301, 302, 403]:
                add(f"/{path}", r.status_code)
            time.sleep(0.2)
        except Exception:
            pass

    # Build result list with status info
    result = []
    for path, status in found.items():
        entry = {"path": path}
        if status is not None:
            entry["status"] = status
        result.append(entry)

    return sorted(result, key=lambda x: x["path"])
