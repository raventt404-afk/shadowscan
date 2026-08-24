# core/leaks.py
import re
from urllib.parse import urljoin

EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
)

MAX_JS_FILES = 6
MAX_JS_SIZE = 1_000_000  # 1MB


def extract_emails(text):
    if not text:
        return set()
    return set(EMAIL_REGEX.findall(text))


def detect_leaks(base_url, session, main_html):
    """
    ВСЁ В ОДНОМ МЕСТЕ:
    - главная HTML
    - robots.txt
    - sitemap.xml
    - common pages
    - JS (ограниченно)
    """

    found = set()

    def safe_get(url, stream=False):
        try:
            r = session.get(url, timeout=8, stream=stream)
            if r.status_code == 200:
                if stream:
                    data = b""
                    for chunk in r.iter_content(1024):
                        data += chunk
                        if len(data) > MAX_JS_SIZE:
                            break
                    return data.decode(errors="ignore")
                return r.text
        except Exception:
            return ""
        return ""

    # 1️⃣ Главная
    found |= extract_emails(main_html)

    # 2️⃣ robots.txt
    robots = safe_get(urljoin(base_url, "/robots.txt"))
    found |= extract_emails(robots)

    # 3️⃣ sitemap.xml
    sitemap = safe_get(urljoin(base_url, "/sitemap.xml"))
    found |= extract_emails(sitemap)

    # 4️⃣ Частые страницы
    COMMON = [
        "/contacts", "/contact", "/about", "/about-us",
        "/press", "/team", "/support", "/help", "/company"
    ]
    for p in COMMON:
        page = safe_get(urljoin(base_url, p))
        found |= extract_emails(page)

    # 5️⃣ JS (ИМЕННО ТУТ БЫЛИ «ТОННЫ EMAIL»)
    js_files = re.findall(r'src=["\'](.*?\.js)["\']', main_html)
    js_files = js_files[:MAX_JS_FILES]

    for js in js_files:
        js_url = urljoin(base_url, js)
        js_content = safe_get(js_url, stream=True)
        found |= extract_emails(js_content)

    return {
        "errors": [],
        "emails": sorted(found),
        "api_keys": []
    }
