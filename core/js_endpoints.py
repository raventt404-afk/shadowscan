import requests
import re

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"
}

PATTERNS = [
    r"/api/[a-zA-Z0-9_/]+",
    r"/v[0-9]+/[a-zA-Z0-9_/]+",
    r"/graphql",
    r"/admin",
]

def scan_js_endpoints(url: str):
    found = set()

    try:
        r = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        scripts = re.findall(r'src=["\'](.*?)["\']', r.text)

        for src in scripts:
            if src.startswith("//"):
                src = "https:" + src
            elif src.startswith("/"):
                src = url + src

            try:
                js = requests.get(src, headers=HEADERS, timeout=5, verify=False).text
                for p in PATTERNS:
                    for match in re.findall(p, js):
                        found.add(match)
            except:
                pass
    except:
        pass

    return sorted(found)
