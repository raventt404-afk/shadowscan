import requests

COMMON_PATHS = [
    "/robots.txt",
    "/.env",
    "/admin",
    "/backup"
]

def check_common_vulns(base_url):
    findings = []
    for path in COMMON_PATHS:
        try:
            r = requests.get(base_url + path, timeout=5)
            if r.status_code == 200:
                findings.append(path)
        except:
            pass
    return findings
