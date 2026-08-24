import requests
from urllib.parse import urljoin

COMMON_API = ["swagger.json", "openapi.json", "graphql"]

def scan_api(base_url):
    found = []
    for endpoint in COMMON_API:
        try:
            r = requests.get(urljoin(base_url, endpoint), timeout=2, verify=False)
            if r.status_code == 200:
                found.append(endpoint)
        except:
            pass
    return found
