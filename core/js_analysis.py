# core/js_analysis.py
import re
import requests
from urllib.parse import urljoin

def analyze_js(base_url):
    findings = {
        "js_files": [],
        "endpoints": [],
        "keys_like": []
    }

    try:
        r = requests.get(base_url, timeout=6, verify=False)
        scripts = re.findall(r'src=["\'](.*?\.js)["\']', r.text)

        for s in scripts:
            js_url = urljoin(base_url, s)
            findings["js_files"].append(js_url)

            js = requests.get(js_url, timeout=6, verify=False).text

            # endpoints
            for ep in re.findall(r'["\'](/api/[^"\']+)["\']', js):
                findings["endpoints"].append(ep)

            # key-like strings
            for key in re.findall(r'["\']([A-Za-z0-9_\-]{20,})["\']', js):
                findings["keys_like"].append(key)

    except Exception:
        pass

    return findings
