# core/crtsh.py
# Subdomain discovery via crt.sh Certificate Transparency logs
import requests


def find_subdomains_crtsh(domain: str):
    """
    Query crt.sh for certificate transparency logs to discover subdomains.
    Returns a sorted list of unique subdomains found.
    """
    results = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    try:
        r = requests.get(url, timeout=15, headers={
            "User-Agent": "Mozilla/5.0 (compatible; ShadowScan/2.0)"
        })
        if r.status_code == 200 and r.text.strip():
            for entry in r.json():
                name_value = entry.get("name_value", "")
                # name_value can contain multiple subdomains separated by newlines
                for sub in name_value.split("\n"):
                    sub = sub.strip().lower()
                    # Filter wildcards and keep only valid subdomains of target domain
                    if sub and not sub.startswith("*") and sub.endswith(f".{domain}"):
                        results.add(sub)
    except ValueError:
        pass  # Invalid JSON from crt.sh (can happen on rate limit)
    except Exception:
        pass

    return sorted(results)
