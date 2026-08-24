# core/subdomains.py
# Subdomain discovery via DNS resolution (wordlist bruteforce)
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def _check_subdomain(sub: str, domain: str):
    fqdn = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return {"subdomain": fqdn, "ip": ip, "alive": True}
    except socket.gaierror:
        return None


def find_subdomains(domain: str, wordlist: list = None):
    if not domain:
        return []

    if wordlist is None:
        wordlist = [
            "www", "api", "dev", "test", "staging", "admin", "mail",
            "smtp", "pop", "imap", "ftp", "vpn", "portal", "app",
            "shop", "store", "blog", "forum", "static", "cdn",
            "assets", "media", "img", "docs", "help", "support"
        ]

    found = []
    # Use threads to speed up DNS resolution (I/O bound)
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(_check_subdomain, sub, domain): sub
            for sub in wordlist
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    return sorted(found, key=lambda x: x["subdomain"])
