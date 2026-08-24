import requests
from urllib.parse import urljoin

COMMON_DIRS = [
    'admin', 'login', 'wp-admin', 'administrator', 'backup', 'backups', 
    'config', 'uploads', 'files', 'docs', '.git', '.env', 'vendor', 'node_modules'
]

def find_directories(base_url):
    found_dirs = []
    for d in COMMON_DIRS:
        try:
            url = urljoin(base_url, d)
            r = requests.get(url, timeout=2, verify=False)
            if r.status_code == 200:
                found_dirs.append({"path": f"/{d}", "status": 200})
            elif r.status_code == 403:
                found_dirs.append({"path": f"/{d}", "status": 403})
        except:
            pass
    # FIX: можно добавить чтение robots.txt и sitemap.xml
    try:
        r = requests.get(urljoin(base_url, "robots.txt"), timeout=2, verify=False)
        if r.status_code == 200:
            found_dirs.append({"path": "/robots.txt", "status": 200})
    except:
        pass
    return found_dirs
