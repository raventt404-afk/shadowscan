import requests
import re

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
}

def detect_tech(url: str):
    tech = []

    try:
        r = requests.get(url, headers=HEADERS, timeout=8, verify=False)
        html = r.text.lower()

        if "wp-content" in html:
            tech.append("WordPress")
        if "drupal" in html:
            tech.append("Drupal")
        if "joomla" in html:
            tech.append("Joomla")

        if re.search(r"react|__react", html):
            tech.append("React")
        if "__next" in html or "next.js" in html:
            tech.append("Next.js")
        if "vue" in html:
            tech.append("Vue.js")
        if "webpack" in html:
            tech.append("Webpack")

    except:
        pass

    return list(set(tech))
