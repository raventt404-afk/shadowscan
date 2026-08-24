import requests
from bs4 import BeautifulSoup

def crawl(url):
    links = []
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        for tag in soup.find_all("a"):
            href = tag.get("href")
            if href:
                links.append(href)
    except:
        pass
    return links
