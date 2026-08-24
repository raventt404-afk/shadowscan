# core/infra_intel.py
# Infrastructure intelligence: reverse DNS + Geo/ASN via ip-api.com
import socket
import requests

TIMEOUT = 6


def get_reverse_dns(ip: str):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def get_geo_asn(ip: str):
    """
    Fetch country, city, ISP, ASN for an IP using ip-api.com (free, no key needed).
    Fields: status, country, regionName, city, isp, org, as, query
    """
    if not ip:
        return {"error": "No IP provided"}

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,query"
        r = requests.get(url, timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                return {
                    "ip": data.get("query"),
                    "country": data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "asn": data.get("as"),
                }
            else:
                return {"error": f"ip-api returned: {data.get('message', 'unknown')}"}
    except Exception as e:
        return {"error": str(e)}

    return {"error": "Failed to fetch geo/ASN data"}


def get_infra_intel(ip: str):
    return {
        "reverse_dns": get_reverse_dns(ip),
        "geo_asn": get_geo_asn(ip),
    }
