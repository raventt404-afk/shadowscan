# core/dns_info.py
# DNS reconnaissance: A, MX, TXT, NS, CNAME records
import socket

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


def _query(domain: str, record_type: str):
    """Query a DNS record type using dnspython."""
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=5)
        return [str(r) for r in answers]
    except Exception:
        return []


def get_dns(domain: str):
    if not domain:
        return {}

    data = {}

    # A record — always available via socket
    try:
        data["A"] = socket.gethostbyname(domain)
    except Exception:
        data["A"] = None

    if not HAS_DNSPYTHON:
        data["note"] = "Install dnspython for full DNS records: pip install dnspython"
        return data

    # MX records — email servers
    mx = _query(domain, "MX")
    data["MX"] = mx if mx else []

    # TXT records — SPF, DMARC, verification tokens
    txt = _query(domain, "TXT")
    data["TXT"] = txt if txt else []

    # NS records — nameservers
    ns = _query(domain, "NS")
    data["NS"] = ns if ns else []

    # CNAME — aliases
    cname = _query(domain, "CNAME")
    data["CNAME"] = cname if cname else []

    # AAAA — IPv6
    aaaa = _query(domain, "AAAA")
    data["AAAA"] = aaaa if aaaa else []

    # Check for zone transfer vulnerability (should fail on healthy servers)
    data["zone_transfer"] = _check_zone_transfer(domain, data.get("NS", []))

    return data


def _check_zone_transfer(domain: str, nameservers: list):
    """
    Attempt AXFR zone transfer — should be refused by secure servers.
    Returns True if transfer succeeded (CRITICAL finding).
    """
    if not HAS_DNSPYTHON or not nameservers:
        return False

    for ns in nameservers[:2]:  # Only try first 2 nameservers
        ns_clean = ns.rstrip(".")
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns_clean, domain, lifetime=3))
            if z:
                return True  # Zone transfer allowed — critical!
        except Exception:
            pass

    return False
