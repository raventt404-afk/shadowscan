import ssl
import socket

def check_ssl(domain: str):
    info = {}

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                info["valid"] = True
                info["expires"] = cert.get("notAfter")
    except:
        info["valid"] = False

    return info
